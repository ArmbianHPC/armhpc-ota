// SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace ArmHpc.Ota.Core;

public static class SerialFrames
{
    public const string Prefix="__ARMHPC_STREAM__:";
    public static JsonElement? Take(StringBuilder buffer)
    {
        string text=buffer.ToString();int first=text.IndexOf(Prefix,StringComparison.Ordinal);
        if(first<0){if(buffer.Length>65536)buffer.Remove(0,buffer.Length-256);return null;}
        int end=text.IndexOf('\n',first);
        if(end<0){if(text.Length-first>131072)throw new InvalidOperationException("串口流响应过大。");return null;}
        if(end-first>131072)throw new InvalidOperationException("串口流响应超过界限。");
        using var document=JsonDocument.Parse(text[(first+Prefix.Length)..end].Trim());
        buffer.Remove(0,end+1);return document.RootElement.Clone();
    }
    public static string Chunk(long offset,ReadOnlySpan<byte> data)=>JsonSerializer.Serialize(new {
        operation="chunk",offset,sha256=Convert.ToHexStringLower(SHA256.HashData(data)),data=Convert.ToBase64String(data)})+"\n";
    public static void CheckOffset(JsonElement frame,long expected,string state)
    {
        if(Protocol.Text(frame,"state")!=state || !frame.TryGetProperty("offset",out var value) || value.GetInt64()!=expected)
            throw new InvalidOperationException("串口续传状态或偏移不符；按原请求重新查询。");
    }
}

public sealed partial class ConsoleSession
{
    private string ReadStreamWire()
    {
        try{return wire.Read();}
        catch(Exception error) when(error is IOException or TimeoutException){throw new TransientConnectionException("串口连接中断，使用原传输 ID 续传。",error);}
    }
    private void WriteStreamWire(string value)
    {
        try{wire.Write(value);}
        catch(Exception error) when(error is IOException or TimeoutException){throw new TransientConnectionException("串口写入结果未知，使用原传输 ID 核对。",error);}
    }

    public async Task StreamFile(string command,string file,long size,string digest,Action<string> log,CancellationToken token)
    {
        await gate.WaitAsync(token);bool receiver=false;
        try
        {
            using var input=File.OpenRead(file);
            if(input.Length!=size || !Regex.IsMatch(digest,"^[a-f0-9]{64}$"))throw new InvalidOperationException("载荷大小/哈希无效。");
            if(Encoding.UTF8.GetByteCount(command)>3000)throw new ArgumentException("串口接收命令过长。");
            ReadStreamWire();WriteStreamWire(command+"\r");receiver=true;
            var buffer=new StringBuilder();
            async Task<JsonElement> ReadFrame()
            {
                var timer=Stopwatch.StartNew();
                while(timer.Elapsed<TimeSpan.FromSeconds(60))
                {
                    token.ThrowIfCancellationRequested();buffer.Append(ReadStreamWire());
                    var frame=SerialFrames.Take(buffer);
                    if(frame is not null)
                    {
                        if(Protocol.Text(frame.Value,"state")=="error")throw new InvalidOperationException("设备串口接收拒绝："+Protocol.Text(frame.Value,"message"));
                        return frame.Value;
                    }
                    if(ConsoleProtocol.Prompt(buffer.ToString()) is "login" or "password" or "menu")
                    {
                        receiver=false; // A new getty is not the previous receiver; do not send it a cancel JSON as a username.
                        throw new TransientConnectionException("串口接收器随设备重启中断；保留原传输 ID 后重连续传。");
                    }
                    await Task.Delay(5,token);
                }
                throw new TransientConnectionException("串口接收结果未知；保留原传输 ID 后重新查询。",new TimeoutException());
            }
            var ready=await ReadFrame();
            long offset=ready.GetProperty("offset").GetInt64();
            if(Protocol.Text(ready,"state")!="ready" || Protocol.Text(ready,"sha256")!=digest ||
                ready.GetProperty("size").GetInt64()!=size || offset<0 || offset>size)
                throw new InvalidOperationException("串口接收计划改变。");
            input.Position=offset;byte[] chunk=new byte[12288];long last=offset;
            while(offset<size)
            {
                int read=await input.ReadAsync(chunk.AsMemory(0,(int)Math.Min(chunk.Length,size-offset)),token);
                if(read==0)throw new IOException("本地载荷被截断。");
                WriteStreamWire(SerialFrames.Chunk(offset,chunk.AsSpan(0,read)));offset+=read;
                SerialFrames.CheckOffset(await ReadFrame(),offset,"ack");
                if(offset-last>=4*1024*1024 || offset==size){log("serial-upload-bytes:"+offset+"/"+size);last=offset;}
            }
            WriteStreamWire("{\"operation\":\"finish\"}\n");
            var verified=await ReadFrame();SerialFrames.CheckOffset(verified,size,"verified");
            if(Protocol.Text(verified,"sha256")!=digest)throw new InvalidOperationException("串口最终 SHA256 不符。");
            receiver=false;
        }
        finally
        {
            // Receiver restores tty flags itself on exit. This frame also lets a
            // connected receiver stop after GUI cancellation, without deploying.
            if(receiver){try{WriteStreamWire("{\"operation\":\"cancel\"}\n");}catch(Exception error) when(error is IOException or TransientConnectionException){}}
            gate.Release();
        }
    }
}

public sealed partial class SerialRunner
{
    public Task<JsonElement> StagePackage(Device device,Credentials credentials,JsonElement package,string target,string requestId,Action<string> log,CancellationToken token)
        =>Use(device,credentials,async session=>
        {
            var identity=await Query(session,Commands.Build("status",[],credentials.Username!="root"),token,TimeSpan.FromSeconds(30));
            ConsoleProtocol.VerifyIdentity(device,identity);
            if(!Version.TryParse(Protocol.Text(identity,"agent_version"),out var version) || version<new Version(0,3,4))
                throw new InvalidOperationException("完整串口推包需要 agent 0.3.4；先安装签名维护包并普通重启。");
            string manifest=Protocol.Text(package,"manifest");
            if(new FileInfo(manifest).Length>1024*1024)throw new InvalidOperationException("清单过大。");
            string remote=await Transfer(session,File.ReadAllBytes(manifest),"manifest.json",token);
            var staged=await Query(session,Commands.Build("receive",["--manifest",remote,"--target",target,"--request-id",requestId,"--phase","prepare"],credentials.Username!="root",true),token);
            if(Protocol.Text(staged,"device_id")!=device.DeviceId || Protocol.Text(staged,"manifest_sha256")!=Protocol.Text(package,"manifest_sha256"))
                throw new InvalidOperationException("串口接收计划的设备/清单身份不符。");
            foreach(var item in staged.GetProperty("artifacts").EnumerateArray())
            {
                if(item.GetProperty("complete").GetBoolean())continue;
                string hash=Protocol.Text(item,"sha256");
                var local=package.GetProperty("artifacts").EnumerateArray().Single(a=>Protocol.Text(a,"sha256")==hash);
                long size=item.GetProperty("size").GetInt64();
                string command=Privileged(credentials,"env PYTHONPATH=/usr/lib/armhpc-ota python3 -m armhpc_ota.serial_stream --request-id "+Commands.Quote(requestId)+" --sha256 "+Commands.Quote(hash));
                await session.StreamFile(command,Protocol.Text(local,"path"),size,hash,log,token);
            }
            return await Query(session,Commands.Build("receive",["--manifest",Protocol.Text(staged,"manifest"),"--target",target,
                "--request-id",requestId,"--phase","commit"],credentials.Username!="root",true),token);
        },token);
}
