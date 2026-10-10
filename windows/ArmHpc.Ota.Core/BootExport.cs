// SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Renci.SshNet;
namespace ArmHpc.Ota.Core;

public static class PrivateBootExport
{
    public static string Destination(string directory,string name)
    {
        if(name is not ("BOOT-original.img" or "BOOT-rescue.img" or "BOOT-rescue.img.xz"))throw new ArgumentException("只导出私有 BOOT 备份。");
        Directory.CreateDirectory(directory);string root=Path.GetFullPath(directory);
        if((File.GetAttributes(root)&FileAttributes.ReparsePoint)!=0)throw new ArgumentException("备份目录不能是链接。");
        string destination=Path.Combine(root,name);
        foreach(string path in new[]{destination,destination+".partial"})
            if(File.Exists(path) && (File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new ArgumentException("BOOT 导出目标不能是链接。");
        return destination;
    }
    public static void Verify(string path,JsonElement item)
    {
        if(new FileInfo(path).Length!=item.GetProperty("bytes").GetInt64())throw new IOException("BOOT 导出大小不符。");
        using var file=File.OpenRead(path);
        if(Convert.ToHexStringLower(SHA256.HashData(file))!=Protocol.Text(item,"sha256"))throw new IOException("BOOT 导出 SHA256 不符。");
    }
}

public sealed partial class SshRunner
{
    public async Task DownloadBoot(Endpoint endpoint,Credentials credentials,Device device,JsonElement task,string directory,Action<string> log,CancellationToken token)
    {
        var identity=await Execute(endpoint,credentials,device,"status",[],cancellation:token);
        await Task.Run(()=>
        {
            using var client=new SftpClient(Info(endpoint,credentials));Pin(client,device,identity.Mode);client.Connect();
            using var cancelled=token.Register(()=>client.Dispose());client.OperationTimeout=TimeSpan.FromSeconds(30);
            foreach(var item in task.GetProperty("backups").EnumerateObject())
            {
                string destination=PrivateBootExport.Destination(directory,item.Name),remote=Protocol.Text(item.Value,"path");
                if(!remote.EndsWith("/boot-backups/"+Protocol.Text(task,"task_id")+"/"+item.Name,StringComparison.Ordinal))
                    throw new InvalidOperationException("设备备份路径不属于当前 BOOT 任务。");
                if(client.GetAttributes(remote).IsSymbolicLink)throw new InvalidOperationException("BOOT 备份不能是链接。");
                string partial=destination+".partial";
                using(var output=File.Open(partial,FileMode.Create,FileAccess.Write)){client.DownloadFile(remote,output);output.Flush(true);}
                PrivateBootExport.Verify(partial,item.Value);File.Move(partial,destination,true);log("private-boot-export:"+item.Name);
            }
        },token);
    }
}

public sealed partial class ConsoleSession
{
    public async Task StreamDownload(string command,string file,long size,string digest,Action<string> log,CancellationToken token)
    {
        await gate.WaitAsync(token);bool receiver=false;
        try
        {
            using var output=File.Open(file,FileMode.OpenOrCreate,FileAccess.ReadWrite);
            long offset=output.Length;if(offset>size)throw new IOException("导出续传文件超过备份大小。");output.Position=offset;
            ReadStreamWire();WriteStreamWire(command+" --offset "+offset+"\r");receiver=true;
            var buffer=new StringBuilder();
            async Task<JsonElement> Frame()
            {
                var timer=Stopwatch.StartNew();
                while(timer.Elapsed<TimeSpan.FromSeconds(60))
                {
                    token.ThrowIfCancellationRequested();buffer.Append(ReadStreamWire());var frame=SerialFrames.Take(buffer);
                    if(frame is not null)
                    {
                        if(Protocol.Text(frame.Value,"state")=="error")throw new IOException("设备导出拒绝："+Protocol.Text(frame.Value,"message"));
                        return frame.Value;
                    }
                    await Task.Delay(5,token);
                }
                throw new TimeoutException("串口导出中断；可从原备份继续。");
            }
            var ready=await Frame();SerialFrames.CheckOffset(ready,offset,"ready");
            if(Protocol.Text(ready,"sha256")!=digest || ready.GetProperty("size").GetInt64()!=size)throw new IOException("导出绑定变化。");
            long last=offset;
            while(offset<size)
            {
                var chunk=await Frame();SerialFrames.CheckOffset(chunk,offset,"chunk");
                byte[] data=Convert.FromBase64String(Protocol.Text(chunk,"data"));
                if(data.Length==0 || data.Length>49152 || data.Length+offset>size ||
                    Convert.ToHexStringLower(SHA256.HashData(data))!=Protocol.Text(chunk,"sha256"))throw new IOException("导出块大小/哈希不符。");
                await output.WriteAsync(data,token);output.Flush(true);offset+=data.Length;
                WriteStreamWire(JsonSerializer.Serialize(new{operation="ack",offset})+"\n");
                if(offset-last>=16*1024*1024 || offset==size){log("serial-export-bytes:"+offset+"/"+size);last=offset;}
            }
            var done=await Frame();SerialFrames.CheckOffset(done,size,"verified");
            output.Position=0;if(Convert.ToHexStringLower(SHA256.HashData(output))!=digest)throw new IOException("导出文件最终 SHA256 不符。");
            receiver=false;
        }
        finally
        {
            if(receiver){try{WriteStreamWire("{\"operation\":\"cancel\"}\n");}catch(Exception error) when(error is IOException or TransientConnectionException){}}
            gate.Release();
        }
    }
}

public sealed partial class SerialRunner
{
    public Task DownloadBoot(Device device,Credentials credentials,JsonElement task,string directory,Action<string> log,CancellationToken token)
        =>Use(device,credentials,async session=>
        {
            var identity=await Query(session,Commands.Build("status",[],credentials.Username!="root"),token,TimeSpan.FromSeconds(30));
            ConsoleProtocol.VerifyIdentity(device,identity);
            foreach(var item in task.GetProperty("backups").EnumerateObject())
            {
                string destination=PrivateBootExport.Destination(directory,item.Name),partial=destination+".partial";
                string command=Privileged(credentials,"env PYTHONPATH=/usr/lib/armhpc-ota python3 -m armhpc_ota.serial_stream --export-task "+
                    Commands.Quote(Protocol.Text(task,"task_id"))+" --name "+Commands.Quote(item.Name));
                await session.StreamDownload(command,partial,item.Value.GetProperty("bytes").GetInt64(),Protocol.Text(item.Value,"sha256"),log,token);
                PrivateBootExport.Verify(partial,item.Value);File.Move(partial,destination,true);
            }
            return true;
        },token);
}
