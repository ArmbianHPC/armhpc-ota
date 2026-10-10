// SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Renci.SshNet;
namespace ArmHpc.Ota.Core;

public static class PushPackage
{
    public static async Task<JsonElement> Inspect(string package,string? release,CancellationToken token)
    {
        string python=Path.Combine(AppContext.BaseDirectory,"publisher/python.exe");
        string output=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ARMHPC","OTA","packages");
        var info=new ProcessStartInfo(python){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(string value in new[]{"-m","armhpc_ota.local_package","--package",package,"--output",output})info.ArgumentList.Add(value);
        if(release is not null){info.ArgumentList.Add("--release");info.ArgumentList.Add(release);}
        using var process=Process.Start(info)!;var stderr=process.StandardError.ReadToEndAsync(token);string text=await process.StandardOutput.ReadToEndAsync(token);await process.WaitForExitAsync(token);
        if(string.IsNullOrWhiteSpace(text))throw new InvalidOperationException("本地 OTA 包解析未返回结果："+(await stderr));
        return Protocol.Decode(text);
    }
}

public sealed partial class SshRunner
{
    public static void UploadResumablePart(SftpClient client,string file,string remote,long offset,long size,Action<string> log,CancellationToken token=default)
    {
        token.ThrowIfCancellationRequested();
        using var input=File.OpenRead(file);
        if(input.Length!=size || offset<0 || offset>size)throw new InvalidOperationException("本地载荷大小或续传偏移改变。");
        if(client.Exists(remote) && client.GetAttributes(remote).IsSymbolicLink)throw new InvalidOperationException("远端载荷不能是符号链接。");
        using var output=client.Open(remote,FileMode.OpenOrCreate,FileAccess.Write);
        if(output.Length!=offset)throw new InvalidOperationException("远端续传偏移改变，请按原任务重新查询。");
        input.Position=offset;output.Position=offset;byte[] buffer=new byte[1024*1024];long sent=offset,last=offset;
        for(int read;(read=input.Read(buffer,0,buffer.Length))>0;)
        {
            token.ThrowIfCancellationRequested();output.Write(buffer,0,read);sent+=read;
            if(sent-last>=16*1024*1024 || sent==size){log("upload-bytes:"+sent+"/"+size);last=sent;}
        }
        output.Flush();client.ChangePermissions(remote,UploadFileMode);
        if(client.GetAttributes(remote).Size!=size)throw new InvalidOperationException("推送后的载荷大小不符。");
    }

    public async Task<JsonElement> StagePackage(Endpoint endpoint,Credentials credentials,Device device,JsonElement package,string target,string requestId,Action<string> log,CancellationToken token)
    {
        string manifestFile=Protocol.Text(package,"manifest");
        string uploaded=await Upload(endpoint,credentials,device,manifestFile,token);
        var args=new[]{"--manifest",uploaded,"--target",target,"--request-id",requestId,"--phase","prepare"};
        var staged=(await Execute(endpoint,credentials,device,"receive",args,true,cancellation:token)).Data;
        if(Protocol.Text(staged,"device_id")!=device.DeviceId || Protocol.Text(staged,"manifest_sha256")!=Protocol.Text(package,"manifest_sha256"))throw new InvalidOperationException("设备接收计划与本地包身份不符。");
        foreach(var item in staged.GetProperty("artifacts").EnumerateArray())
        {
            if(item.GetProperty("complete").GetBoolean())continue;
            string hash=Protocol.Text(item,"sha256");var local=package.GetProperty("artifacts").EnumerateArray().First(a=>Protocol.Text(a,"sha256")==hash);
            string remote=Protocol.Text(item,"path");long offset=item.GetProperty("offset").GetInt64(),size=item.GetProperty("size").GetInt64();
            string directory=Protocol.Text(staged,"directory");
            if(!remote.StartsWith(directory+"/",StringComparison.Ordinal) || !remote.EndsWith("/"+hash+".part",StringComparison.Ordinal))throw new InvalidOperationException("设备返回了非法接收路径。");
            log("upload:"+Protocol.Text(item,"role")+" "+offset+"/"+size);
            var identity=await Execute(endpoint,credentials,device,"status",[],cancellation:token);
            await Task.Run(()=>
            {
                using var client=new SftpClient(Info(endpoint,credentials));Pin(client,device,identity.Mode);client.OperationTimeout=TimeSpan.FromSeconds(30);client.Connect();
                using var cancelled=token.Register(()=>client.Dispose());
                try{UploadResumablePart(client,Protocol.Text(local,"path"),remote,offset,size,log,token);}
                catch(Exception) when(token.IsCancellationRequested){throw new OperationCanceledException(token);}
            },token);
        }
        return (await Execute(endpoint,credentials,device,"receive",["--manifest",Protocol.Text(staged,"manifest"),"--target",target,"--request-id",requestId,"--phase","commit"],true,cancellation:token)).Data;
    }
}
