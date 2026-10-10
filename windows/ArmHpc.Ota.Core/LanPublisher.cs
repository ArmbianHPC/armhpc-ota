// SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace ArmHpc.Ota.Core;

public sealed class LanPublisher
{
    public string Configuration { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ARMHPC", "OTA", "publisher.json");
    public async Task<JsonElement> Publish(string operation, IReadOnlyList<string> arguments)
    {
        string runtime=Path.Combine(AppContext.BaseDirectory,"publisher","python.exe");
        if (!File.Exists(runtime)) throw new InvalidOperationException("便携包缺少 Python 发布运行时。");
        var info=new ProcessStartInfo(runtime) {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        info.ArgumentList.Add("-m");info.ArgumentList.Add("armhpc_ota.lan_publish");info.ArgumentList.Add(operation);
        foreach(string a in arguments)info.ArgumentList.Add(a);
        using var process=Process.Start(info)!;
        Task<string> error=process.StandardError.ReadToEndAsync();string output=await process.StandardOutput.ReadToEndAsync();await process.WaitForExitAsync();
        if(string.IsNullOrWhiteSpace(output))throw new InvalidOperationException("发布助手未返回 JSON："+(await error)[..Math.Min(1000,(await error).Length)]);
        return Protocol.Decode(output);
    }
    public void Start(string root,string bind,int port,bool https,string? certificate,string password)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Configuration)!);
        string? protectedPassword=string.IsNullOrEmpty(password)?null:Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(password),null,DataProtectionScope.CurrentUser));
        File.WriteAllText(Configuration,JsonSerializer.Serialize(new {root=Path.GetFullPath(root),bind,port,https,certificate,protectedPassword}));
        string executable=Path.Combine(AppContext.BaseDirectory,"server","ARMHPC-OTA-Server.exe");
        if(!File.Exists(executable))throw new InvalidOperationException("便携包缺少发布服务。");
        var info=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true};info.ArgumentList.Add("--config");info.ArgumentList.Add(Configuration);Process.Start(info);
    }
    public async Task<JsonElement> Control(string command)
    {
        string pipeName="ARMHPC.OTA.Publish."+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(Configuration))))[..16];
        using var pipe=new NamedPipeClientStream(".",pipeName,PipeDirection.InOut,PipeOptions.Asynchronous);
        await pipe.ConnectAsync(3000);
        using var writer=new StreamWriter(pipe,leaveOpen:true){AutoFlush=true};using var reader=new StreamReader(pipe,leaveOpen:true);
        await writer.WriteLineAsync(command);
        return JsonDocument.Parse(await reader.ReadLineAsync()??"{}").RootElement.Clone();
    }
}
