// SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;
using System.Text.Json;

namespace ArmHpc.Ota.Core;

public static class UsbRescue
{
    public static async Task<JsonElement> Run(string toolDirectory,string export,bool prepare,Action<string> log,CancellationToken token)
    {
        string root=Path.GetFullPath(toolDirectory),script=Path.Combine(root,"oesp-usb-rescue.py");
        if(!File.Exists(script) || File.GetAttributes(script).HasFlag(FileAttributes.ReparsePoint))
            throw new ArgumentException("选择随包 OESP USB 恢复工具目录。");
        if(!Path.IsPathFullyQualified(export))export=Path.GetFullPath(export);
        string executable=OperatingSystem.IsWindows()?Path.Combine(root,"python","python.exe"):"python3";
        if(OperatingSystem.IsWindows() && !File.Exists(executable))throw new IOException("USB 恢复包缺少 Python 运行时。");
        var start=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,
            RedirectStandardError=true,WorkingDirectory=root};
        foreach(var arg in new[]{"-B",script,prepare?"prepare":"boot","--export",export,"--load-ram","--yes"})start.ArgumentList.Add(arg);
        if(!OperatingSystem.IsWindows())start.Environment["PYTHONPATH"]=Path.Combine(root,"linux","Lib");
        using var process=Process.Start(start)??throw new IOException("无法启动 USB 恢复工具。");
        using var cancelled=token.Register(()=>{try{process.Kill(true);}catch(InvalidOperationException){}});
        JsonElement? result=null;
        var errors=process.StandardError.ReadToEndAsync(token);
        while(await process.StandardOutput.ReadLineAsync(token) is string line)
        {
            log(line);
            try{using var document=JsonDocument.Parse(line);if(document.RootElement.TryGetProperty("protocol",out _))result=document.RootElement.Clone();}
            catch(JsonException){}
        }
        await process.WaitForExitAsync(token);string diagnostic=await errors;
        if(result is null)throw new IOException("USB 恢复未返回结果；先查看私有恢复报告。"+diagnostic);
        if(process.ExitCode!=0 || !result.Value.GetProperty("ok").GetBoolean())
            throw new IOException(Protocol.Text(result.Value.GetProperty("error"),"message"));
        return result.Value.GetProperty("data").Clone();
    }
}
