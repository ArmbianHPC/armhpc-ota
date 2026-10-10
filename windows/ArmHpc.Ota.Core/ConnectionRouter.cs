// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
namespace ArmHpc.Ota.Core;

public sealed class ConnectionRouter(Func<Device,IConsoleWire>? consoleFactory=null):IDisposable
{
    private readonly SshRunner ssh=new();
    private readonly SerialRunner serial=new(consoleFactory);
    private static async Task<T> Safe<T>(Func<Task<T>> action)
    {
        try{return await action();}
        catch(Exception e) when(e is Renci.SshNet.Common.SshConnectionException or Renci.SshNet.Common.SshOperationTimeoutException or System.Net.Sockets.SocketException)
        {throw new TransientConnectionException("连接结果未知；请按原持久任务 ID 查询。",e);}
    }
    public Task<RemoteResult> Execute(Endpoint endpoint,Credentials credentials,Device? expected,string operation,IReadOnlyList<string> arguments,
        bool yes=false,Func<string,string,bool>? approveHostKey=null,CancellationToken cancellation=default)
        =>expected?.Transport=="serial"?serial.Execute(expected,credentials,operation,arguments,yes,cancellation)
            :ssh.Execute(endpoint,credentials,expected,operation,arguments,yes,approveHostKey,cancellation);
    public Task<RemoteResult> Authenticate(Endpoint endpoint,Credentials credentials,Device device,
        Func<string,string,bool>? approveHostKey=null,Action<string>? progress=null,CancellationToken token=default)
        =>device.Transport=="serial"?serial.Authenticate(device,credentials,progress,token):
            ssh.Execute(endpoint,credentials,device,"status",[],approveHostKey:approveHostKey,cancellation:token);
    public Task<string> Upload(Endpoint endpoint,Credentials credentials,Device device,string file,CancellationToken token=default,bool maintenance=false)
        =>Safe(()=>device.Transport=="serial"?serial.Upload(device,credentials,file,token,maintenance):ssh.Upload(endpoint,credentials,device,file,token,maintenance));
    public Task<JsonElement> InstallTools(Endpoint endpoint,Credentials credentials,Device device,string bundle,CancellationToken token=default,string? requestId=null)
        =>Safe(()=>device.Transport=="serial"?serial.InstallTools(device,credentials,bundle,requestId??Guid.NewGuid().ToString("D"),token):ssh.InstallTools(endpoint,credentials,device,bundle,token,requestId));
    public Task<JsonElement> MaintenanceStatus(Endpoint endpoint,Credentials credentials,Device device,CancellationToken token=default,bool rollback=false)
        =>Safe(()=>device.Transport=="serial"?serial.MaintenanceStatus(device,credentials,token,rollback):ssh.MaintenanceStatus(endpoint,credentials,device,token,rollback));
    public async Task<Endpoint?> Reconnect(Device device,Credentials credentials,IReadOnlyList<string> ranges,CancellationToken cancellation=default,bool maintenance=false)
    {
        if(device.Transport!="serial")
        {
            var found=await ssh.Reconnect(device,credentials,ranges,cancellation,maintenance);
            if(found is not null){device.Address=found.Address;device.Port=found.Port;}
            if(found is not null)return found;
            // Only explicitly registered COM ports may receive credentials.
            if(device.SerialPorts.Length==0 || credentials.PrivateKeyPath is not null)return null;
            string previous=device.Address;device.Transport="serial";device.Address=device.SerialPorts[0];
            var fallback=await Reconnect(device,credentials,[],cancellation,maintenance);
            if(fallback is not null)return fallback;
            device.Transport="ssh";device.Address=previous;return null;
        }
        string original=device.Address;
        // Only the selected port and explicitly approved alternatives may receive login credentials.
        foreach(string port in new[]{original}.Concat(device.SerialPorts).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            serial.Reset(port);device.Address=port;
            try
            {
                if(maintenance)await serial.MaintenanceStatus(device,credentials,cancellation);
                else await serial.Execute(device,credentials,"status",[],false,cancellation);
                return new Endpoint(port,device.Port);
            }
            catch(Exception) when(!cancellation.IsCancellationRequested){device.Address=original;}
        }
        device.Address=original;return null;
    }
    public Task<JsonElement> StagePackage(Endpoint endpoint,Credentials credentials,Device device,JsonElement package,string target,string requestId,Action<string> log,CancellationToken token)
    {
        return Safe(()=>device.Transport=="serial"?serial.StagePackage(device,credentials,package,target,requestId,log,token):
            ssh.StagePackage(endpoint,credentials,device,package,target,requestId,log,token));
    }
    public Task DownloadBoot(Endpoint endpoint,Credentials credentials,Device device,JsonElement task,string directory,Action<string> log,CancellationToken token=default)
        =>device.Transport=="serial"?serial.DownloadBoot(device,credentials,task,directory,log,token):ssh.DownloadBoot(endpoint,credentials,device,task,directory,log,token);
    public async Task<CommandReply> ExecuteArmHpc(Endpoint endpoint,Credentials credentials,Device device,ArmHpcRequest request,CancellationToken token=default,RebootWatchOptions? reboot=null,Action<string>? progress=null)
    {
        CommandReply reply;
        try{reply=device.Transport=="serial"?await serial.ExecuteArmHpc(device,credentials,request,token):await ssh.ExecuteArmHpc(endpoint,credentials,device,request,token);}
        catch(CommandResultUnknownException error) when(request.VerifyReboot && error.BootIdBefore is not null && !token.IsCancellationRequested)
        {reply=new(-1,"",error.Message,device.Hostname,device.Mode,device.DeviceId,BootIdBefore:error.BootIdBefore);}
        catch(Exception error) when(!request.Writes && error is TransientConnectionException or CommandResultUnknownException)
        {
            var restored=await Reconnect(device,credentials,reboot?.Ranges??[],token);
            if(restored is null)throw;
            reply=device.Transport=="serial"?await serial.ExecuteArmHpc(device,credentials,request,token):await ssh.ExecuteArmHpc(restored,credentials,device,request,token);
        }
        if(!request.VerifyReboot || reply.ExitCode>0)return reply;
        return await RebootVerification.Confirm(device,request,reply,
            ct=>device.Transport=="serial"?serial.ReadRebootSnapshot(device,credentials,ct):ssh.ReadRebootSnapshot(new(device.Address,device.Port),credentials,device,ct),
            async ct=>{await Reconnect(device,credentials,reboot?.Ranges??[],ct);},reboot,progress,token);
    }
    public Task<SshTerminal> OpenTerminal(Endpoint endpoint,Credentials credentials,Device device,CancellationToken token=default)
    {
        if(device.Transport!="ssh")throw new ArgumentException("交互终端使用 SSH；串口请先释放后使用本地终端。");
        return ssh.OpenTerminal(endpoint,credentials,device,token);
    }
    public void Dispose()=>serial.Dispose();
    public void Disconnect(Device device){if(device.Transport=="serial")serial.Reset(device.Address);}
}
