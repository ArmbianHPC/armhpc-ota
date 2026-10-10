// SPDX-License-Identifier: GPL-3.0-only
using Renci.SshNet;
using System.Net.Sockets;
using System.Text.Json;
namespace ArmHpc.Ota.Core;

public sealed partial class SshRunner
{
    public const string HostnameCommand="hostname";
    private static string Hostname(SshClient client)
    {
        using var probe=client.CreateCommand(HostnameCommand);probe.CommandTimeout=TimeSpan.FromSeconds(8);
        string name=probe.Execute().Trim();return probe.ExitStatus==0 && name.Length<=253 && !name.Any(char.IsControl)?name:"";
    }
    public Task<CommandReply> ExecuteArmHpc(Endpoint endpoint,Credentials credentials,Device device,ArmHpcRequest request,CancellationToken token)
    {
        if(request.Interactive)throw new ArgumentException("此命令需要交互终端。");
        return Task.Run(()=>
        {
            bool submitted=false;string? before=null;
            try
            {
                using var client=new SshClient(Info(endpoint,credentials));var fingerprint=Pin(client,device);client.Connect();
                using var cancelled=token.Register(()=>client.Dispose());var identity=Command(client,credentials,"status",[]);
                ValidateMaintenanceIdentity(device,identity,fingerprint());string hostname=Hostname(client),mode=Protocol.Text(identity,"mode");if(request.VerifyReboot)before=BootId(client);
                using var command=client.CreateCommand(request.Build(mode,credentials.Username!="root"));command.CommandTimeout=TimeSpan.FromMinutes(30);
                submitted=true;string output=command.Execute();return new CommandReply(command.ExitStatus??-1,output,command.Error,hostname,mode,device.DeviceId,BootIdBefore:before);
            }
            catch(Exception error) when(token.IsCancellationRequested){if(submitted)throw new CommandResultUnknownException("已取消结果观察；命令可能已执行，请查询设备状态。",error,before);throw new OperationCanceledException(token);}
            catch(Exception e) when(e is Renci.SshNet.Common.SshConnectionException or Renci.SshNet.Common.SshOperationTimeoutException or SocketException)
            {if(submitted)throw new CommandResultUnknownException("命令提交结果未知；原命令不会自动重发。",e,before);throw new TransientConnectionException("连接或预检失败，管理命令尚未发送。",e);}
        },token);
    }
    public Task<SshTerminal> OpenTerminal(Endpoint endpoint,Credentials credentials,Device device,CancellationToken token)
        =>Task.Run(()=>
        {
            var client=new SshClient(Info(endpoint,credentials));var fingerprint=Pin(client,device);
            try
            {
                using var cancelled=token.Register(()=>client.Dispose());token.ThrowIfCancellationRequested();client.Connect();var identity=Command(client,credentials,"status",[]);ValidateMaintenanceIdentity(device,identity,fingerprint());
                string hostname=Hostname(client);var shell=client.CreateShellStream("xterm",120,35,960,560,8192);return new SshTerminal(client,shell,Protocol.Text(identity,"mode"),hostname);
            }catch{client.Dispose();throw;}
        },token);
}

public sealed class SshTerminal(SshClient client,ShellStream shell,string mode,string hostname):IDisposable
{
    public string Mode=>mode;
    public string Hostname=>hostname;
    public string Read()=>shell.DataAvailable?shell.Read():"";
    public void Send(string text)=>shell.Write(text);
    public void Dispose(){shell.Dispose();client.Dispose();}
}

public sealed partial class SerialRunner
{
    public Task<CommandReply> ExecuteArmHpc(Device device,Credentials credentials,ArmHpcRequest request,CancellationToken token)
        =>Use(device,credentials,async session=>
        {
            if(request.Interactive)throw new ArgumentException("此命令需要本地交互终端；请释放串口后连接。");
            var identity=await Query(session,Commands.Build("status",[],credentials.Username!="root"),token,TimeSpan.FromSeconds(30));ConsoleProtocol.VerifyIdentity(device,identity);
            var host=await session.Run(SshRunner.HostnameCommand,TimeSpan.FromSeconds(8),token);
            string command=request.Build(Protocol.Text(identity,"mode"),credentials.Username!="root");
            string? before=null;
            if(request.VerifyReboot)
            {
                var boot=await session.Run(SshRunner.BootIdCommand,TimeSpan.FromSeconds(10),token);
                if(boot.ExitCode!=0 || !Guid.TryParse(boot.Output.Trim(),out _))throw new InvalidOperationException("重启前 boot ID 无效。");before=boot.Output.Trim();
            }
            ConsoleReply result;
            try{result=await session.Run(command,request.VerifyReboot?TimeSpan.FromSeconds(8):TimeSpan.FromMinutes(30),token);}
            catch(Exception error) when(error is IOException or TimeoutException or OperationCanceledException)
            {
                if(sessions.TryRemove(device.Address,out var stale))stale.Dispose();
                throw new CommandResultUnknownException("串口命令提交结果未知；原命令不会自动重发。",error,before);
            }
            return new CommandReply(result.ExitCode,result.Output,result.Error,host.ExitCode==0?host.Output.Trim():"",Protocol.Text(identity,"mode"),Protocol.Text(identity,"device_id"),BootIdBefore:before);
        },token);
}
