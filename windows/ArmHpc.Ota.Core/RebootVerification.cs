// SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;
namespace ArmHpc.Ota.Core;

public sealed record RebootSnapshot(string DeviceId,string BootId,string Mode,string Hostname,string Address);
public sealed record RebootWatchOptions(int TimeoutSeconds=180,string[]? Ranges=null);
public static class RebootVerification
{
    public static async Task<CommandReply> Confirm(Device device,ArmHpcRequest request,CommandReply original,
        Func<CancellationToken,Task<RebootSnapshot>> probe,Func<CancellationToken,Task>? discover=null,
        RebootWatchOptions? options=null,Action<string>? progress=null,CancellationToken token=default,
        Func<CancellationToken,Task>? delay=null)
    {
        options??=new();delay??=t=>Task.Delay(3000,t);
        if(original.ExitCode>0)return original;
        if(!Guid.TryParse(original.BootIdBefore,out _))throw new CommandResultUnknownException("缺少重启前 boot ID，不能确认本次重启。");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds));
        var elapsed=Stopwatch.StartNew();double lastDiscover=-30;RebootSnapshot? lastChanged=null;
        progress?.Invoke("等待重启后的身份和 boot ID 确认");
        try
        {
            while(true)
            {
                deadline.Token.ThrowIfCancellationRequested();
                try
                {
                    var after=await probe(deadline.Token);
                    if(after.DeviceId!=device.DeviceId)throw new InvalidOperationException("重启后设备 ID 不匹配。");
                    if(!Guid.TryParse(after.BootId,out _))throw new InvalidOperationException("重启后 boot ID 无效。");
                    if(after.BootId!=original.BootIdBefore)
                    {
                        lastChanged=after;
                        if(request.ExpectedRebootMode is null || request.ExpectedRebootMode==after.Mode)
                        {
                            progress?.Invoke("已确认新 boot ID · "+after.Mode);
                            return original with {Hostname=after.Hostname,Mode=after.Mode,RebootConfirmed=true,BootIdAfter=after.BootId,Error=original.ExitCode<0?"":original.Error};
                        }
                        progress?.Invoke("已重启，当前 "+after.Mode+"，等待 "+request.ExpectedRebootMode);
                    }
                }
                catch(TransientConnectionException)
                {
                    progress?.Invoke("设备重启中，等待重连");
                    if(discover is not null && elapsed.Elapsed.TotalSeconds-lastDiscover>=15)
                    {lastDiscover=elapsed.Elapsed.TotalSeconds;try{await discover(deadline.Token);}catch(TransientConnectionException){}}
                }
                await delay(deadline.Token);
            }
        }
        catch(OperationCanceledException) when(!token.IsCancellationRequested)
        {
            if(lastChanged is not null && request.ExpectedRebootMode is not null)
                throw new InvalidOperationException("已观察到重启，但未进入目标环境 "+request.ExpectedRebootMode+"，当前为 "+lastChanged.Mode+"。");
            throw new CommandResultUnknownException("重启确认超时；尚未观察到同一设备的新 boot ID，原命令不会重发。");
        }
        catch(OperationCanceledException) when(token.IsCancellationRequested)
        {throw new CommandResultUnknownException("已停止重启结果观察，原命令不会重发。");}
    }
}

public sealed partial class SshRunner
{
    public const string BootIdCommand="cat /proc/sys/kernel/random/boot_id";
    private static string BootId(Renci.SshNet.SshClient client)
    {
        using var command=client.CreateCommand(BootIdCommand);command.CommandTimeout=TimeSpan.FromSeconds(10);
        string value=command.Execute().Trim();if(command.ExitStatus!=0 || !Guid.TryParse(value,out _))throw new InvalidOperationException("不能读取有效的 Linux boot ID。");return value;
    }
    public Task<RebootSnapshot> ReadRebootSnapshot(Endpoint endpoint,Credentials credentials,Device device,CancellationToken token)
        =>Task.Run(()=>
        {
            try
            {
                using var client=new Renci.SshNet.SshClient(Info(endpoint,credentials));var fingerprint=Pin(client,device);
                using var stop=token.Register(()=>client.Dispose());token.ThrowIfCancellationRequested();client.Connect();
                var identity=Command(client,credentials,"status",[],timeout:TimeSpan.FromSeconds(15));ValidateMaintenanceIdentity(device,identity,fingerprint());
                return new RebootSnapshot(device.DeviceId,BootId(client),Protocol.Text(identity,"mode"),Hostname(client),endpoint.Address);
            }
            catch(Exception) when(token.IsCancellationRequested){throw new OperationCanceledException(token);}
            catch(Exception error) when(error is Renci.SshNet.Common.SshConnectionException or Renci.SshNet.Common.SshOperationTimeoutException or System.Net.Sockets.SocketException)
            {throw new TransientConnectionException("重启后的 SSH 尚不可用。",error);}
        },token);
}

public sealed partial class SerialRunner
{
    public Task<RebootSnapshot> ReadRebootSnapshot(Device device,Credentials credentials,CancellationToken token)
        =>Use(device,credentials,async session=>
        {
            var identity=await Query(session,Commands.Build("status",[],credentials.Username!="root"),token,TimeSpan.FromSeconds(15));ConsoleProtocol.VerifyIdentity(device,identity);
            var boot=await session.Run(SshRunner.BootIdCommand,TimeSpan.FromSeconds(10),token);
            if(boot.ExitCode!=0 || !Guid.TryParse(boot.Output.Trim(),out _))throw new InvalidOperationException("重启后串口 boot ID 无效。");
            var host=await session.Run(SshRunner.HostnameCommand,TimeSpan.FromSeconds(8),token);
            return new RebootSnapshot(device.DeviceId,boot.Output.Trim(),Protocol.Text(identity,"mode"),host.Output.Trim(),device.Address);
        },token);
}
