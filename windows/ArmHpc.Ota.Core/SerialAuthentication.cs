// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
namespace ArmHpc.Ota.Core;

public sealed partial class SerialRunner
{
    /// <summary>Fresh, read-only console authentication with a bounded total wait.</summary>
    public async Task<RemoteResult> Authenticate(Device device,Credentials credentials,Action<string>? progress=null,
        CancellationToken token=default,TimeSpan? timeout=null)
    {
        string phase="等待串口操作完成";
        void Report(string value){phase=value;progress?.Invoke(value);}
        Report(phase);
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);
        var limit=timeout??TimeSpan.FromSeconds(30);deadline.CancelAfter(limit);
        try
        {
            return await Use(device,credentials,async session=>
            {
                Report("读取 ARMHPC 设备身份");
                var identity=await Query(session,Commands.Build("status",[],credentials.Username!="root"),deadline.Token,TimeSpan.FromSeconds(12));
                ConsoleProtocol.VerifyIdentity(device,identity);
                Report("读取主机名");
                var host=await session.Run(SshRunner.HostnameCommand,TimeSpan.FromSeconds(4),deadline.Token);
                deadline.Token.ThrowIfCancellationRequested();Report("认证成功");
                return new RemoteResult(identity,"",Protocol.Text(identity,"mode"),host.ExitCode==0?host.Output.Trim():"");
            },deadline.Token,fresh:true,progress:Report).ConfigureAwait(false);
        }
        catch(OperationCanceledException) when(!token.IsCancellationRequested)
        {
            throw new TimeoutException($"串口认证超时（{phase}；总等待上限 {limit.TotalSeconds:0} 秒）。连接已释放，未提交 OTA 或复位诊断任务。");
        }
        catch(Exception error) when(error is not OperationCanceledException)
        {
            throw new InvalidOperationException($"串口认证未完成（{phase}）：{error.Message}",error);
        }
    }
}
