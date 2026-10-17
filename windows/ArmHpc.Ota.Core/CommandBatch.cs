// SPDX-License-Identifier: GPL-3.0-only
using System.Collections.Concurrent;
namespace ArmHpc.Ota.Core;

public sealed class CommandResultUnknownException(string message,Exception? inner=null,string? bootIdBefore=null):Exception(message,inner) {public string? BootIdBefore=>bootIdBefore;}
public sealed record CommandBatchOptions(int Concurrency=1,bool IgnoreUnknown=false,bool Pilot=false);
public sealed record CommandOutcome(string DeviceId,string Address,string Hostname,string Status,int? ExitCode=null,
    string Output="",string Error="",bool UnknownIgnored=false,string? Confirmation=null,string? BootIdBefore=null,string? BootIdAfter=null);
public sealed record CommandBatchReport(string BatchId,string Command,int Concurrency,bool IgnoreUnknown,
    IReadOnlyList<CommandOutcome> Results,bool Stopped)
{
    public int Succeeded=>Results.Count(r=>r.Status=="succeeded");
    public int Failed=>Results.Count(r=>r.Status=="failed");
    public int Unknown=>Results.Count(r=>r.Status=="unknown");
    public int Skipped=>Results.Count(r=>r.Status=="skipped");
}

/// <summary>Unknown is preserved as unknown; continuing never re-sends a command.</summary>
public static class CommandBatch
{
    public static async Task<CommandBatchReport> Run(IReadOnlyList<Device> targets,ArmHpcRequest request,CommandBatchOptions options,
        Func<Device,Task<CommandReply>> send,Action<CommandOutcome>? completed=null,BatchQueue? queue=null,CancellationToken token=default)
    {
        BatchQueue.ValidateConcurrency(options.Concurrency);
        bool diagnostic=request.Arguments.FirstOrDefault() is "watchdog" or "emmc" || request.Arguments.Take(2).SequenceEqual(new[]{"ota","boot"});
        if(diagnostic && request.Writes && (targets.Count!=1 || options.Concurrency!=1 || options.IgnoreUnknown))
            throw new ArgumentException("看门狗故障/BOOT 诊断只允许单台、并发 1；未知结果必须查询，不可忽略。");
        if(request.Interactive)throw new ArgumentException("交互命令请使用单台终端。");
        if(targets.Any(d=>!d.Managed) || targets.GroupBy(d=>d.DeviceId).Any(g=>g.Count()>1))throw new ArgumentException("命令目标必须是已登记、互不重复的设备。");
        queue??=new BatchQueue();var results=new ConcurrentDictionary<string,CommandOutcome>();
        void Record(CommandOutcome result){results[result.DeviceId]=result;completed?.Invoke(result);}
        await queue.Run(targets,options.Concurrency,async device=>
        {
            if(token.IsCancellationRequested){queue.Stop();return false;}
            CommandOutcome result;
            try
            {
                var reply=await send(device);
                if(reply.DeviceId!=device.DeviceId)throw new InvalidOperationException("命令返回设备 ID 不匹配。");
                result=reply.RebootConfirmed
                    ? new(device.DeviceId,device.Address,reply.Hostname,"succeeded",reply.ExitCode>=0?reply.ExitCode:null,reply.Output,reply.Error,Confirmation:"reboot_verified",BootIdBefore:reply.BootIdBefore,BootIdAfter:reply.BootIdAfter)
                    :reply.ExitCode<0
                    ? new(device.DeviceId,device.Address,reply.Hostname,"unknown",Output:reply.Output,Error:"命令退出状态未返回。",UnknownIgnored:options.IgnoreUnknown)
                    :new(device.DeviceId,device.Address,reply.Hostname,reply.ExitCode==0?"succeeded":"failed",reply.ExitCode,reply.Output,reply.Error);
            }
            catch(CommandResultUnknownException error){result=new(device.DeviceId,device.Address,device.Hostname,"unknown",Error:error.Message,UnknownIgnored:options.IgnoreUnknown,BootIdBefore:error.BootIdBefore);}
            catch(OperationCanceledException) when(token.IsCancellationRequested){queue.Stop();return false;}
            catch(Exception error){result=new(device.DeviceId,device.Address,device.Hostname,"failed",Error:error.Message);}
            Record(result);
            if(token.IsCancellationRequested)queue.Stop();
            return result.Status=="succeeded" || result.Status=="unknown" && options.IgnoreUnknown;
        },device=>Record(new(device.DeviceId,device.Address,device.Hostname,"skipped",Error:"未发送：队列已停止。")),pilot:options.Pilot,stopOnFailure:true);
        foreach(var d in targets)if(!results.ContainsKey(d.DeviceId))Record(new(d.DeviceId,d.Address,d.Hostname,"skipped",Error:"未发送：观察已取消。"));
        return new(Guid.NewGuid().ToString("D"),request.Label,options.Concurrency,options.IgnoreUnknown,targets.Select(d=>results[d.DeviceId]).ToArray(),queue.Stopped);
    }
}
