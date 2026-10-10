// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
public static class CommandBatchChecks
{
    public static async Task Run(Action<bool,string> check,Action<Action,string> refused)
    {
        var targets=Enumerable.Range(0,16).Select(i=>new Device{DeviceId="batch-"+i,Address="192.168.1."+(i+10)}).ToArray();
        var request=ArmHpcCommands.Parse("armhpc led --heartbeat on");
        CommandReply Good(Device d)=>new(0,"ok","","host", "system",d.DeviceId);
        int running=0,maximum=0;var seen=new System.Collections.Concurrent.ConcurrentDictionary<string,int>();
        var report=await CommandBatch.Run(targets,request,new(8),async d=>
        {
            seen.AddOrUpdate(d.DeviceId,1,(_,n)=>n+1);int active=Interlocked.Increment(ref running);
            int prior;do{prior=maximum;}while(active>prior && Interlocked.CompareExchange(ref maximum,active,prior)!=prior);
            await Task.Delay(50);Interlocked.Decrement(ref running);return Good(d);
        });
        check(maximum==8 && report.Succeeded==16 && seen.Values.All(n=>n==1),"command workers run eight devices concurrently and submit each once");
        var small=targets.Take(3).ToArray();var order=new List<string>();
        report=await CommandBatch.Run(small,request,new(1),d=>{order.Add(d.DeviceId);throw new CommandResultUnknownException("lost after send");});
        check(report.Unknown==1 && report.Skipped==2 && report.Stopped && order.Count==1,"default unknown result pauses remaining commands");
        order.Clear();report=await CommandBatch.Run(small,request,new(1,true),d=>
        {order.Add(d.DeviceId);if(d==small[0])throw new CommandResultUnknownException("lost after send");return Task.FromResult(Good(d));});
        check(report.Unknown==1 && report.Succeeded==2 && report.Results[0].UnknownIgnored && order.Count==3 && order.Distinct().Count()==3,"ignore unknown preserves uncertainty, continues and never resends");
        report=await CommandBatch.Run(small,request,new(1,true),d=>throw new TransientConnectionException("preflight failed"));
        check(report.Failed==1 && report.Unknown==0 && report.Skipped==2,"preflight failures cannot be ignored as unknown submissions");
        report=await CommandBatch.Run(small,request,new(1,true),d=>Task.FromResult(new CommandReply(7,"out","error","host","system",d.DeviceId)));
        check(report.Failed==1 && report.Results[0].ExitCode==7 && report.Skipped==2,"known nonzero exit remains a failure under ignore unknown");
        report=await CommandBatch.Run(small,request,new(1,true),d=>Task.FromResult(Good(d) with {DeviceId="wrong"}));
        check(report.Failed==1 && report.Skipped==2,"device identity mismatch remains blocking");
        report=await CommandBatch.Run(small,request,new(1,true),d=>Task.FromResult(Good(d) with {ExitCode=-1}));
        check(report.Unknown==3 && report.Succeeded==0 && report.Results.All(r=>r.ExitCode is null),"missing exit status is unknown rather than successful");
        int invoked=0;using(var stop=new CancellationTokenSource())
        {
            stop.Cancel();report=await CommandBatch.Run(small,request,new(8,true),d=>{invoked++;return Task.FromResult(Good(d));},token:stop.Token);
            check(invoked==0 && report.Skipped==3,"cancelled command batch never sends pending commands");
        }
        var queue=new BatchQueue();report=await CommandBatch.Run(small,request,new(1,true),d=>{queue.Stop();return Task.FromResult(Good(d));},queue:queue);
        check(report.Succeeded==1 && report.Skipped==2,"manual stop still prevents remaining sends under ignore unknown");
        refused(()=>BatchQueue.ValidateConcurrency(9),"parallel limit above eight refused");refused(()=>BatchQueue.ValidateConcurrency(0),"zero concurrency refused");
        order.Clear();report=await CommandBatch.Run(small,request,new(8,false,true),d=>{order.Add(d.DeviceId);return Task.FromResult(Good(d));});
        check(order[0]==small[0].DeviceId && report.Succeeded==3,"optional command pilot precedes the rest of the batch");
    }
}
