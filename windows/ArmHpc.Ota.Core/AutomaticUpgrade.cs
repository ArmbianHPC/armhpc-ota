using System.Diagnostics;
// SPDX-License-Identifier: GPL-3.0-only
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace ArmHpc.Ota.Core;

public sealed record UpgradeOptions(string Source,string? Release=null,string Target="all",bool AllowHttp=false,
    string? Bundle=null,string? BundleSha256=null,string? Ca=null,string MinimumAgent="1.1.4",string[]? Ranges=null,bool ToolsOnly=false,string? Package=null,string? PackageSha256=null);
public sealed record AutomaticTask(string TaskId,string DeviceId,UpgradeOptions Options,string MaintenanceId,string JobId,
    string Stage="created",string? Release=null,string? Error=null,string Phase="created",string? Manifest=null)
{
    public bool Terminal=>Stage is "succeeded" or "failed-recoverable" or "cancelled" or "superseded";
    public static AutomaticTask Create(string deviceId,UpgradeOptions options)
    {
        if(deviceId.Length==0 || options.Target is not ("all" or "system" or "rescue"))throw new ArgumentException("自动升级需要已认证设备和有效目标。");
        if(!options.ToolsOnly && options.Package is null)
        {
        if(!Uri.TryCreate(options.Source,UriKind.Absolute,out var url) || url.Scheme is not ("http" or "https") || url.UserInfo.Length>0 || url.Fragment.Length>0)
            throw new ArgumentException("请输入无凭据的 HTTP(S) 索引地址。");
        if(url.Scheme=="http")
        {
            if(!options.AllowHttp || !IPAddress.TryParse(url.Host,out var ip) || ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork)throw new ArgumentException("HTTP 须明确授权 RFC1918 IPv4 地址。");
            byte[] b=ip.GetAddressBytes();if(!(b[0]==10 || b[0]==172 && b[1]>=16 && b[1]<=31 || b[0]==192 && b[1]==168))throw new ArgumentException("HTTP 仅支持具体 RFC1918 地址。");
        }
        }
        if(options.ToolsOnly && options.Bundle is null)throw new ArgumentException("工具自动升级需要签名维护包。");
        if(!Version.TryParse(options.MinimumAgent,out _))throw new ArgumentException("最低 agent 版本无效。");
        if(Version.Parse(options.MinimumAgent)<Version.Parse("0.3.5"))options=options with {MinimumAgent="0.3.5"};
        foreach(string range in options.Ranges??[])Scanner.Expand(range);
        if(options.Bundle is not null)
        {
            string file=Path.GetFullPath(options.Bundle);using var stream=File.OpenRead(file);
            string digest=Convert.ToHexStringLower(SHA256.HashData(stream));
            if(options.BundleSha256 is not null && options.BundleSha256!=digest)throw new InvalidOperationException("已批准的维护包发生变化。");
            options=options with {Bundle=file,BundleSha256=digest};
        }
        if(options.Package is not null)
        {
            if(!File.Exists(options.Package) && !Directory.Exists(options.Package))throw new ArgumentException("本地 OTA 包不存在。");
            options=options with {Package=Path.GetFullPath(options.Package)};
            if(File.Exists(options.Package)){using var stream=File.OpenRead(options.Package);string hash=Convert.ToHexStringLower(SHA256.HashData(stream));if(options.PackageSha256 is not null && options.PackageSha256!=hash)throw new InvalidOperationException("本地 OTA 包已改变。");options=options with {PackageSha256=hash};}
        }
        return new(Guid.NewGuid().ToString("D"),deviceId,options,Guid.NewGuid().ToString("D"),Guid.NewGuid().ToString("D"));
    }
}

public interface IUpgradeConnection
{
    Task<JsonElement> Command(string command,IReadOnlyList<string> arguments,bool yes,CancellationToken token);
    Task<JsonElement> Maintenance(CancellationToken token);
    Task<JsonElement> Install(string bundle,string requestId,CancellationToken token);
    Task<string> UploadCa(string file,CancellationToken token);
    Task Reconnect(bool maintenance,CancellationToken token);
    Task<JsonElement> StagePackage(string package,string? release,string target,string requestId,Action<string> log,CancellationToken token)=>throw new NotSupportedException();
}

public sealed class UpgradeConnection(ConnectionRouter router,Device device,Credentials credentials,string[] ranges):IUpgradeConnection
{
    private Endpoint Endpoint=>new(device.Address,device.Port);
    public async Task<JsonElement> Command(string command,IReadOnlyList<string> arguments,bool yes,CancellationToken token)
        =>(await router.Execute(Endpoint,credentials,device,command,arguments,yes,cancellation:token)).Data;
    public Task<JsonElement> Maintenance(CancellationToken token)=>router.MaintenanceStatus(Endpoint,credentials,device,token);
    public Task<JsonElement> Install(string bundle,string requestId,CancellationToken token)=>router.InstallTools(Endpoint,credentials,device,bundle,token,requestId);
    public Task<string> UploadCa(string file,CancellationToken token)=>router.Upload(Endpoint,credentials,device,file,token);
    public async Task<JsonElement> StagePackage(string package,string? release,string target,string requestId,Action<string> log,CancellationToken token)
    {
        var local=await PushPackage.Inspect(package,release,token);
        return await router.StagePackage(Endpoint,credentials,device,local,target,requestId,log,token);
    }
    public async Task Reconnect(bool maintenance,CancellationToken token){await router.Reconnect(device,credentials,ranges,token,maintenance);}
}

/// <summary>Host orchestration only. All signature, disk, trial and recovery decisions use the device CLI.</summary>
public static class AutomaticUpgrade
{
    public static async Task<AutomaticTask> Run(AutomaticTask original,IUpgradeConnection connection,Action<AutomaticTask> save,
        Action<string> log,CancellationToken token=default,Func<CancellationToken,Task>? delay=null,int maintenancePolls=600,int jobPolls=4800)
    {
        delay??=t=>Task.Delay(3000,t);var task=original;
        void Stage(string value,string? error=null){task=task with {Stage=value,Error=error,Phase=value is "paused" or "reconnecting"?task.Phase:value};save(task);log(value);}
        async Task<JsonElement> Query(Func<Task<JsonElement>> operation,bool maintenance=false)
        {
            var reconnecting=Stopwatch.StartNew();
            for(int i=0;i<600;i++)
            {
                token.ThrowIfCancellationRequested();
                try{return await operation();}
                catch(TransientConnectionException)
                {
                    if(reconnecting.Elapsed>=TimeSpan.FromMinutes(5))throw new TimeoutException("重连等待超过 5 分钟，原任务已保留；可继续观察，不重复提交。");
                    Stage("reconnecting");log("等待设备重连，保留原任务 ID");
                    try{await connection.Reconnect(maintenance,token);}catch(TransientConnectionException){}
                    await delay(token);
                }
            }
            throw new TimeoutException("设备未能重连；持久请求可继续观察。");
        }
        void CheckId(JsonElement value){if(Protocol.Text(value,"device_id")!=task.DeviceId)throw new InvalidOperationException("自动升级设备 ID 不匹配。");}
        async Task<bool> Observe()
        {
            return await JobMonitor.Run(new(task.DeviceId,task.JobId,task.Release!,task.Options.Target),
                ()=>connection.Command("status",["--job",task.JobId],false,token),
                async()=>await connection.Command("apply",task.Manifest is null
                    ? ["--release",task.Release!,"--target",task.Options.Target,"--request-id",task.JobId]
                    : ["--manifest",task.Manifest,"--target",task.Options.Target,"--request-id",task.JobId,"--local-only"],true,token),
                ()=>connection.Reconnect(false,token),(stage,percent)=>Stage(stage),token,jobPolls,delay);
        }
        try
        {
            if(task.Terminal)return task;
            // Once a release is bound, resume only that exact job; do not change the source or run maintenance again.
            if(task.Release is not null)
            {
                bool success=await Observe();Stage(success?"succeeded":"failed-recoverable");return task;
            }
            bool resumeMaintenance=original.Phase=="maintaining";
            JsonElement status=default;
            Stage(resumeMaintenance?"maintaining":"checking-device");
            if(!resumeMaintenance)
            {
                status=await Query(()=>connection.Command("status",[],false,token));CheckId(status);
                if(!status.GetProperty("bootstrapped").GetBoolean())throw new InvalidOperationException("设备尚未完成 OTA 布局接入；请先完成 bootstrap。");
                if(status.TryGetProperty("job",out var active) && active.ValueKind==JsonValueKind.Object && Protocol.Text(active,"stage") is not ("succeeded" or "failed-recoverable" or "cancelled"))
                    throw new InvalidOperationException("设备已有活动 OTA 任务。");
            }
            var maintenance=await Query(()=>connection.Maintenance(token),true);CheckId(maintenance);
            bool pending=maintenance.TryGetProperty("maintenance",out var existing) && existing.ValueKind==JsonValueKind.Object && Protocol.Text(existing,"stage") is not ("succeeded" or "rolled-back");
            bool needsTools=resumeMaintenance || task.Options.ToolsOnly || Version.Parse(Protocol.Text(status,"agent_version"))<Version.Parse(task.Options.MinimumAgent) || pending;
            if(pending && Protocol.Text(existing,"task_id")!=task.MaintenanceId)throw new InvalidOperationException("设备有其他工具维护请求；请先继续或回退该请求。");
            if(needsTools)
            {
                Stage("maintaining");string? bundle=task.Options.Bundle;
                var before=await Query(()=>connection.Maintenance(token),true);CheckId(before);
                bool same=before.TryGetProperty("maintenance",out var m) && m.ValueKind==JsonValueKind.Object && Protocol.Text(m,"task_id")==task.MaintenanceId;
                if(!same || Protocol.Text(m,"stage") is "incomplete" or "rolled-back")
                {
                    try{TaskFiles.VerifyBundle(task);await connection.Install(bundle!,task.MaintenanceId,token);}
                    catch(TransientConnectionException){Stage("reconnecting");log("maintenance-submit-unknown · 等待设备重连");}
                }
                bool completed=false;int submissions=1;
                for(int poll=0;poll<maintenancePolls;poll++)
                {
                    var result=await Query(()=>connection.Maintenance(token),true);CheckId(result);
                    bool hasRecord=result.TryGetProperty("maintenance",out m) && m.ValueKind==JsonValueKind.Object;
                    if(hasRecord && Protocol.Text(m,"task_id")==task.MaintenanceId)
                    {
                        string stage=Protocol.Text(m,"stage");log("tools:"+stage);
                        if(stage=="succeeded"){completed=true;break;}
                        if(stage is "incomplete" or "rolled-back")throw new InvalidOperationException("工具维护未成功；可继续原请求或回退维护。");
                    }
                    else if(hasRecord && Protocol.Text(m,"stage") is not ("succeeded" or "rolled-back"))
                        throw new InvalidOperationException("设备有其他活动维护请求；原请求 ID 不匹配。");
                    else if(submissions++<3)
                    {
                        // A lost reply does not authorize a new request. Retry the same signed bundle and ID.
                        try{TaskFiles.VerifyBundle(task);await connection.Install(bundle!,task.MaintenanceId,token);}catch(TransientConnectionException){Stage("reconnecting");log("maintenance-submit-unknown · 等待设备重连");}
                    }
                    await delay(token);
                }
                if(!completed)throw new TimeoutException("工具维护仍在运行；可继续原自动升级任务。");
                status=await Query(()=>connection.Command("status",[],false,token));CheckId(status);
                if(Version.Parse(Protocol.Text(status,"agent_version"))<Version.Parse(task.Options.MinimumAgent))throw new InvalidOperationException("维护后的工具版本仍低于要求。");
            }
            if(task.Options.ToolsOnly){Stage("succeeded");return task;}
            if(task.Options.Package is not null)
            {
                if(task.Options.PackageSha256 is not null){using var stream=File.OpenRead(task.Options.Package);if(Convert.ToHexStringLower(SHA256.HashData(stream))!=task.Options.PackageSha256)throw new InvalidOperationException("本地包已改变，拒绝继续原任务。");}
                Stage("uploading-package");var staged=await Query(()=>connection.StagePackage(task.Options.Package,task.Options.Release,task.Options.Target,task.TaskId,log,token));CheckId(staged);
                if(!staged.GetProperty("complete").GetBoolean())throw new InvalidOperationException("设备尚未接收完整包。");
                task=task with {Release=Protocol.Text(staged,"release"),Manifest=Protocol.Text(staged,"manifest")};Stage("submitting");
                bool success=await Observe();Stage(success?"succeeded":"failed-recoverable");return task;
            }
            Stage("configuring-source");var args=new List<string>{"set","--url",task.Options.Source};
            if(task.Options.AllowHttp)args.Add("--allow-http");
            if(task.Options.Ca is not null)args.AddRange(["--ca",await connection.UploadCa(task.Options.Ca,token)]);
            await Query(()=>connection.Command("source",args,true,token));
            Stage("verifying-source");await Query(()=>connection.Command("source",["test"],false,token));
            var index=await Query(()=>connection.Command("check",[],false,token));CheckId(index);
            var candidates=index.GetProperty("releases").EnumerateArray().Where(r=>task.Options.Release is null || Protocol.Text(r,"release")==task.Options.Release).ToArray();
            if(candidates.Length==0)throw new InvalidOperationException("更新源没有所选的兼容版本。");
            string minimum=Protocol.Text(candidates[0],"minimum_agent");
            if(minimum.Length>0 && Version.Parse(Protocol.Text(status,"agent_version"))<Version.Parse(minimum))
            {
                task=task with {Options=task.Options with {MinimumAgent=minimum}};Stage("maintaining");
                return await Run(task,connection,save,log,token,delay,maintenancePolls,jobPolls);
            }
            Stage("diagnosing");await Query(()=>connection.Command("doctor",[],false,token));
            Stage("planning");var arguments=new List<string>{"--target",task.Options.Target};if(task.Options.Release is not null)arguments.AddRange(["--release",task.Options.Release]);
            var plan=await Query(()=>connection.Command("plan",arguments,false,token));CheckId(plan);
            if(!plan.GetProperty("write_allowed").GetBoolean())throw new InvalidOperationException("设备拒绝此升级计划；请检查兼容性、空间和硬件门槛。");
            string release=Protocol.Text(plan,"release");if(release.Length==0)throw new InvalidOperationException("升级计划缺少版本。");
            task=task with {Release=release};Stage("submitting");
            bool ok=await Observe();Stage(ok?"succeeded":"failed-recoverable");return task;
        }
        catch(OperationCanceledException){save(task);throw;}
        catch(Exception e){Stage("paused",e is RemoteRejectedException r?r.Code:e.GetType().Name);throw;}
    }
}
