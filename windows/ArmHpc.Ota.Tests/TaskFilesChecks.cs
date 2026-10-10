// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
using System.Text.Json;

public static class TaskFilesChecks
{
    static JsonElement J(object value)=>JsonSerializer.SerializeToElement(value);
    public static async Task Run(Action<bool,string> check,Action<Action,string> refused)
    {
        string folder=Path.Combine(Path.GetTempPath(),"armhpc-files-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
        string old=Path.Combine(folder,"old-maintenance.tar.xz"),moved=Path.Combine(folder,"moved-maintenance.tar.xz"),newer=Path.Combine(folder,"new-maintenance.tar.xz");
        File.WriteAllText(old,"signed fixture old bytes");File.Copy(old,moved);File.WriteAllText(newer,"signed fixture new version");
        try
        {
            var task=AutomaticTask.Create("file-fixture",new UpgradeOptions("",Bundle:old,ToolsOnly:true));
            task=task with {Stage="paused",Phase="maintaining"};File.Delete(old);
            var relocated=TaskFiles.SelectTools(task,moved);
            check(relocated.Task.Options.Bundle==Path.GetFullPath(moved) && relocated.Task.MaintenanceId==task.MaintenanceId && relocated.Task.TaskId==task.TaskId && relocated.Task.Options.BundleSha256==task.Options.BundleSha256,"selected relocated maintenance file replaces the missing old path while preserving all approved IDs and hash");
            refused(()=>TaskFiles.RelocateBundle(task,newer),"different maintenance bytes cannot replace a package under the old ID");
            var remote=J(new{device_id=task.DeviceId,mode="rescue",maintenance=new{task_id=task.MaintenanceId,stage="succeeded"}});
            var selection=TaskFiles.SelectTools(task,newer,remote);
            check(selection.Task.Options.Bundle==Path.GetFullPath(newer) && selection.Task.MaintenanceId!=task.MaintenanceId && selection.Superseded?.Terminal==true && selection.Superseded.MaintenanceId==task.MaintenanceId,"new package after completed device maintenance creates a new ID and preserves superseded local history");
            refused(()=>TaskFiles.SelectTools(task,newer,J(new{device_id=task.DeviceId,mode="rescue",maintenance=new{task_id=task.MaintenanceId,stage="installing"}})),"an active original maintenance cannot be replaced with another version");
            refused(()=>TaskFiles.SelectTools(task,newer,J(new{device_id=task.DeviceId,mode="rescue",maintenance=new{task_id="other",stage="queued"}})),"another active device maintenance also blocks package replacement");
            refused(()=>TaskFiles.SelectTools(task,newer,J(new{device_id="wrong-device",mode="rescue",maintenance=(object?)null})),"package replacement requires the original authenticated device identity");
            refused(()=>TaskFiles.SelectTools(task,newer,J(new{device_id=task.DeviceId,mode="rescue"})),"missing maintenance metadata cannot authorize replacement");
            selection=TaskFiles.SelectTools(task,newer,J(new{device_id=task.DeviceId,mode="rescue",maintenance=(object?)null}));
            check(selection.Task.MaintenanceId!=task.MaintenanceId && selection.Action=="new-maintenance-after-device-idle","unused old local maintenance can be superseded after device reports no maintenance");
            refused(()=>TaskFiles.SelectTools(task with {Options=task.Options with {ToolsOnly=false}},newer,remote),"system upgrade package binding cannot be replaced through the tools picker");
            var connection=new Connection(task.MaintenanceId,completed:true);
            var result=await AutomaticUpgrade.Run(task,connection,_=>{},_=>{},delay:_=>Task.CompletedTask,maintenancePolls:4);
            check(result.Stage=="succeeded" && connection.Installs==0,"already completed device maintenance is observed without requiring its deleted local package");
            connection=new Connection(task.MaintenanceId,completed:false);
            result=await AutomaticUpgrade.Run(task,connection,_=>{},_=>{},delay:_=>Task.CompletedTask,maintenancePolls:4);
            check(result.Stage=="succeeded" && connection.Installs==0,"running staged maintenance resumes observation with a missing local file and never resubmits");
            connection=new Connection(null,completed:false);bool missing=false;
            try{await AutomaticUpgrade.Run(task,connection,_=>{},_=>{},delay:_=>Task.CompletedTask,maintenancePolls:3);}catch(FileNotFoundException){missing=true;}
            check(missing && connection.Installs==0,"not yet submitted maintenance still requires its approved local bytes before sending");
            var vault=new Vault(Path.Combine(folder,"vault"));vault.SaveAutomatic([selection.Superseded!,selection.Task]);
            var restored=vault.LoadAutomatic();
            check(restored.Count==2 && restored.Single(t=>t.TaskId==task.TaskId).Terminal && restored.Single(t=>!t.Terminal).Options.Bundle==Path.GetFullPath(newer),"replacement path and immutable previous binding survive controller restart");
        }
        finally{Directory.Delete(folder,true);}
    }
    sealed class Connection(string? id,bool completed):IUpgradeConnection
    {
        int reads;public int Installs;
        public Task<JsonElement> Command(string c,IReadOnlyList<string> a,bool y,CancellationToken token)
            =>Task.FromResult(J(new{device_id="file-fixture",mode="rescue",agent_version="1.0.0",bootstrapped=true,job=(object?)null}));
        public Task<JsonElement> Maintenance(CancellationToken token)
            =>Task.FromResult(J(new{device_id="file-fixture",mode="rescue",maintenance=id is null?null:new{task_id=id,stage=completed || ++reads>=4?"succeeded":"installing"}}));
        public Task<JsonElement> Install(string bundle,string request,CancellationToken token){Installs++;throw new Exception("unexpected submission");}
        public Task<string> UploadCa(string file,CancellationToken token)=>throw new Exception("unexpected CA");
        public Task Reconnect(bool maintenance,CancellationToken token)=>Task.CompletedTask;
    }
}
