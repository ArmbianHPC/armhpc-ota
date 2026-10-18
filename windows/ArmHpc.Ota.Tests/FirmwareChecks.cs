// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
using System.Text.Json;

public static class FirmwareChecks
{
    static JsonElement J(object value)=>JsonSerializer.SerializeToElement(value);
    public static async Task Run(Action<bool,string> check,Action<Action,string> refused)
    {
        var timeout=typeof(SshRunner).GetMethod("DefaultCommandTimeout",System.Reflection.BindingFlags.Static|System.Reflection.BindingFlags.NonPublic)!;
        TimeSpan Timeout(string operation,string action)=>(TimeSpan)timeout.Invoke(null,new object[]{operation,new[]{action}})!;
        check(Timeout("boot","plan")==TimeSpan.FromMinutes(60) && Timeout("boot","apply")==TimeSpan.FromMinutes(60),
              "paired firmware validation and backup have a large-payload SSH deadline");
        check(Timeout("boot","rollback")==TimeSpan.FromMinutes(60) && Timeout("boot","restore")==TimeSpan.FromMinutes(60),
              "BOOT recovery has the same long-running SSH deadline");
        check(Timeout("boot","status")==TimeSpan.FromMinutes(3) && Timeout("status","")==TimeSpan.FromMinutes(3),
              "status queries retain their shorter SSH deadline");
        string directory=Path.Combine(Path.GetTempPath(),"armhpc-firmware-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
        string package=Path.Combine(directory,"firmware.tar.xz");File.WriteAllText(package,"fixture bytes");
        try
        {
            var task=AutomaticTask.Create("device",new("",Package:package));AutomaticTask? saved=null;
            var connection=new FirmwareConnection{LoseSwitchReply=true};
            var result=await AutomaticUpgrade.Run(task,connection,t=>saved=t,_=>{},delay:_=>Task.CompletedTask,jobPolls:12);
            check(result.Stage=="succeeded" && result.Kind=="firmware-update" && connection.FlashCount==1,"firmware upgrade survives a lost switch reply without duplicate deployment");
            check(connection.EnterCount==1 && connection.Exports==1 && connection.Id==task.JobId && saved?.BackupDirectory=="private/"+task.JobId,
                  "normal firmware exports a task-bound recovery backup before switching BOOT");
            var resume=new FirmwareConnection{Id=task.JobId,Stage="awaiting-firmware",Mode="rescue"};
            result=await AutomaticUpgrade.Run(task with{Release="firmware-1.2.1",Kind="firmware-update",FirmwareBundle="/cache/bundle",FirmwareSha256=FirmwareConnection.Hash},resume,_=>{},_=>{},delay:_=>Task.CompletedTask,jobPolls:5);
            check(result.Stage=="succeeded" && resume.Pushes==0 && resume.Exports==0 && resume.MaintenanceQueries==0,
                  "a resumed firmware task only observes its original device request");
            foreach(var incomplete in new[]{"system","rescue","missing"})
            {
                var mismatch=new FirmwareConnection{Id=task.JobId,Stage="committed",Mode="system",
                    SystemRelease=incomplete=="system"?"old-system":"firmware-1.2.1",
                    RescueRelease=incomplete=="rescue"?"old-rescue":"firmware-1.2.1",
                    OmitVersions=incomplete=="missing"};
                AutomaticTask? held=null;bool rejected=false;
                try{await AutomaticUpgrade.Run(task with{Release="firmware-1.2.1",Kind="firmware-update",FirmwareBundle="/cache/bundle",FirmwareSha256=FirmwareConnection.Hash},mismatch,t=>held=t,_=>{},delay:_=>Task.CompletedTask,jobPolls:2);}
                catch(InvalidOperationException){rejected=true;}
                check(rejected && held?.Stage=="paused" && !held.Terminal && mismatch.FlashCount==0,
                      "a committed BOOT task cannot report full success with unconfirmed "+incomplete+" versions");
            }
            var missingSoftware=new FirmwareConnection{Id=task.JobId,Stage="updating-system",Mode="rescue",Frozen=true,FailedSystem=true};
            bool detailedFailure=false;
            try{await AutomaticUpgrade.Run(task with{Release="firmware-1.2.1",Kind="firmware-update",FirmwareBundle="/cache/bundle",FirmwareSha256=FirmwareConnection.Hash},missingSoftware,_=>{},_=>{},delay:_=>Task.CompletedTask,jobPolls:2);}
            catch(InvalidOperationException error){detailedFailure=error.Message.Contains("software_resources") && error.Message.Contains("ipvsadm=1:1.31-1") && error.Message.Contains("尚未写盘");}
            check(detailedFailure && missingSoftware.FlashCount==0,"firmware pause reports the exact software error and prewrite boundary without resubmitting");
            var failedExport=new FirmwareConnection{FailExport=true};bool exportFailed=false;
            try{await AutomaticUpgrade.Run(AutomaticTask.Create("device",new("",Package:package)),failedExport,_=>{},_=>{},delay:_=>Task.CompletedTask,jobPolls:8);}
            catch(IOException){exportFailed=true;}
            check(exportFailed && failedExport.FlashCount==0,"failed recovery export prevents BOOT deployment");
            var unknown=new FirmwareConnection{Frozen=true};AutomaticTask? unknownSaved=null;bool timedOut=false;
            try{await AutomaticUpgrade.Run(AutomaticTask.Create("device",new("",Package:package)),unknown,t=>unknownSaved=t,_=>{},delay:_=>Task.CompletedTask,jobPolls:5);}
            catch(TimeoutException){timedOut=true;}
            check(timedOut && unknownSaved?.Stage=="paused" && !unknownSaved.Terminal,"firmware observation timeout retains an unresolved original task");
            refused(()=>ArmHpcCommands.Parse("armhpc auth key-only --public-key-file /root/admin.pub"),"authentication changes require the operator's explicit --yes");
            refused(()=>ArmHpcCommands.Parse("armhpc firewall set --apply --management-cidr 192.168.1.0/24 --cluster-cidr 192.168.1.0/24"),"firewall changes cannot acquire an implicit confirmation");
            refused(()=>ArmHpcCommands.Parse("armhpc auth _watch"),"private authentication watcher cannot be called through the command panel");
            check(!ArmHpcCommands.Parse("armhpc state reconcile --json").Writes &&
                  ArmHpcCommands.Parse("armhpc state reconcile --apply --yes --json").Writes,"node recovery preview and explicit apply remain distinct");
            check(ArmHpcCommands.Parse("armhpc network set --interface eth0 --dhcp --management --family ipv4 --metric 100 --management-target 192.168.1.1 --plan --json").Writes==false,
                  "management-network preview accepts the new route settings without writing");
            check(NodePresentation.Describe(J(new{})).Caption=="未提供","older agents display missing node fields without inventing health");
        }
        finally{Directory.Delete(directory,true);}
    }

    sealed class FirmwareConnection:IUpgradeConnection
    {
        public const string Hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        public string? Id,Stage;public string Mode="system";public int EnterCount,Exports,FlashCount,Pushes,MaintenanceQueries;
        public bool LoseSwitchReply,FailExport,Frozen,OmitVersions,FailedSystem;
        public string SystemRelease="firmware-1.2.1",RescueRelease="firmware-1.2.1";
        object? TaskRecord()=>Id is null?null:new{task_id=Id,device_id="device",release="firmware-1.2.1",purpose="firmware-update",
            bundle_sha256=Hash,stage=Stage,system_job_id="paired-system",backups=new Dictionary<string,object>{{"BOOT-rescue.img.xz",new{sha256=Hash}}}};
        public Task<JsonElement> Command(string command,IReadOnlyList<string> arguments,bool yes,CancellationToken token)
        {
            if(command=="status")
            {
                if(!Frozen)
                {
                    if(Stage=="awaiting-firmware")Stage="updating-system";
                    else if(Stage=="updating-system"){Stage="committed";Mode="system";}
                }
                return Task.FromResult(J(new{device_id="device",mode=Mode,agent_version="1.2.1",bootstrapped=true,job=FailedSystem?(object)new{job_id="paired-system",stage="failed-recoverable",write_started=false,error=new{code="software_resources",message="Offline software resources missing: ipvsadm=1:1.31-1"}}:null,boot_maintenance=new{task=TaskRecord()},versions=OmitVersions?null:new{system=SystemRelease,rescue=RescueRelease}}));
            }
            if(command=="boot" && arguments[0]=="enter"){EnterCount++;Mode="rescue";return Task.FromResult(J(new{device_id="device"}));}
            if(command=="boot" && arguments[0]=="apply")
            {
                string id=arguments[arguments.ToList().IndexOf("--request-id")+1];
                if(Id is not null && Id!=id)throw new InvalidOperationException("Another task ID");
                Id=id;
                if(arguments.Contains("--exported-backup-sha256") && Stage=="backup-ready")
                {
                    if(Exports!=1)throw new InvalidOperationException("Unexported backup");
                    FlashCount++;Stage="awaiting-firmware";
                    if(LoseSwitchReply){LoseSwitchReply=false;throw new TransientConnectionException("lost switch reply");}
                }
                else if(Stage is null)Stage="backup-ready";
                return Task.FromResult(J(new{task=TaskRecord()}));
            }
            throw new InvalidOperationException(command);
        }
        public Task<JsonElement> StagePackage(string package,string? release,string target,string requestId,Action<string> log,CancellationToken token)
        {Pushes++;return Task.FromResult(J(new{device_id="device",complete=true,kind="firmware-update",release="firmware-1.2.1",firmware_bundle="/cache/bundle",firmware_sha256=Hash}));}
        public Task<string> ExportFirmwareBackup(JsonElement task,Action<string> log,CancellationToken token)
        {if(FailExport)throw new IOException("Export interrupted");Exports++;return Task.FromResult("private/"+Protocol.Text(task,"task_id"));}
        public Task<JsonElement> Maintenance(CancellationToken token){MaintenanceQueries++;return Task.FromResult(J(new{device_id="device",maintenance=(object?)null}));}
        public Task<JsonElement> Install(string bundle,string requestId,CancellationToken token)=>throw new InvalidOperationException("No maintenance expected");
        public Task<string> UploadCa(string file,CancellationToken token)=>throw new NotSupportedException();
        public Task Reconnect(bool maintenance,CancellationToken token)=>Task.CompletedTask;
    }
}
