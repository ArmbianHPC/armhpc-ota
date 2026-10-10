// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

public static class AutomationChecks
{
    static JsonElement J(object value)=>JsonSerializer.SerializeToElement(value);
    public static async Task Run(Action<bool,string> check,Action<Action,string> refused)
    {
        if(Environment.GetEnvironmentVariable("ARMHPC_CONSOLE_FIXTURES") is {} export)
        {
            var samples=new[]{"plain","中文与🙂","single' double\" quote","literal $(echo injected) `echo injected` $HOME","multi\nline"};
            File.WriteAllText(export,JsonSerializer.Serialize(samples.Select(value=>{string id=Guid.NewGuid().ToString("N");return new{nonce=id,expected=value,command=ConsoleProtocol.Wrap("printf %s "+Commands.Quote(value),id)};})));
        }
        string n=Guid.NewGuid().ToString("N");string payload=Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"rc\":0,\"out\":\"fixture\",\"err\":\"\"}"));
        string frame="\r\n__ARMHPC_"+n+"__:"+payload+":__END__\r\n";
        check(ConsoleProtocol.Decode("Linux banner\nroot@fixture:~# "+frame,n)?.Output=="fixture","serial frame ignores banners and shell echo");
        check(ConsoleProtocol.Decode(frame,Guid.NewGuid().ToString("N")) is null,"serial ignores responses from another command");
        check(ConsoleProtocol.Decode(frame[..^12],n) is null,"fragmented serial frame is not treated as a complete response");
        check(ConsoleProtocol.Prompt("\r\narmhpc login: ")=="login" && ConsoleProtocol.Prompt("Password: ")=="password" && ConsoleProtocol.Prompt("选择 [0]: ")=="menu","serial identifies login, password and first-login menu");
        refused(()=>ConsoleProtocol.Wrap(new string('x',4000),n),"serial rejects lines above canonical terminal capacity");
        refused(()=>ConsoleProtocol.VerifyIdentity(new Device{DeviceId="expected"},J(new{device_id="wrong",mode="rescue"})),"serial checks persistent device identity before operations");
        using(var wire=new FakeWire())using(var session=new ConsoleSession(wire))
        {
            await session.Login(new("root","fixture-password"),CancellationToken.None);
            var reply=await session.Run("printf fixture",TimeSpan.FromSeconds(2),CancellationToken.None);
            check(reply.Output=="fixture" && wire.Authenticated,"serial session authenticates and reads a fragmented framed command");
        }
        var serialDevice=new Device{Transport="serial",Address="COM8",BaudRate=115200,Name="USB console"};
        var roundTrip=Csv.Import(Csv.Export([serialDevice])).Single();check(roundTrip.Transport=="serial" && roundTrip.Address=="COM8","serial CSV round trip preserves transport without credentials");
        string folder=Path.Combine(Path.GetTempPath(),"armhpc-automation-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);string bundle=Path.Combine(folder,"maintenance.tar.xz");File.WriteAllText(bundle,"signed fixture package");
        try
        {
            UpgradeOptions Options()=>new("http://192.168.100.192:28780/ota-index.json","r13",AllowHttp:true,Bundle:bundle);
            refused(()=>AutomaticTask.Create("device",Options() with {AllowHttp=false}),"automation refuses HTTP without explicit consent");
            refused(()=>AutomaticTask.Create("device",Options() with {Source="http://example.com/ota-index.json"}),"automation refuses HTTP DNS outside the registered literal address");
            refused(()=>AutomaticTask.Create("device",Options() with {Source="http://8.8.8.8/index.json"}),"automation refuses public HTTP before maintenance");
            var current=AutomaticTask.Create("device",Options());AutomaticTask? saved=null;
            var old=new FakeUpgrade{Version="0.2.0",LoseInstallReply=true,LoseApplyReply=true};
            var result=await AutomaticUpgrade.Run(current,old,t=>saved=t,_=>{},delay:_=>Task.CompletedTask,maintenancePolls:5,jobPolls:8);
            check(result.Stage=="succeeded" && old.Installs==1 && old.Applies==1,"r12 tool maintenance and full upgrade survive lost replies without duplicate jobs");
            check(old.MaintenanceId==current.MaintenanceId && old.JobId==current.JobId && saved?.Release=="r13","automation persists and binds both device request IDs and selected release");
            var toolsOnly=new FakeUpgrade{Version="0.2.0"};
            result=await AutomaticUpgrade.Run(AutomaticTask.Create("device",new UpgradeOptions("",Bundle:bundle,ToolsOnly:true)),toolsOnly,_=>{},_=>{},delay:_=>Task.CompletedTask,maintenancePolls:5);
            check(result.Stage=="succeeded" && toolsOnly.Installs==1 && toolsOnly.Sources==0 && toolsOnly.Applies==0,"tool-only automation maintains all runtimes without submitting a system upgrade");
            var parserLegacy=new FakeUpgrade{Version="0.3.2"};
            await AutomaticUpgrade.Run(AutomaticTask.Create("device",Options()),parserLegacy,_=>{},_=>{},delay:_=>Task.CompletedTask,maintenancePolls:5,jobPolls:5);
            check(parserLegacy.Installs==1 && parserLegacy.Version=="1.0.0","agent 0.3.2 receives the diagnostic guardian maintenance before a new upgrade");
            var legacyBound=current with {Options=current.Options with {MinimumAgent="0.3.2"},Release="r13",Stage="reconnecting",Phase="trial-rescue"};
            var legacyObserver=new FakeUpgrade{Version="0.3.2",JobId=legacyBound.JobId};
            await AutomaticUpgrade.Run(legacyBound,legacyObserver,_=>{},_=>{},delay:_=>Task.CompletedTask,jobPolls:5);
            check(legacyObserver.Installs==0 && legacyObserver.Applies==0,"a persisted agent 0.3.2 task continues with its original binding");
            var fresh=new FakeUpgrade();await AutomaticUpgrade.Run(AutomaticTask.Create("device",Options()),fresh,_=>{},_=>{},delay:_=>Task.CompletedTask,jobPolls:5);
            check(fresh.Installs==0 && fresh.Applies==1,"up-to-date OTA tools are automatically skipped");
            var reject=new FakeUpgrade{WriteAllowed=false};bool blocked=false;
            try{await AutomaticUpgrade.Run(AutomaticTask.Create("device",Options()),reject,_=>{},_=>{},delay:_=>Task.CompletedTask);}catch(InvalidOperationException){blocked=true;}
            check(blocked && reject.Applies==0,"a rejected disk plan cannot submit deployment");
            var resume=new FakeUpgrade{JobId=current.JobId};
            var bound=current with {Release="r13",Stage="reconnecting",Phase="trial-rescue"};
            await AutomaticUpgrade.Run(bound,resume,_=>{},_=>{},delay:_=>Task.CompletedTask,jobPolls:4);
            check(resume.Sources==0 && resume.Installs==0 && resume.Applies==0,"reopening a bound upgrade observes the same job without source changes or resubmission");
            var partial=new FakeUpgrade{Version="0.2.0",MaintenanceId=current.MaintenanceId,BlockCliUntilMaintenance=true};
            await AutomaticUpgrade.Run(current with {Stage="paused",Phase="maintaining"},partial,_=>{},_=>{},delay:_=>Task.CompletedTask,maintenancePolls:5,jobPolls:5);
            check(partial.Installs==0 && partial.Applies==1,"partially maintained agent resumes through shared identity without importing broken CLI code");
            var other=new FakeUpgrade{Identity="another-device"};bool mismatch=false;
            try{await AutomaticUpgrade.Run(current,other,_=>{},_=>{},delay:_=>Task.CompletedTask);}catch(InvalidOperationException){mismatch=true;}
            check(mismatch && other.Applies==0 && other.Installs==0,"automatic flow refuses a different device before writes");
            var interrupt=new FakeUpgrade{Version="0.2.0",DropBeforePersist=true};
            await AutomaticUpgrade.Run(current,interrupt,_=>{},_=>{},delay:_=>Task.CompletedTask,maintenancePolls:5,jobPolls:5);
            check(interrupt.Installs==2 && interrupt.InstallIds.Distinct().Count()==1,"lost pre-persistence maintenance submission retries the same signed request ID");
            var higher=new FakeUpgrade{Minimum="1.1.0",InstalledVersion="1.1.0"};
            await AutomaticUpgrade.Run(AutomaticTask.Create("device",Options()),higher,_=>{},_=>{},delay:_=>Task.CompletedTask,maintenancePolls:5,jobPolls:5);
            check(higher.Installs==1 && higher.Version=="1.1.0" && higher.Applies==1,"signed index can require a newer agent and trigger supplied tool maintenance");
            var failure=new FakeUpgrade{JobStage="failed-recoverable"};
            result=await AutomaticUpgrade.Run(AutomaticTask.Create("device",Options()),failure,_=>{},_=>{},delay:_=>Task.CompletedTask,jobPolls:5);
            check(result.Stage=="failed-recoverable" && failure.Applies==1,"deployment failure stops automation for explicit manual recovery");
            var vault=new Vault(Path.Combine(folder,"vault"));vault.SaveAutomatic([current]);var restored=vault.LoadAutomatic().Single();
            var credentialDevice=new Device{DeviceId="same-device",Transport="ssh"};vault.SaveConnection(credentialDevice,new("root","",PrivateKeyPath:"fixture-key"));
            credentialDevice.Transport="serial";vault.SaveConnection(credentialDevice,new("root","fixture-password"));
            string? serialPassword=vault.LoadConnection(credentialDevice)?.Password;credentialDevice.Transport="ssh";
            check(serialPassword=="fixture-password" && vault.LoadConnection(credentialDevice)?.PrivateKeyPath=="fixture-key","SSH key and serial password remain separate in DPAPI storage");
            string raw=File.ReadAllText(Path.Combine(folder,"vault/automatic.json"));
            check(restored.JobId==current.JobId && restored.MaintenanceId==current.MaintenanceId && !raw.Contains("Password") && !raw.Contains("Passphrase"),"automatic tasks survive controller restarts without storing credentials");
            string package=Path.Combine(folder,"release.tar.xz");File.WriteAllText(package,"fixture signed package");
            UpgradeOptions Push()=>new("",Target:"all",Bundle:bundle,Package:package);
            var pushed=new FakeUpgrade{Version="1.0.0",InstalledVersion="1.0.0",LosePushReply=true};
            var pushTask=AutomaticTask.Create("device",Push());
            result=await AutomaticUpgrade.Run(pushTask,pushed,_=>{},_=>{},delay:_=>Task.CompletedTask,jobPolls:5);
            check(result.Stage=="succeeded" && pushed.Sources==0 && pushed.Pushes==2 && pushed.PushIds.Distinct().Single()==pushTask.TaskId && pushed.Applies==1 && pushed.LocalOnlyApply,"push resumes the same upload and submits local-only OTA without source configuration");
            var legacyPush=new FakeUpgrade{Version="0.3.0",InstalledVersion="1.0.0"};
            result=await AutomaticUpgrade.Run(AutomaticTask.Create("device",Push()),legacyPush,_=>{},_=>{},delay:_=>Task.CompletedTask,maintenancePolls:5,jobPolls:5);
            check(result.Stage=="succeeded" && legacyPush.Installs==1 && legacyPush.Pushes==1 && legacyPush.Sources==0,"existing r12 agent is maintained once before package push");
            var partialPush=new FakeUpgrade{Version="1.0.0",PushComplete=false};bool partialRefused=false;
            try{await AutomaticUpgrade.Run(AutomaticTask.Create("device",Push()),partialPush,_=>{},_=>{},delay:_=>Task.CompletedTask,jobPolls:5);}catch(InvalidOperationException){partialRefused=true;}
            check(partialRefused && partialPush.Applies==0,"incomplete upload cannot submit disk writing");
            var lost=new FakeUpgrade{Version="1.0.0",LoseApplyReply=true};
            result=await AutomaticUpgrade.Run(AutomaticTask.Create("device",Push()),lost,_=>{},_=>{},delay:_=>Task.CompletedTask,jobPolls:5);
            check(result.Stage=="succeeded" && lost.Applies==1 && lost.LocalOnlyApply,"push observes lost apply response without a duplicate deployment");
            var pushResume=new FakeUpgrade{JobId=pushTask.JobId,Version="1.0.0"};
            result=await AutomaticUpgrade.Run(pushTask with {Release="r13",Manifest="/shared/manifests/r13.json",Stage="reconnecting"},pushResume,_=>{},_=>{},delay:_=>Task.CompletedTask,jobPolls:5);
            check(result.Stage=="succeeded" && pushResume.Pushes==0 && pushResume.Sources==0,"bound push task resumes remote observation without republishing");
            var fileChanged=AutomaticTask.Create("device",Push());File.AppendAllText(package,"changed");var untouched=new FakeUpgrade{Version="1.0.0"};bool packageRejected=false;
            try{await AutomaticUpgrade.Run(fileChanged,untouched,_=>{},_=>{},delay:_=>Task.CompletedTask);}catch(InvalidOperationException){packageRejected=true;}
            check(packageRejected && untouched.Pushes==0 && untouched.Applies==0,"changed approved local package is rejected before payload upload");
            var changed=AutomaticTask.Create("device",Options());File.AppendAllText(bundle,"modified");var target=new FakeUpgrade{Version="0.2.0"};bool bad=false;
            try{await AutomaticUpgrade.Run(changed,target,_=>{},_=>{},delay:_=>Task.CompletedTask);}catch(InvalidOperationException){bad=true;}
            check(bad && target.Installs==0,"resume rejects a changed local maintenance bundle before installation");
        }
        finally{Directory.Delete(folder,true);}
    }
    private sealed class FakeWire:IConsoleWire
    {
        readonly Queue<string> buffer=new();int login;
        public bool Authenticated{get;private set;}
        public void Write(string value)
        {
            if(login==0){buffer.Enqueue("Debian\r\narmhpc login: ");login++;}
            else if(login==1){buffer.Enqueue("Password: ");login++;}
            else if(login==2){Authenticated=value=="fixture-password\r";buffer.Enqueue("\r\nroot@fixture:~# ");login++;}
            else
            {
                string id=Regex.Match(value,"__ARMHPC_([a-f0-9]{32})__").Groups[1].Value;
                string reply="\r\n__ARMHPC_"+id+"__:"+Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"rc\":0,\"out\":\"fixture\",\"err\":\"\"}"))+":__END__\r\n";
                buffer.Enqueue("shell echo\r\n"+reply[..40]);buffer.Enqueue(reply[40..]);
            }
        }
        public string Read()=>buffer.TryDequeue(out var value)?value:"";
        public void Dispose(){}
    }
    private sealed class FakeUpgrade:IUpgradeConnection
    {
        public string Version="1.0.0",InstalledVersion="1.0.0",Minimum="0.3.0",Identity="device",JobStage="succeeded";
        public string? MaintenanceId,JobId;public int Installs,Applies,Sources,Pushes;public List<string> InstallIds=[],PushIds=[];
        public bool LoseInstallReply,LoseApplyReply,DropBeforePersist,BlockCliUntilMaintenance,LosePushReply,LocalOnlyApply,WriteAllowed=true,PushComplete=true;
        public Task<JsonElement> Command(string command,IReadOnlyList<string> arguments,bool yes,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if(BlockCliUntilMaintenance)throw new InvalidOperationException("broken CLI must not be imported during resumed maintenance");
            if(command=="status")
            {
                if(arguments.Contains("--job") && JobId is null)throw new RemoteRejectedException("job_missing","not submitted yet");
                return Task.FromResult(J(new{device_id=Identity,mode="system",agent_version=Version,bootstrapped=true,job=JobId is null?null:new{job_id=JobId,stage=JobStage}}));
            }
            if(command=="source"){if(arguments[0]=="set")Sources++;return Task.FromResult(J(new{verified=true}));}
            if(command=="doctor")return Task.FromResult(J(new{hardware_verified=false}));
            if(command=="check")return Task.FromResult(J(new{device_id=Identity,releases=new[]{new{release="r13",minimum_agent=Minimum}}}));
            if(command=="plan")return Task.FromResult(J(new{device_id=Identity,release="r13",target="all",write_allowed=WriteAllowed}));
            if(command=="apply")
            {
                LocalOnlyApply=arguments.Contains("--local-only") && arguments.Contains("--manifest");Applies++;JobId=arguments[arguments.ToList().IndexOf("--request-id")+1];
                if(LoseApplyReply){LoseApplyReply=false;throw new TransientConnectionException("lost apply reply");}
                return Task.FromResult(J(new{job_id=JobId}));
            }
            throw new InvalidOperationException("Unexpected command: "+command);
        }
        public Task<JsonElement> Maintenance(CancellationToken token)
        {
            if(MaintenanceId is not null){Version=InstalledVersion;BlockCliUntilMaintenance=false;}
            return Task.FromResult(J(new{device_id=Identity,mode="rescue",maintenance=MaintenanceId is null?null:new{task_id=MaintenanceId,stage="succeeded"}}));
        }
        public Task<JsonElement> Install(string bundle,string requestId,CancellationToken token)
        {
            Installs++;InstallIds.Add(requestId);
            if(DropBeforePersist){DropBeforePersist=false;throw new TransientConnectionException("lost before persistence");}
            MaintenanceId=requestId;
            if(LoseInstallReply){LoseInstallReply=false;throw new TransientConnectionException("lost install reply");}
            return Maintenance(token);
        }
        public Task<JsonElement> StagePackage(string package,string? release,string target,string requestId,Action<string> log,CancellationToken token)
        {
            Pushes++;PushIds.Add(requestId);
            if(LosePushReply){LosePushReply=false;throw new TransientConnectionException("lost during upload");}
            return Task.FromResult(J(new{device_id=Identity,complete=PushComplete,release="r13",manifest="/shared/manifests/r13.json"}));
        }
        public Task<string> UploadCa(string file,CancellationToken token)=>Task.FromResult("/tmp/public-ca.pem");
        public Task Reconnect(bool maintenance,CancellationToken token)=>Task.CompletedTask;
    }
}
