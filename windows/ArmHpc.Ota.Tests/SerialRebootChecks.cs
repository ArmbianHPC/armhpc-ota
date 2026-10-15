// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

public static class SerialRebootChecks
{
    static Device Device()=>new(){DeviceId="serial-reboot-fixture",Transport="serial",Address="COM7",SerialPorts=["COM8"]};
    static Credentials Credentials()=>new("root","fixture-password");
    public static async Task Run(Action<bool,string> check)
    {
        var state=new State();var device=Device();
        using(var router=new ConnectionRouter(state.Open))
        {
            var reply=await router.ExecuteArmHpc(new(device.Address,22),Credentials(),device,ArmHpcCommands.Parse("armhpc rescue --reboot"),reboot:new(10));
            check(reply.RebootConfirmed && state.Reboots==1 && reply.BootIdBefore!=reply.BootIdAfter,"serial invalid-operation disconnect during reboot is observed, not treated as an immediate failure");
        }
        state=new(){ChangePort=true};device=Device();
        using(var router=new ConnectionRouter(state.Open))
        {
            var reply=await router.ExecuteArmHpc(new(device.Address,22),Credentials(),device,ArmHpcCommands.Parse("armhpc rescue --reboot"),reboot:new(10));
            check(reply.RebootConfirmed && state.Reboots==1 && device.Address=="COM8","serial reboot finds an explicitly approved replacement COM and preserves device identity");
        }
        state=new(){WrongAfterReboot=true};device=Device();
        using(var router=new ConnectionRouter(state.Open))
        {
            bool rejected=false;try{await router.ExecuteArmHpc(new(device.Address,22),Credentials(),device,ArmHpcCommands.Parse("armhpc rescue --reboot"),reboot:new(10));}catch(InvalidOperationException){rejected=true;}
            check(rejected && state.Reboots==1,"serial reboot never accepts another device or repeats the reboot command");
        }
        string file=Path.GetTempFileName();File.WriteAllText(file,"small signed-package transport fixture");
        try
        {
            state=new();device=Device();var saved=new List<AutomaticTask>();
            using var router=new ConnectionRouter(state.Open);
            var original=AutomaticTask.Create(device.DeviceId,new UpgradeOptions("",Bundle:file,ToolsOnly:true,MinimumAgent:"1.0.0"));
            var result=await AutomaticUpgrade.Run(original,new UpgradeConnection(router,device,Credentials(),[]),saved.Add,_=>{},
                delay:_=>Task.CompletedTask,maintenancePolls:5);
            check(result.Stage=="succeeded" && state.Installs==1 && state.MaintenanceId==original.MaintenanceId,"serial maintenance losing its reboot reply resumes the original maintenance ID without duplicate installation");
            check(saved.Any(t=>t.Stage=="reconnecting" && t.Phase=="maintaining"),"serial reconnect state persists its maintenance phase for controller restart");
        }
        finally{File.Delete(file);}
        string stream=Path.GetTempFileName();File.WriteAllText(stream,"stream restart fixture");
        try
        {
            using var wire=new RestartedReceiver();using var session=new ConsoleSession(wire);
            bool interrupted=false;
            try{await session.StreamFile("fixture-receiver",stream,new FileInfo(stream).Length,
                Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(stream))),_=>{},CancellationToken.None);}
            catch(TransientConnectionException){interrupted=true;}
            check(interrupted && wire.CancelFrames==0,"restarted serial receiver preserves transfer uncertainty and never sends cancel JSON to the new login prompt");
        }
        finally{File.Delete(stream);}
        var pending=new PendingTask("serial-reboot-fixture",Guid.NewGuid().ToString("D"),"r13","all");
        bool uncertain=false;int submits=0;
        try
        {
            await JobMonitor.Run(pending,()=>throw new TransientConnectionException("offline"),
                ()=>{submits++;throw new Exception("must not submit");},()=>throw new TransientConnectionException("still rebooting"),(_,_)=>{},
                polls:5,delay:_=>Task.Delay(5),reconnectTimeout:TimeSpan.FromMilliseconds(1));
        }
        catch(TimeoutException){uncertain=true;}
        check(uncertain && submits==0,"serial reconnect timeout remains an unconfirmed original task, never a new deployment or false success");
    }
    sealed class RestartedReceiver:IConsoleWire
    {
        bool started,delivered;public int CancelFrames;
        public string Read(){if(started && !delivered){delivered=true;return "armhpc login: ";}return "";}
        public void Write(string value){if(value.StartsWith("fixture-receiver"))started=true;if(value.Contains("cancel"))CancelFrames++;}
        public void Dispose(){}
    }
    sealed class State
    {
        public string Boot=Guid.NewGuid().ToString("D"),Mode="system",Version="0.3.4";
        public string? MaintenanceId;public bool ChangePort,WrongAfterReboot;public int Reboots,Installs;
        readonly Dictionary<string,StringBuilder> uploaded=new();
        public IConsoleWire Open(Device d)
        {
            if(ChangePort && Reboots>0 && d.Address!="COM8")throw new IOException("COM disappeared during reboot");
            return new Wire(this);
        }
        public string Execute(string command,Wire wire)
        {
            if(command=="true")return "";
            if(command=="hostname")return "serial-host\n";
            if(command==NetworkMetadata.Command)return "{\"interfaces\":[{\"interface\":\"eth0\",\"mac_address\":\"02:00:00:00:00:07\",\"addresses\":[\"192.168.1.7\"]}]}";
            if(command==SshRunner.BootIdCommand)return Boot+"\n";
            string identity=WrongAfterReboot && Reboots>0?"wrong-device":"serial-reboot-fixture";
            if(command==Commands.Build("status",[],false))return JsonSerializer.Serialize(new{protocol=1,ok=true,data=new{device_id=identity,mode=Mode,agent_version=Version,bootstrapped=true,job=(object?)null}});
            if(command=="python3 -c "+Commands.Quote(SshRunner.MaintenanceIdentityCode))
                return JsonSerializer.Serialize(new{protocol=1,ok=true,data=new{device_id=identity,mode=Mode,maintenance=MaintenanceId is null?null:new{task_id=MaintenanceId,stage="succeeded"}}});
            if(command.Contains("--reboot"))
            {
                Reboots++;Boot=Guid.NewGuid().ToString("D");Mode="rescue";wire.Gone=true;return "";
            }
            var append=Regex.Match(command,@"^printf %s '([A-Za-z0-9+/=]*)' >> '([^']+)'");
            if(append.Success)
            {
                if(!uploaded.TryGetValue(append.Groups[2].Value,out var value))uploaded[append.Groups[2].Value]=value=new();
                value.Append(append.Groups[1].Value);return "";
            }
            var hash=Regex.Match(command,@"^sha256sum '([^']+)'");
            if(hash.Success)
            {
                byte[] data=Convert.FromBase64String(uploaded[hash.Groups[1].Value+".b64"].ToString());
                return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(data))+"  fixture\n";
            }
            var install=Regex.Match(command,@"^python3 '([^']+/verify.py)' '[^']+' '([a-f0-9-]+)'$");
            if(install.Success)
            {
                Installs++;MaintenanceId=install.Groups[2].Value;Version="1.0.0";Mode="rescue";
                Boot=Guid.NewGuid().ToString("D");wire.Gone=true;return "";
            }
            if(command.StartsWith("umask ") || command.StartsWith("base64 -d ") || command.StartsWith("touch "))return "";
            throw new Exception("Unexpected transport fixture command");
        }
    }
    sealed class Wire(State state):IConsoleWire
    {
        readonly ConcurrentQueue<string> pending=new();public bool Gone;
        public string Read(){if(Gone)throw new InvalidOperationException("The port is closed");return pending.TryDequeue(out var value)?value:"";}
        public void Write(string value)
        {
            if(value=="\u0015\r" || value=="\r"){pending.Enqueue("root@serial-host:~#");return;}
            string normalized=value.Replace("'\\''","'");
            string id=Regex.Match(value,"__ARMHPC_([a-f0-9]{32})__").Groups[1].Value;
            string encoded=Regex.Match(normalized,@"base64.b64decode\('([A-Za-z0-9+/=]+)'\)").Groups[1].Value;
            string output=state.Execute(Encoding.UTF8.GetString(Convert.FromBase64String(encoded)),this);
            if(!Gone)pending.Enqueue("\r\n__ARMHPC_"+id+"__:"+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new{rc=0,@out=output,err=""}))+":__END__\r\n");
        }
        public void Dispose(){if(Gone)throw new IOException("device already unplugged");}
    }
}
