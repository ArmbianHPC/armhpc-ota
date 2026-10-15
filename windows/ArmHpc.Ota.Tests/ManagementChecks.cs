// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
public static class ManagementChecks
{
    public static async Task Run(Action<bool,string> check,Action<Action,string> refused)
    {
        string exportDirectory=Path.Combine(Path.GetTempPath(),"armhpc-boot-export-"+Guid.NewGuid());
        try
        {
            string id=Guid.NewGuid().ToString("D");var exportDevice=new Device{DeviceId="export-device"};
            byte[] payload="private boot backup"u8.ToArray();string digest=Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(payload));
            var backups=new Dictionary<string,object>();
            foreach(string name in new[]{"BOOT-original.img","BOOT-rescue.img","BOOT-rescue.img.xz"})
            {File.WriteAllBytes(PrivateBootExport.Destination(exportDirectory,name),payload);backups[name]=new{bytes=payload.Length,sha256=digest};}
            var exportTask=JsonSerializer.SerializeToElement(new{task_id=id,device_id=exportDevice.DeviceId,boot=new{start_lba=204800,sectors=1048576},backups,
                emmc_cid_sha256=new string('a',64),recovery=new{board="wxy-oesp-v22",slot="a"}});
            PrivateBootExport.Descriptor(exportDirectory,exportDevice,exportTask);
            using var descriptor=JsonDocument.Parse(File.ReadAllText(Path.Combine(exportDirectory,"BOOT-export.json")));
            check(Protocol.Text(descriptor.RootElement,"task_id")==id && Protocol.Text(descriptor.RootElement,"device_id")==exportDevice.DeviceId,
                "private BOOT export descriptor binds original task and device");
            refused(()=>PrivateBootExport.Descriptor(exportDirectory,new Device{DeviceId="other-device"},exportTask),"BOOT descriptor rejects a different device");
            File.AppendAllText(Path.Combine(exportDirectory,"BOOT-rescue.img"),"changed");
            refused(()=>PrivateBootExport.Descriptor(exportDirectory,exportDevice,exportTask),"BOOT descriptor is not replaced after a failed file hash");
            check(Commands.Build("boot",["restore","--request-id",id,"--execute"],false,true).Contains("'restore'"),
                "BOOT-only restore uses the existing public protocol");
        }finally{if(Directory.Exists(exportDirectory))Directory.Delete(exportDirectory,true);}
        var normal=new Device{DeviceId="normal",Hostname="armhpc-010f",Address="192.168.1.10",Name="worker",Mode="system",Selected=true};
        var rescue=new Device{DeviceId="rescue",Hostname="armhpc-rescue-72ac",Address="192.168.1.11",Mode="rescue"};
        check(DeviceSelection.Matches(rescue,"RESCUE") && DeviceSelection.Matches(normal,"192.168.1.10"),"hostname search ignores case and accepts address fallback");
        check(DeviceSelection.Matches(normal,"ARMHPC-010F",true) && !DeviceSelection.Matches(normal,"010f",true),"exact hostname matches a complete name");
        check(!DeviceSelection.Matches(rescue,"",mode:"system"),"environment filter separates normal and Rescue hosts");
        check(DeviceSelection.Targets([rescue],[rescue]).Single()==rescue,"hidden checked rows cannot become batch targets");
        check(DeviceSelection.Targets([normal,rescue],[rescue]).Single()==normal,"visible checkboxes take priority over highlighted rows");
        normal.Selected=false;check(DeviceSelection.Targets([normal,rescue],[normal,rescue]).Count==2,"Ctrl/Shift highlighted rows support multiple targets");
        var imported=Csv.Import(Csv.Export([normal,rescue]));check(imported[1].Hostname==rescue.Hostname,"hostname survives inventory CSV round trip");
        string folder=Path.Combine(Path.GetTempPath(),"armhpc-defaults-"+Guid.NewGuid().ToString("N"));
        try
        {
            var vault=new Vault(folder);var credentials=new Credentials("fixture-user","not-a-real-password");vault.SaveDefault(credentials);
            check(new Vault(folder).LoadDefault()==credentials,"default login survives controller restart under DPAPI");
            check(!Directory.GetFiles(folder).Any(p=>File.ReadAllText(p).Contains(credentials.Password)),"default password never appears in plaintext storage");
            vault.SaveConnection(normal,new("node-user","fixture-override"));vault.ClearDefault();
            check(vault.LoadDefault() is null && vault.LoadConnection(normal)?.Username=="node-user","clearing defaults retains per-device credentials");
        }finally{Directory.Delete(folder,true);}
        var help=ArmHpcCommands.Parse("armhpc --help");check(!help.Writes && help.Build("rescue",false).Contains("armhpc-rescue"),"common commands route to the current environment");
        var request=ArmHpcCommands.Parse("armhpc rescue --reboot");check(request.Writes && request.Reboots && request.Build("rescue",false).Contains("'boot'"),"Rescue boot request uses the Rescue command group");
        check(ArmHpcCommands.Parse("armhpc reboot").Build("system",true)=="sudo -n -- /usr/bin/systemctl reboot","normal reboot maps to systemd without a missing framework subcommand");
        check(ArmHpcCommands.Parse("armhpc ota status --json").Writes==false,"OTA queries remain read operations");
        check(ArmHpcCommands.Parse("armhpc ota cancel").Arguments.Contains("--yes"),"mutating OTA commands carry confirmation after GUI approval");
        check(!ArmHpcCommands.Parse("armhpc-rescue install --disk /dev/sda").Writes,"SATA install preview does not write disks");
        check(ArmHpcCommands.Parse("armhpc-rescue install --disk /dev/sda --execute").Interactive,"actual factory installation requires an interactive terminal");
        check(ArmHpcCommands.Parse("armhpc-kube configuration").Interactive && !ArmHpcCommands.Parse("armhpc-kube configuration --help").Interactive,"configuration uses TTY while its help remains batch-readable");
        var identify=ArmHpcCommands.Parse("armhpc identify --interface eth0 --seconds 45 --period-ms 1000 --json");
        check(identify.Writes && !identify.Reboots && !identify.Interactive && identify.Build("rescue",true).Contains("armhpc-rescue 'identify'"),"network identification routes through the same normal and Rescue command groups");
        check(ArmHpcCommands.Parse("armhpc identify --status --json").Writes==false && ArmHpcCommands.Parse("armhpc-rescue identify --stop --json").Writes,"identification status is read-only and stopping retains write confirmation");
        foreach(string command in new[]{"armhpc identify --worker private","armhpc identify --seconds 0","armhpc identify --seconds 601","armhpc identify --period-ms 100","armhpc identify --interface ../eth0","armhpc identify --status --stop","armhpc identify --seconds 30 --seconds 40"})
            refused(()=>ArmHpcCommands.Parse(command),"invalid or internal identification options rejected");
        var host=ArmHpcCommands.Parse("armhpc hostname set compute-07 --json");
        check(host.Writes && !host.Interactive && host.Arguments.Contains("--yes") && !host.Reboots,"hostname writes use GUI confirmation and do not reboot");
        check(!ArmHpcCommands.Parse("armhpc hostname --json").Writes && !ArmHpcCommands.Parse("armhpc network show --json").Writes,"hostname and network state remain read-only");
        check(ArmHpcCommands.Parse("armhpc hostname configure").Interactive && ArmHpcCommands.Parse("armhpc network configure").Interactive,"guided configuration requires an interactive terminal");
        var net=ArmHpcCommands.Parse("armhpc network set --interface eth0 --address 192.168.1.20/24 --gateway 192.168.1.1 --dns 1.1.1.1 --dns 8.8.8.8 --json");
        check(net.Writes && net.Arguments.Contains("--yes") && !net.Reboots,"guarded network changes can run through the command panel");
        check(!ArmHpcCommands.Parse("armhpc network set --dhcp --plan --json").Writes,"network plan does not modify files");
        check(ArmHpcCommands.Parse("armhpc network confirm --transaction 00112233-4455-6677-8899-aabbccddeeff --json").Writes,"network confirmation is a write operation");
        foreach(string input in new[]{"armhpc hostname set ../node","armhpc hostname set armbian","armhpc hostname _service", "armhpc network set --dhcp --address 192.168.1.9/24", "armhpc network set", "armhpc network set --dhcp --rollback-after 1", "armhpc network set --dhcp --interface ../eth0", "armhpc network confirm --transaction bad", "armhpc network set --dhcp --rootfs /", "armhpc network _service"})
            refused(()=>ArmHpcCommands.Parse(input),"invalid and private host configuration parameters are rejected");
        refused(()=>host.Build("rescue",false),"custom hostnames remain normal-system-only");
        refused(()=>net.Build("rescue",false),"normal network configuration is not translated to Rescue");
        var quoted=ArmHpcCommands.Parse("armhpc led --error 'literal $(touch /tmp/bad); test'");
        check(quoted.Build("system",false).EndsWith(Commands.Quote("literal $(touch /tmp/bad); test")),"quoted command values are passed as literal arguments");
        foreach(string input in new[]{"rm -rf /","armhpc --help; reboot","armhpc ota _service worker","armhpc ota status --simulate-root /","armhpc ota status --watch","armhpc led --error 'unfinished"})refused(()=>ArmHpcCommands.Parse(input),"unsafe or unsupported command rejected");
        refused(()=>ArmHpcCommands.Parse("armhpc-rescue status").Build("system",false),"Rescue-only command cannot run on normal root");
        refused(()=>ArmHpcCommands.Parse("armhpc-kube check").Build("rescue",false),"K3s commands cannot run in Rescue");
        var queue=new BatchQueue();var order=new List<string>();
        await queue.Run([normal,rescue],2,d=>{order.Add(d.DeviceId);return Task.FromResult(false);},pilot:false,stopOnFailure:false);
        check(order.Count==2 && !queue.Stopped,"read batches continue to collect failures from all selected hosts");
        var serial=new Device{DeviceId="serial-fixture",Address="COM8",Transport="serial"};var wire=new Wire();
        using(var runner=new SerialRunner(_=>wire))
        {
            var status=await runner.Execute(serial,new("root","fixture-password"),"status",[],false,CancellationToken.None);
            check(status.Hostname=="serial-host" && status.Mode=="rescue","serial framed status reads hostname from the console");
            var reply=await runner.ExecuteArmHpc(serial,new("root","fixture-password"),ArmHpcCommands.Parse("armhpc --help"),CancellationToken.None);
            check(reply.Output=="serial ARMHPC help" && reply.ExitCode==0 && reply.Hostname=="serial-host","serial management command returns framed output and exit status");
            wire.Wrong=true;int before=wire.HelpCommands;bool blocked=false;
            try{await runner.ExecuteArmHpc(serial,new("root","fixture-password"),ArmHpcCommands.Parse("armhpc --help"),CancellationToken.None);}catch(InvalidOperationException){blocked=true;}
            check(blocked && wire.HelpCommands==before,"serial identity mismatch blocks management command before execution");
        }
        check(ArmHpcCommands.Presets.All(p=>ArmHpcCommands.Parse(p.Command) is not null),"every built-in ARMHPC preset parses successfully");
    }
    private sealed class Wire:IConsoleWire
    {
        readonly Queue<string> pending=new();public bool Wrong;public int HelpCommands;
        public void Write(string command)
        {
            if(command=="\r" || command=="\u0015\r"){pending.Enqueue("root@serial-host:~# ");return;}
            string nonce=Regex.Match(command,"__ARMHPC_([a-f0-9]{32})__").Groups[1].Value;
            string output;
            if(command.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes(SshRunner.HostnameCommand))))output="serial-host\n";
            else if(command.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes(Commands.Build("status",[],false)))))output=JsonSerializer.Serialize(new{protocol=1,ok=true,data=new{device_id=Wrong?"wrong":"serial-fixture",mode="rescue",agent_version="0.3.1"}});
            else {HelpCommands++;output="serial ARMHPC help";}
            string frame=Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new{rc=0,@out=output,err=""}));pending.Enqueue("\n__ARMHPC_"+nonce+"__:"+frame+":__END__\n");
        }
        public string Read()=>pending.TryDequeue(out var v)?v:"";
        public void Dispose(){}
    }

}
