// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
public static class ManagementChecks
{
    public static async Task Run(Action<bool,string> check,Action<Action,string> refused)
    {
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
