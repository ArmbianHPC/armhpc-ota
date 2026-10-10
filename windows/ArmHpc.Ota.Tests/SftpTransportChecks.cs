// SPDX-License-Identifier: GPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;
using Renci.SshNet;
using ArmHpc.Ota.Core;

public static class SftpTransportChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        string? fixture=Environment.GetEnvironmentVariable("ARMHPC_SFTP_FIXTURE");if(fixture is null)return;
        using var document=JsonDocument.Parse(File.ReadAllText(fixture));var cfg=document.RootElement;
        using var client=new SftpClient(cfg.GetProperty("host").GetString()!,cfg.GetProperty("port").GetInt32(),cfg.GetProperty("username").GetString()!,cfg.GetProperty("password").GetString()!);
        client.HostKeyReceived+=(_,e)=>e.CanTrust="SHA256:"+Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=')==cfg.GetProperty("fingerprint").GetString();
        client.OperationTimeout=TimeSpan.FromSeconds(10);client.Connect();
        string directory=Path.Combine(Path.GetTempPath(),"armhpc-sftp-test-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
        try
        {
            string file=Path.Combine(directory,"payload.bin");byte[] data=RandomNumberGenerator.GetBytes(65536);File.WriteAllBytes(file,data);
            string target="/fixture/upload-"+Guid.NewGuid().ToString("N");string uploaded=SshRunner.UploadVerifiedFile(client,file,target);
            check(uploaded==target+"/payload.bin","production SFTP upload succeeds over a real pinned SSH connection");
            using var stream=client.OpenRead(uploaded);check(SHA256.HashData(stream).SequenceEqual(SHA256.HashData(data)),"real SFTP downloaded bytes match uploaded SHA256");
            var folder=client.GetAttributes(target);var attributes=client.GetAttributes(uploaded);
            check(folder.OwnerCanExecute && !folder.GroupCanRead && !folder.OthersCanRead && !attributes.OwnerCanExecute && !attributes.GroupCanRead && !attributes.OthersCanRead,"real SFTP wire retains directory 0700 and file 0600");
            string resumed=target+"/resumed.part";const int prefix=17000;
            using(var part=new MemoryStream(data[..prefix]))client.UploadFile(part,resumed);
            SshRunner.UploadResumablePart(client,file,resumed,prefix,data.Length,_=>{});
            using(var complete=client.OpenRead(resumed))check(SHA256.HashData(complete).SequenceEqual(SHA256.HashData(data)),"production SFTP resume appends from verified offset and retains exact SHA256");
            bool wrongOffset=false;try{SshRunner.UploadResumablePart(client,file,resumed,0,data.Length,_=>{});}catch(InvalidOperationException){wrongOffset=true;}
            check(wrongOffset,"production resume refuses an unexpected remote length");
            using var cancellation=new CancellationTokenSource();cancellation.Cancel();bool cancelled=false;
            try{SshRunner.UploadResumablePart(client,file,target+"/cancelled.part",0,data.Length,_=>{},cancellation.Token);}catch(OperationCanceledException){cancelled=true;}
            check(cancelled && !client.Exists(target+"/cancelled.part"),"cancelled SFTP transfer creates no new remote payload");
        }
        finally{Directory.Delete(directory,true);}
        var device=new Device{DeviceId="fixture-device",Address="127.0.0.2",Port=cfg.GetProperty("port").GetInt32()};
        device.HostKeys["rescue"]=cfg.GetProperty("fingerprint").GetString()!;
        var credentials=new Credentials(cfg.GetProperty("username").GetString()!,cfg.GetProperty("password").GetString()!);
        using var router=new ConnectionRouter();
        var found=await router.Reconnect(device,credentials,["127.0.0.1/32"]);
        check(found?.Address=="127.0.0.1" && device.Address=="127.0.0.1","real SSH rediscovery records the trusted new IP for subsequent commands");
        var status=await router.Execute(new(device.Address,device.Port),credentials,device,"status",[]);
        check(Protocol.Text(status.Data,"device_id")==device.DeviceId,"subsequent CLI status reaches the rediscovered endpoint");
        check(status.Hostname=="fixture-host","real SSH status reads hostname independently of the installed agent");
        var reply=await router.ExecuteArmHpc(new(device.Address,device.Port),credentials,device,ArmHpcCommands.Parse("armhpc --help"));
        check(reply.ExitCode==0 && reply.Output.Contains("ARMHPC fixture help") && reply.Hostname=="fixture-host","raw ARMHPC command uses validated identity and returns stdout/exit status");
        using(var terminal=await router.OpenTerminal(new(device.Address,device.Port),credentials,device))
        {
            terminal.Send("fixture-command\r");string text="";
            for(int i=0;i<50 && !text.Contains("fixture echo");i++){await Task.Delay(20);text+=terminal.Read();}
            check(terminal.Mode=="rescue" && terminal.Hostname=="fixture-host" && text.Contains("fixture-command"),"interactive SSH terminal pins identity and exchanges shell input without launching a real command");
        }
        var uncertain=await CommandBatch.Run([device],ArmHpcCommands.Parse("armhpc led --heartbeat on"),new(1,true),d=>router.ExecuteArmHpc(new(d.Address,d.Port),credentials,d,ArmHpcCommands.Parse("armhpc led --heartbeat on")));
        check(uncertain.Unknown==1 && uncertain.Succeeded==0 && uncertain.Results[0].UnknownIgnored,"real SSH disconnect after command submission is preserved as unknown");
        string profile=Path.Combine(Path.GetTempPath(),"armhpc-cli-test-"+Guid.NewGuid().ToString("N"));
        try
        {
            var vault=new Vault(profile);vault.SaveDevices([device]);vault.SaveConnection(device,credentials);
            var stdout=Console.Out;
            async Task<(int Code,JsonElement Data)> Cli(string command,bool ignore)
            {
                using var buffer=new StringWriter();Console.SetOut(buffer);
                try
                {
                    var options=new List<string>{"--all-managed","--command",command,"--concurrency","8","--yes","--json"};if(ignore)options.Add("--ignore-unknown");
                    int code=await ArmHpc.Ota.Cli.CommandCli.Run(options.ToArray(),vault);
                    return(code,Protocol.Decode(buffer.ToString()));
                }finally{Console.SetOut(stdout);}
            }
            var accepted=await Cli("armhpc --help",false);
            check(accepted.Code==0 && accepted.Data.GetProperty("concurrency").GetInt32()==8 && accepted.Data.GetProperty("succeeded").GetInt32()==1,"actual CLI parser executes pinned inventory command with concurrency eight");
            var ignored=await Cli("armhpc led --heartbeat on",true);
            check(ignored.Code==0 && ignored.Data.GetProperty("unknown").GetInt32()==1 && ignored.Data.GetProperty("succeeded").GetInt32()==0,"CLI ignore-unknown option continues policy without claiming command success");
            var paused=await Cli("armhpc led --heartbeat on",false);
            check(paused.Code==3 && paused.Data.GetProperty("unknown").GetInt32()==1,"CLI default reports unknown submission with a distinct exit code");
        }finally{Directory.Delete(profile,true);}
        var reboot=await router.ExecuteArmHpc(new(device.Address,device.Port),credentials,device,ArmHpcCommands.Parse("armhpc rescue --reboot"),reboot:new(5));
        check(reboot.RebootConfirmed && reboot.BootIdBefore!=reboot.BootIdAfter && reboot.Mode=="rescue","real SSH lost reboot reply is confirmed by authenticated post-boot observation");
        var bypass=new Device{DeviceId=device.DeviceId,Address=device.Address,Port=device.Port,IgnoreFingerprint=true};
        var bypassReply=await router.ExecuteArmHpc(new(bypass.Address,bypass.Port),credentials,bypass,ArmHpcCommands.Parse("armhpc --help"));
        check(bypassReply.ExitCode==0,"real SSH explicit bypass reaches unpinned fixture endpoint");
        bypass.DeviceId="wrong";bool blockedBypass=false;
        try{await router.ExecuteArmHpc(new(bypass.Address,bypass.Port),credentials,bypass,ArmHpcCommands.Parse("armhpc --help"));}catch(InvalidOperationException){blockedBypass=true;}
        check(blockedBypass,"real SSH bypass still blocks mismatched device identity");
        var wrong=new Device{DeviceId="another-device",Address="127.0.0.2",Port=device.Port};wrong.HostKeys["rescue"]=device.HostKeys["rescue"];
        check(await router.Reconnect(wrong,credentials,["127.0.0.1/32"]) is null && wrong.Address=="127.0.0.2","rediscovery refuses a mismatched persistent identity and retains the approved address");
    }
}
