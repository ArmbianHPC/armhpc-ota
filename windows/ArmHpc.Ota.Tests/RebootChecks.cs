// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
using System.Text.Json;
public static class RebootChecks
{
    public static async Task Run(Action<bool,string> check,Action<Action,string> refused)
    {
        var device=new Device{DeviceId="reboot-fixture",Address="192.168.1.10"};
        string before=Guid.NewGuid().ToString(),after=Guid.NewGuid().ToString();
        var request=ArmHpcCommands.Parse("armhpc rescue --reboot");
        var original=new CommandReply(-1,"","lost reply","host","system",device.DeviceId,BootIdBefore:before);
        RebootSnapshot Snapshot(string boot,string mode="rescue",string? id=null)=>new(id??device.DeviceId,boot,mode,"host",device.Address);
        var result=await RebootVerification.Confirm(device,request,original,_=>Task.FromResult(Snapshot(after)),options:new(1),delay:_=>Task.CompletedTask);
        check(result.RebootConfirmed && result.BootIdBefore==before && result.BootIdAfter==after && result.Mode=="rescue","lost reboot acknowledgement is confirmed by new boot ID and Rescue environment");
        int probes=0;result=await RebootVerification.Confirm(device,request,original with {ExitCode=0},_=>Task.FromResult(Snapshot(++probes==1?before:after)),options:new(1),delay:_=>Task.CompletedTask);
        check(probes==2 && result.RebootConfirmed,"zero exit still waits for observed reboot rather than declaring immediate success");
        bool noReboot=false;
        try{await RebootVerification.Confirm(device,request,original,_=>Task.FromResult(Snapshot(before)),options:new(1),delay:t=>Task.Delay(50,t));}catch(CommandResultUnknownException){noReboot=true;}
        check(noReboot,"reachable host with unchanged boot ID remains unknown");
        bool wrongMode=false;
        try{await RebootVerification.Confirm(device,request,original,_=>Task.FromResult(Snapshot(after,"system")),options:new(1),delay:t=>Task.Delay(50,t));}catch(InvalidOperationException){wrongMode=true;}
        check(wrongMode,"new boot ID in the wrong environment cannot confirm Rescue command");
        bool wrongId=false;
        try{await RebootVerification.Confirm(device,request,original,_=>Task.FromResult(Snapshot(after,id:"different")),options:new(1));}catch(InvalidOperationException){wrongId=true;}
        check(wrongId,"reboot confirmation refuses a different device");
        int discovery=0;probes=0;
        result=await RebootVerification.Confirm(device,request,original,_=>++probes==1?throw new TransientConnectionException("offline"):Task.FromResult(Snapshot(after)),_=>{discovery++;return Task.CompletedTask;},new(1),delay:_=>Task.CompletedTask);
        check(discovery==1 && result.RebootConfirmed,"reboot observer waits through transport loss and trusted rediscovery");
        probes=0;result=await RebootVerification.Confirm(device,request,original with {ExitCode=7},_=>{probes++;return Task.FromResult(Snapshot(after));});
        check(result.ExitCode==7 && probes==0 && !result.RebootConfirmed,"known command failure is never overwritten by reboot verification");
        var report=await CommandBatch.Run([device],request,new(),_=>Task.FromResult(original with {RebootConfirmed=true,BootIdAfter=after}));
        check(report.Succeeded==1 && report.Unknown==0 && report.Results[0].ExitCode is null && report.Results[0].Confirmation=="reboot_verified","batch records effect confirmation without inventing a lost exit code");
        check(request.VerifyReboot && request.ExpectedRebootMode=="rescue" && !ArmHpcCommands.Parse("armhpc rescue --reboot --help").VerifyReboot,"only actual reboot actions invoke observer");
        device.IgnoreFingerprint=true;var identity=JsonSerializer.SerializeToElement(new{device_id=device.DeviceId,mode="rescue"});
        SshRunner.ValidateMaintenanceIdentity(device,identity,"unregistered-fingerprint");check(true,"explicit fingerprint bypass allows unpinned key while checking identity");
        refused(()=>SshRunner.ValidateMaintenanceIdentity(device,JsonSerializer.SerializeToElement(new{device_id="different",mode="rescue"}),"key"),"fingerprint bypass never bypasses persistent device ID");
        check(!JsonSerializer.Serialize(device).Contains("IgnoreFingerprint"),"fingerprint bypass is temporary and absent from stored inventory");
    }
}
