// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using ArmHpc.Ota.Core;

public static class DeviceDiscoveryChecks
{
    private static byte[] Reply(IPAddress address, ushort id, string hostname, uint ttl=120)
    {
        byte[] question=HostDiscovery.CreateQuery(address,id);
        question[2]=0x84;question[3]=0;question[6]=0;question[7]=1;
        using var data=new MemoryStream();
        foreach(string label in hostname.Split('.')){var bytes=Encoding.UTF8.GetBytes(label);data.WriteByte((byte)bytes.Length);data.Write(bytes);}data.WriteByte(0);
        using var stream=new MemoryStream();stream.Write(question);stream.Write([0xc0,0x0c,0,12,0,1]);
        byte[] time=new byte[4];BinaryPrimitives.WriteUInt32BigEndian(time,ttl);stream.Write(time);
        byte[] length=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(length,(ushort)data.Length);stream.Write(length);stream.Write(data.ToArray());return stream.ToArray();
    }

    public static async Task Run(Action<bool,string> check)
    {
        var ip=IPAddress.Parse("192.168.100.20");const ushort id=5412;
        check(HostDiscovery.ReverseName(ip)=="20.100.168.192.in-addr.arpa","mDNS query binds the exact target IPv4 reverse name");
        check(HostDiscovery.CleanName("node-07.local.")=="node-07.local","DNS discovery normalizes a trailing root dot");
        check(HostDiscovery.CleanName("192.168.100.20")=="" && HostDiscovery.CleanName("bad\nname.local")=="" && HostDiscovery.CleanName("node name.local")=="","discovery never presents an IP or control text as a hostname");
        byte[] response=Reply(ip,id,"armhpc-node07.local");
        check(HostDiscovery.ParseResponse(response,ip,id)=="armhpc-node07.local","mDNS PTR response accepts a compressed owner bound to its target");
        check(HostDiscovery.ParseResponse(response,IPAddress.Parse("192.168.100.21"),id)=="","mDNS rejects a PTR for another scanned address");
        check(HostDiscovery.ParseResponse(response,ip,1)=="","mDNS correlates legacy-unicast transaction IDs");
        check(HostDiscovery.ParseResponse(Reply(ip,id,"armhpc-node07.local",0),ip,id)=="","mDNS goodbye records cannot become a discovered name");
        check(HostDiscovery.ParseResponse(Reply(ip,id,"outside.example.com"),ip,id)=="","mDNS reverse discovery requires a local namespace name");
        byte[] loop=Reply(ip,id,"x.local");int payload=HostDiscovery.CreateQuery(ip,id).Length+12;loop[payload]=0xc0;loop[payload+1]=(byte)payload;
        check(HostDiscovery.ParseResponse(loop,ip,id)=="","cyclic DNS compression pointers are refused");
        check(HostDiscovery.ParseResponse(response[..^3],ip,id)=="","truncated DNS RDATA is refused");
        var snapshot=NetworkMetadata.Parse("""
{"local_address":"192.168.100.20","interfaces":[{"interface":"lo","mac_address":"00:00:00:00:00:00","addresses":["127.0.0.1"]},{"interface":"eth0","mac_address":"02:00:00:00:00:01","addresses":["192.168.200.20"]},{"interface":"eth1","mac_address":"02:00:00:00:00:02","addresses":["192.168.100.20"]}]}
""");
        check(snapshot?.MacAddress=="02:00:00:00:00:02" && snapshot.Interfaces.Count==2,"MAC display selects the actual SSH-connected physical interface");
        check(snapshot!.Detail.Contains("eth0") && snapshot.Detail.Contains("eth1"),"multi-interface MACs remain available in row details");
        var merged=snapshot.Merge(JsonSerializer.SerializeToElement(new{agent_version="1.0.1",device_id="original",clock=new{quality="estimated"}}),"node-07");
        check(Protocol.Text(merged,"device_id")=="original" && merged.GetProperty("clock").GetProperty("quality").GetString()=="estimated" && Protocol.Text(merged,"mac_address")==snapshot.MacAddress,"controller network metadata extends status without replacing existing protocol fields");
        check(!NetworkMetadata.ValidMac("ff:ff:ff:ff:ff:ff") && !NetworkMetadata.ValidMac("00:00:00:00:00:00") && !NetworkMetadata.ValidMac("../../address"),"invalid or multicast MAC values are refused");
        check(NetworkMetadata.Parse("not JSON")==null && NetworkMetadata.Parse("{\"interfaces\":[]}")==null,"legacy or unavailable network metadata remains optional");
        var inventory=new List<Device>();var endpoint=new Endpoint("192.168.100.20");
        var candidate=DeviceInventory.ApplyDiscovery(inventory,new(endpoint,"node-07.local","mDNS"));
        check(inventory.Count==1 && candidate.Hostname=="node-07.local" && !candidate.Managed && candidate.DeviceId.Length==0,"DNS names are shown during scanning without authenticating or assigning a device identity");
        DeviceInventory.ApplyDiscovery(inventory,new(endpoint,"new-name.local","DNS"));
        check(inventory.Count==1 && candidate.Hostname=="new-name.local","rescan updates the existing candidate instead of duplicating its address");
        candidate.DeviceId="trusted-device";candidate.Hostname="verified-name";candidate.HostnameSource="SSH";candidate.MacAddress=snapshot.MacAddress;
        DeviceInventory.ApplyDiscovery(inventory,new(endpoint,"unverified-name.local","mDNS"));
        check(candidate.Hostname=="verified-name" && candidate.HostnameSource=="SSH","unauthenticated discovery cannot overwrite a verified managed hostname");
        check(DeviceSelection.Matches(candidate,"00:00:00:02"),"inventory filtering includes MAC addresses");
        bool busy=false;try{DeviceInventory.Remove(inventory,[candidate],true);}catch(InvalidOperationException){busy=true;}
        check(busy && inventory.Count==1,"host removal is refused while a local operation is active");
        var task=new PendingTask(candidate.DeviceId,Guid.NewGuid().ToString("D"),"release-original","all");
        var removed=DeviceInventory.Remove(inventory,[candidate,candidate]);
        check(removed.Count==1 && inventory.Count==0 && task.DeviceId=="trusted-device","host deletion deduplicates rows and leaves the original persistent task binding intact");
        check(ArmHpcCommands.DevelopmentPresets.All(p=>p.Development) && ArmHpcCommands.ManagementPresets.All(p=>!p.Development),"development commands are grouped separately from daily device management");
        check(!ArmHpcCommands.ManagementPresets.Any(p=>p.Command.StartsWith("armhpc watchdog") || p.Command.StartsWith("armhpc ota boot ")),"watchdog and BOOT commands stay out of the daily command picker");
        string directory=Path.Combine(Path.GetTempPath(),"armhpc-inventory-"+Guid.NewGuid().ToString("N"));
        try
        {
            var vault=new Vault(directory);vault.SaveDevices([candidate]);vault.SaveTasks([task]);vault.SaveConnection(candidate,new("user","fixture-value"));
            var restored=vault.LoadDevices().Single();check(restored.MacAddress==candidate.MacAddress && restored.HostnameSource=="SSH","MAC and hostname provenance persist across controller restarts");
            vault.ForgetConnection(candidate,true);vault.SaveDevices([]);
            check(vault.LoadDevices().Count==0 && vault.LoadConnection(candidate)==null && vault.LoadTasks().Single().JobId==task.JobId,"removing a local connection clears its credentials and preserves upgrade task history");
        }
        finally { Directory.Delete(directory,true); }
        using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));int received=-1,queries=0;var events=new List<DiscoveredHost>();
        var server=Task.Run(async()=>
        {
            using var client=await listener.AcceptTcpClientAsync(timeout.Token);var wire=client.GetStream();
            await wire.WriteAsync("SSH-2.0-ARMHPC-fixture\r\n"u8.ToArray(),timeout.Token);byte[] bytes=new byte[128];received=await wire.ReadAsync(bytes,timeout.Token);
        });
        var found=await Scanner.ScanWithNames("127.0.0.1/32",port,discovered:h=>events.Add(h),cancellation:timeout.Token,
            resolver:(address,token)=>{queries++;return Task.FromResult<DiscoveryName?>(new("fixture-host.local","mDNS"));});
        await server;
        check(found.Single().Hostname=="fixture-host.local" && queries==1 && received==0,"actual SSH candidate scanning sends no credentials or SSH authentication payload while resolving names");
        check(events.Count==2 && events[0].Hostname=="" && events[1].Hostname=="fixture-host.local","scan presents a candidate before its DNS/mDNS lookup completes");
    }
}
