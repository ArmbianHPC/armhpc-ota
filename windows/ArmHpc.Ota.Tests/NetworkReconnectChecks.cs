// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
using ArmHpc.Ota.Core;

public static class NetworkReconnectChecks
{
    public static async Task Run(Action<bool, string> check)
    {
        const string mac = "02:11:22:33:44:55", secondMac = "02:11:22:33:44:66";
        var system = new Endpoint("192.168.100.20", 2222);
        var rescue = new Endpoint("192.168.100.125", 2222);
        var device = new Device { DeviceId = "network-node", Address = system.Address, Port = system.Port,
            HostKeys = new() { ["system"] = "system-key", ["rescue"] = "rescue-key" } };
        var network = new NetworkSnapshot(mac, [new("eth0", mac, [system.Address]), new("eth1", secondMac, ["192.168.200.20"])]);
        NetworkReconnect.Remember(device, system, "system", network);
        NetworkReconnect.Remember(device, rescue, "rescue", new(mac, [new("eth0", mac, [rescue.Address])]));
        check(device.MacAddresses.Contains(mac) && device.MacAddresses.Contains(secondMac), "reconnect remembers every authenticated physical port, including an unused secondary port");
        check(device.KnownAddresses.Any(a => a.Mode == "system" && a.Address == system.Address) &&
              device.KnownAddresses.Any(a => a.Mode == "rescue" && a.Address == rescue.Address), "static System and DHCP Rescue addresses remain separate observations");
        for (int i = 1; i <= 20; i++) NetworkReconnect.Remember(device, new("192.168.100." + i, 2222), "system");
        check(device.KnownAddresses.Count(a => a.Mode == "system") == 4 && device.KnownAddresses.Any(a => a.Mode == "rescue"), "bounded DHCP history cannot evict the other boot environment");
        NetworkReconnect.Remember(device, system, "system", network);
        device.IgnoreFingerprint = true;
        var candidate = NetworkReconnect.DiscoveryIdentity(device);
        check(!candidate.IgnoreFingerprint && candidate.DeviceId == device.DeviceId && candidate.HostKeys.Count == 2,
              "MAC and known-address rediscovery keep both pinned host keys and persistent device ID without inheriting fingerprint bypass");
        check(NetworkReconnect.Contains("192.168.100.20/23", "192.168.101.200") &&
              !NetworkReconnect.Contains("192.168.100.20/23", "192.168.102.1") &&
              NetworkReconnect.Contains("192.168.100.20/32", system.Address) &&
              !NetworkReconnect.Contains("192.168.100.20/32", rescue.Address), "scope matching uses the actual prefix rather than assuming a /24");
        var windows = NetworkReconnect.ParseNeighbors("""
Interface: 192.168.100.1 --- 0x4
  Internet Address      Physical Address      Type
  192.168.100.125       02-11-22-33-44-55     dynamic
  192.168.100.126       ff-ff-ff-ff-ff-ff     static
  999.168.100.2         02-11-22-33-44-55     dynamic
""", true);
        check(windows.Count == 1 && windows[0] == new NetworkNeighbor(rescue.Address, mac), "Windows ARP parsing ignores localized headings and invalid or broadcast entries");
        var linux = NetworkReconnect.ParseNeighbors("""
[{"dst":"192.168.100.125","lladdr":"02:11:22:33:44:55","state":["STALE"]},
 {"dst":"192.168.100.126","lladdr":"02:11:22:33:44:55","state":["FAILED"]},
 {"dst":"192.168.100.127","state":["INCOMPLETE"]},1]
""", false);
        check(linux.SequenceEqual(windows) && NetworkReconnect.ParseNeighbors("invalid", false).Count == 0,
              "Linux neighbor parsing accepts stale hints and rejects failed or incomplete records");

        // Exercise the same candidate selection used by the SSH runner, with identity rejection before success.
        device.KnownAddresses = [];
        var attempted = new List<Endpoint>(); int scans = 0;
        var found = await NetworkReconnect.Find(device, ["192.168.100.0/24"], (endpoint, discovered, token) =>
        {
            attempted.Add(endpoint);
            if (endpoint == system) throw new IOException("offline");
            check(discovered, "a DHCP address is always handled as a discovery candidate");
            var expected = NetworkReconnect.DiscoveryIdentity(device);
            string id = endpoint.Address.EndsWith("124") ? "other-device" : device.DeviceId;
            SshRunner.ValidateMaintenanceIdentity(expected, JsonSerializer.SerializeToElement(new { device_id = id, mode = "rescue" }), "rescue-key");
            return Task.CompletedTask;
        }, neighbors: _ => Task.FromResult<IReadOnlyList<NetworkNeighbor>>([
            new("10.0.0.5", mac), new("192.168.100.124", mac), new(rescue.Address, mac)]),
           scan: (_, _, _) => { scans++; return Task.FromResult<IReadOnlyList<Endpoint>>([]); });
        check(found == rescue && scans == 0 && attempted.Count == 3 && attempted.All(e => e.Port == 2222),
              "matching MAC locates a changed DHCP address, rejects another device sharing that MAC, and retains the custom SSH port");
        check(!attempted.Any(e => e.Address == "10.0.0.5"), "a neighbor with the same MAC outside the approved range is not contacted");

        device.IgnoreFingerprint = false; attempted.Clear(); int neighborReads = 0; var visitedRanges = new List<string>();
        found = await NetworkReconnect.Find(device, [], (endpoint, discovered, token) =>
        {
            attempted.Add(endpoint); if (endpoint != rescue) throw new IOException("offline");
            return Task.CompletedTask;
        }, neighbors: _ => Task.FromResult<IReadOnlyList<NetworkNeighbor>>(++neighborReads == 1 ? [] : [new(rescue.Address, mac)]),
           scan: (range, port, token) => { visitedRanges.Add(range); return Task.FromResult<IReadOnlyList<Endpoint>>([new("192.168.100.99", port), rescue]); },
           localRanges: () => ["192.168.100.0/24"]);
        check(found == rescue && visitedRanges.SequenceEqual(new[] { "192.168.100.0/24" }) && !attempted.Any(e => e.Address.EndsWith("99")),
              "local rediscovery refreshes ARP through credential-free scanning and tries the matching MAC before unrelated SSH hosts");

        NetworkReconnect.Remember(device, system, "system"); device.Address = rescue.Address;
        found = await NetworkReconnect.Find(device, [], (endpoint, discovered, token) =>
        {
            if (endpoint == rescue) throw new IOException("Rescue stopped");
            return endpoint == system ? Task.CompletedTask : throw new IOException("offline");
        }, neighbors: _ => throw new Exception("known static address should be tried first"),
           scan: (_, _, _) => throw new Exception("known static address needs no scan"));
        check(found == system, "returning from DHCP Rescue reconnects to the remembered static System address without scanning");

        var legacy = new Device { DeviceId = device.DeviceId, Address = system.Address, Port = 2222 };
        scans = 0;
        found = await NetworkReconnect.Find(legacy, [], (_, _, _) => throw new IOException("offline"),
            neighbors: _ => throw new Exception("old inventory has no known MAC"),
            scan: (_, _, _) => { scans++; return Task.FromResult<IReadOnlyList<Endpoint>>([]); });
        check(found is null && scans == 0, "legacy inventory without an authenticated MAC never triggers an automatic LAN scan");
        found = await NetworkReconnect.Find(legacy, ["192.168.100.0/24"], (endpoint, _, _) =>
            endpoint == rescue ? Task.CompletedTask : throw new IOException("offline"),
            scan: (_, _, _) => Task.FromResult<IReadOnlyList<Endpoint>>([rescue]));
        check(found == rescue, "explicit ranges remain usable with old agents and inventory lacking MAC metadata");
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); bool propagated = false;
        try { await NetworkReconnect.Find(device, [], (_, _, _) => Task.CompletedTask, cancelled.Token); }
        catch (OperationCanceledException) { propagated = true; }
        check(propagated, "reconnection cancellation cannot be swallowed as an offline result");
        string folder = Path.Combine(Path.GetTempPath(), "armhpc-network-" + Guid.NewGuid().ToString("N"));
        try
        {
            var vault = new Vault(folder); vault.SaveDevices([device]); var saved = vault.LoadDevices().Single();
            check(saved.KnownAddresses.SequenceEqual(device.KnownAddresses) && saved.MacAddresses.SequenceEqual(device.MacAddresses),
                  "both environment addresses and MACs survive a controller restart");
        }
        finally { Directory.Delete(folder, true); }

        int movedQueries = 0, resumed = 0, submissions = 0;
        var job = new PendingTask(device.DeviceId, Guid.NewGuid().ToString("D"), "same-release", "system");
        bool completed = await JobMonitor.Run(job,
            () => NetworkReconnect.ReadBound(() =>
            {
                if (++movedQueries == 1) throw new DeviceIdentityMismatchException("old DHCP lease now belongs to a peer");
                return Task.FromResult(JsonSerializer.SerializeToElement(new { device_id = device.DeviceId,
                    job = new { job_id = job.JobId, stage = "succeeded" } }));
            }),
            () => { submissions++; throw new Exception("must not submit again"); },
            () => { resumed++; return Task.CompletedTask; }, (_, _) => { }, delay: _ => Task.CompletedTask);
        check(completed && resumed == 1 && submissions == 0 && movedQueries == 2,
              "a reused DHCP address causes rediscovery of the original job without another write submission");
        bool writesRefused = false;
        try { SshRunner.ValidateMaintenanceIdentity(device,
            JsonSerializer.SerializeToElement(new { device_id = "different", mode = "system" }), "system-key"); }
        catch (DeviceIdentityMismatchException) { writesRefused = true; }
        check(writesRefused, "write preflight still rejects another persistent device before submitting a command");

        var actual = await NetworkReconnect.Neighbors(CancellationToken.None);
        check(actual.All(n => NetworkReconnect.UsableAddress(n.Address) && NetworkMetadata.ValidMac(n.MacAddress)),
              "the current host neighbor reader completes without changing adapters or ARP entries");
    }
}
