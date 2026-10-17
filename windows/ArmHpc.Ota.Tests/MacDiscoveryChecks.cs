// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
using ArmHpc.Ota.Core;

public static class MacDiscoveryChecks
{
    public static async Task Run(Action<bool, string> check)
    {
        const string mac = "02:11:22:33:44:55", secondMac = "02:11:22:33:44:66";
        var device = new Device { DeviceId = "manual-mac-fixture", Address = "192.168.100.18", MacAddress = mac,
            HostKeys = new() { ["system"] = "system-key" }, IgnoreFingerprint = true };
        var second = new Device { DeviceId = "second-fixture", Address = "192.168.100.19", MacAddress = secondMac };
        var ready = new Endpoint("192.168.100.125"); bool scanned = false; int scans = 0;
        var logs = new List<string>();
        var report = await MacDiscovery.Scan([device, second], ["192.168.100.0/24"], progress: logs.Add,
            scan: (_, _, _) => { scanned = true; scans++; return Task.FromResult<IReadOnlyList<Endpoint>>([ready]); },
            neighbors: _ =>
            {
                if (!scanned) throw new InvalidOperationException("neighbor lookup must follow the active scan");
                return Task.FromResult<IReadOnlyList<NetworkNeighbor>>([
                    new(device.Address, mac), new(ready.Address, mac.ToUpperInvariant()), new("192.168.100.126", secondMac),
                    new("192.168.200.10", mac), new("192.168.100.100", "02:99:99:99:99:99")]);
            });
        check(scans == 1 && report.Devices.Count == 2, "manual MAC discovery scans once per subnet and port for all selected devices");
        var candidates = report.Devices.Single(d => d.DeviceId == device.DeviceId).Candidates;
        check(candidates.Count == 2 && candidates[0].Address == ready.Address && candidates[0].SshReady && !candidates[1].SshReady,
            "active scan prioritizes the new SSH-ready IP while distinguishing cached unready addresses");
        check(report.Devices[1].Candidates.Single().MacAddress == secondMac && candidates.All(c => c.Address != "192.168.200.10"),
            "matching honors device MAC ownership and the explicit scan range");
        check(device.Address == "192.168.100.18" && device.HostKeys.Count == 1 && logs.Any(l => l.Contains(ready.Address)),
            "discovery displays candidates without mutating an address or trusting an SSH key");

        static RemoteResult Reply(string id, string key = "rescue-key") => new(
            JsonSerializer.SerializeToElement(new { agent_version = "1.2.3", device_id = id }), key, "rescue");
        var selected = candidates[0]; bool refused = false;
        try { MacDiscovery.Accept(device, selected, Reply("wrong-device"), true); } catch (DeviceIdentityMismatchException) { refused = true; }
        check(refused && device.Address == "192.168.100.18" && !device.HostKeys.ContainsKey("rescue"),
            "a duplicate MAC cannot replace the original persistent device identity");
        refused = false;
        try { MacDiscovery.Accept(device, selected, Reply(device.DeviceId)); } catch (SshHostIdentityException) { refused = true; }
        check(refused && device.Address == "192.168.100.18", "a missing environment key still requires explicit approval despite a selected-address bypass");
        MacDiscovery.Accept(device, selected, Reply(device.DeviceId), true);
        check(device.Address == ready.Address && device.DeviceId == "manual-mac-fixture" && device.HostKeys["rescue"] == "rescue-key" &&
              device.KnownAddresses.Any(a => a.Address == ready.Address && a.Mode == "rescue"),
            "manual approval and verified identity adopt the new address and retain environment history");
        refused = false;
        try { MacDiscovery.Accept(device, selected with { Address = "192.168.100.127" }, Reply(device.DeviceId, "changed-key"), true); }
        catch (SshHostIdentityException) { refused = true; }
        check(refused && device.Address == ready.Address && device.HostKeys["rescue"] == "rescue-key", "manual approval cannot silently replace an existing environment pin");
        refused = false;
        try { MacDiscovery.Accept(device, selected with { SshReady = false }, Reply(device.DeviceId)); } catch (ArgumentException) { refused = true; }
        check(refused, "a cached neighbor without SSH readiness cannot be adopted");

        var local = await MacDiscovery.Scan([device], [], localRanges: () => ["192.168.100.0/24"],
            scan: (_, _, _) => Task.FromResult<IReadOnlyList<Endpoint>>([]),
            neighbors: _ => Task.FromResult<IReadOnlyList<NetworkNeighbor>>([]));
        check(local.Ranges.Single() == "192.168.100.0/24" && local.Devices.Single().Candidates.Count == 0,
            "blank manual scope uses bounded local ranges and reports an empty result");
        refused = false;
        try { await MacDiscovery.Scan([new Device { DeviceId = "no-mac", Address = device.Address }], ["192.168.100.0/24"]); }
        catch (ArgumentException) { refused = true; }
        check(refused, "missing authenticated MAC data is refused before any scan");
        refused = false;
        try { await MacDiscovery.Scan([device], [], localRanges: () => []); } catch (ArgumentException) { refused = true; }
        check(refused, "missing local scope requests an explicit subnet");
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); bool stopped = false;
        try { await MacDiscovery.Scan([device], ["192.168.100.0/24"], cancelled.Token); } catch (OperationCanceledException) { stopped = true; }
        check(stopped, "stopping manual scanning cancels before network activity");
    }
}
