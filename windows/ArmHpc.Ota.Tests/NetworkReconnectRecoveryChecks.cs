// SPDX-License-Identifier: GPL-3.0-only
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using ArmHpc.Ota.Core;

public static class NetworkReconnectRecoveryChecks
{
    public static async Task Run(Action<bool, string> check)
    {
        const string mac = "02:11:22:33:44:55";
        var system = new Endpoint("192.168.100.18");
        var rescue = new Endpoint("192.168.100.125");
        var device = new Device { DeviceId = "handoff-fixture", Address = system.Address, MacAddress = mac,
            KnownAddresses = [new(rescue.Address, rescue.Port, "rescue")],
            HostKeys = new() { ["system"] = "system-key", ["rescue"] = "rescue-key" } };
        var progress = new List<string>(); bool up = false; int rescueAttempts = 0;
        var found = await NetworkReconnect.Find(device, ["192.168.100.0/24"], (endpoint, discovered, token) =>
        {
            if (endpoint == system) throw new IOException("offline");
            rescueAttempts++;
            if (!up) throw new IOException("not ready before scan");
            SshRunner.ValidateMaintenanceIdentity(NetworkReconnect.DiscoveryIdentity(device),
                JsonSerializer.SerializeToElement(new { device_id = device.DeviceId, mode = "rescue" }), "rescue-key");
            return Task.CompletedTask;
        }, neighbors: _ => Task.FromResult<IReadOnlyList<NetworkNeighbor>>([new(rescue.Address, mac)]),
            scan: (_, _, _) => { up = true; return Task.FromResult<IReadOnlyList<Endpoint>>([rescue]); }, progress: progress.Add);
        check(found == rescue && rescueAttempts == 2, "a known DHCP address which starts SSH during scanning is retried in the same reconnect round");
        check(progress.Any(p => p.Contains("MAC 匹配") && p.Contains(rescue.Address)) && progress.Last().Contains("重连成功"),
              "discovery reports the matched MAC address and verified reconnection");

        int logins = 0; up = false;
        found = await NetworkReconnect.Find(device, ["192.168.100.0/24"], (endpoint, _, _) =>
        { logins++; return endpoint == rescue ? Task.CompletedTask : throw new IOException("offline"); },
            neighbors: _ => Task.FromResult<IReadOnlyList<NetworkNeighbor>>([new(rescue.Address, mac)]),
            scan: (_, _, _) => { up = true; return Task.FromResult<IReadOnlyList<Endpoint>>([rescue]); },
            ready: (endpoint, _) => Task.FromResult(up && endpoint == rescue));
        check(found == rescue && logins == 1, "unready historical IPs receive no SSH authentication attempt before the banner probe succeeds");

        progress.Clear();
        found = await NetworkReconnect.Find(device, ["192.168.100.0/24"], (_, _, _) =>
            throw new Renci.SshNet.Common.SshAuthenticationException("not for diagnostic output"),
            neighbors: _ => Task.FromResult<IReadOnlyList<NetworkNeighbor>>([new(rescue.Address, mac)]),
            scan: (_, _, _) => Task.FromResult<IReadOnlyList<Endpoint>>([]), progress: progress.Add);
        check(found is null && device.LastReconnectDetail.Contains("MAC 匹配 1") && device.LastReconnectDetail.Contains("SSH 登录认证失败"),
              "a found MAC with rejected credentials is distinguished from no discovered address");
        check(!progress.Any(p => p.Contains("not for diagnostic output")), "reconnect diagnostics do not echo arbitrary authentication exception text");

        device.HostKeys.Remove("rescue");
        found = await NetworkReconnect.Find(device, ["192.168.100.0/24"], (endpoint, _, _) =>
        {
            if (endpoint != rescue) throw new IOException("offline");
            SshRunner.ValidateMaintenanceIdentity(NetworkReconnect.DiscoveryIdentity(device),
                JsonSerializer.SerializeToElement(new { device_id = device.DeviceId, mode = "rescue" }), "rescue-key");
            return Task.CompletedTask;
        }, neighbors: _ => Task.FromResult<IReadOnlyList<NetworkNeighbor>>([new(rescue.Address, mac)]),
            scan: (_, _, _) => Task.FromResult<IReadOnlyList<Endpoint>>([]));
        check(found is null && device.LastReconnectDetail.Contains("SSH 指纹未登记或已改变"), "missing Rescue trust is reported while the discovered address remains untrusted");
        device.HostKeys["rescue"] = "rescue-key";

        string before = Guid.NewGuid().ToString(), after = Guid.NewGuid().ToString();
        var request = ArmHpcCommands.Parse("armhpc rescue --reboot");
        var original = new CommandReply(-1, "", "lost reply", "node", "system", device.DeviceId, BootIdBefore: before);
        device.Address = system.Address; up = false;
        var outcome = await RebootVerification.Confirm(device, request, original,
            _ => device.Address == system.Address ? throw new TransientConnectionException("old IP stopped") :
                Task.FromResult(new RebootSnapshot(device.DeviceId, after, "rescue", "rescue-node", device.Address)),
            async token =>
            {
                var target = await NetworkReconnect.Find(device, ["192.168.100.0/24"], (endpoint, _, _) =>
                {
                    if (!up || endpoint != rescue) throw new IOException("not ready");
                    return Task.CompletedTask;
                }, token, neighbors: _ => Task.FromResult<IReadOnlyList<NetworkNeighbor>>([new(rescue.Address, mac)]),
                    scan: (_, _, _) => { up = true; return Task.FromResult<IReadOnlyList<Endpoint>>([rescue]); });
                if (target is not null) device.Address = target.Address;
            }, new(2), delay: _ => Task.CompletedTask);
        check(outcome.RebootConfirmed && outcome.BootIdBefore == before && outcome.BootIdAfter == after && device.Address == rescue.Address,
              "the actual Rescue reboot observer follows static-to-DHCP MAC discovery and confirms the original device's new boot ID");

        device.LastReconnectDetail = "MAC 匹配 1 个地址 · SSH 登录认证失败";
        var unknown = await CommandBatch.Run([device], request, new(), async _ =>
            await RebootVerification.Confirm(device, request, original,
                _ => throw new TransientConnectionException("still offline"), options: new(1), delay: t => Task.Delay(50, t)));
        check(unknown.Unknown == 1 && unknown.Results[0].BootIdBefore == before && unknown.Results[0].Error.Contains("SSH 登录认证失败"),
              "a timeout preserves the pre-reboot boot ID and final reconnect reason in the GUI/CLI command result");
        check(!JsonSerializer.Serialize(device).Contains("LastReconnectDetail"), "temporary reconnect diagnostics are excluded from the persistent inventory");

        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes("SSH"));
            await Task.Delay(40);
            await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes("-2.0-ARMHPC-fixture\r\n"));
            byte[] incoming = new byte[1];
            return await client.GetStream().ReadAsync(incoming);
        });
        bool banner = await Scanner.HasSshBanner(new("127.0.0.1", port));
        int sent = await server;
        check(banner && sent == 0, "the production readiness probe accepts a split SSH banner and sends no credentials or client data");
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); bool stopped = false;
        try { await Scanner.HasSshBanner(new("127.0.0.1", port), cancelled.Token); }
        catch (OperationCanceledException) { stopped = true; }
        check(stopped, "banner probing propagates caller cancellation");
    }
}
