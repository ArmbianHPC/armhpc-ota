// SPDX-License-Identifier: GPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;
using Renci.SshNet;
using Renci.SshNet.Common;
using System.Net.Sockets;

namespace ArmHpc.Ota.Core;

public sealed partial class SshRunner
{
    public async Task<RemoteResult> Execute(Endpoint endpoint, Credentials credentials, Device? expected, string operation,
        IReadOnlyList<string> arguments, bool yes = false, Func<string, string, bool>? approveHostKey = null,
        CancellationToken cancellation = default)
    {
        try { return await Task.Run(() =>
        {
            using var login = ConnectLogin(endpoint, credentials, expected, info => new SshClient(info), cancellation, approveHostKey);
            var client = login.Client;
            var actualCredentials = login.Credentials;
            string fingerprint = login.Fingerprint;
            using var registration = cancellation.Register(() => client.Dispose());
            // Identity is checked before any mutating CLI command, even at a previously known IP.
            JsonElement status = Command(client, actualCredentials, "status", []);
            string id = Protocol.Text(status, "device_id"), mode = Protocol.Text(status, "mode");
            if (id.Length == 0 || mode is not ("system" or "rescue")) throw new InvalidOperationException("SSH 候选不是可管理的 ARMHPC OTA 设备。");
            if (expected?.Managed == true && expected.DeviceId != id) throw new DeviceIdentityMismatchException("设备 ID 不匹配，拒绝在此 IP 执行操作。");
            if (expected?.IgnoreFingerprint!=true && expected?.HostKeys.TryGetValue(mode, out string? pin) == true && pin != fingerprint)
                throw new SshHostIdentityException("当前环境的 SSH 主机密钥已改变。请单独核查后重新登记。");
            login.Verified(status);
            string hostname=Hostname(client);
            var network = operation == "status" ? NetworkMetadata.Read(client) : null;
            if (expected is not null) NetworkReconnect.Remember(expected, endpoint, mode, network);
            cancellation.ThrowIfCancellationRequested();
            JsonElement data = operation == "status" && arguments.Count == 0 ? (network?.Merge(status,hostname)??status) : Command(client, actualCredentials, operation, arguments, yes);
            return new RemoteResult(data, fingerprint, mode, hostname, network);
        }, cancellation); }
        catch (Exception) when (cancellation.IsCancellationRequested) { throw new OperationCanceledException(cancellation); }
        catch (Exception error) when (error is SshConnectionException or SshOperationTimeoutException or SocketException)
        { throw new TransientConnectionException("SSH 连接中断；设备任务仍需通过持久 ID 查询。", error); }
    }

    private static TimeSpan DefaultCommandTimeout(string operation,IReadOnlyList<string> arguments)
        =>TimeSpan.FromMinutes(operation is "download" or "apply" or "bootstrap" or "recover" or "tools" ||
            operation=="storage" || operation=="boot" && arguments.FirstOrDefault() is "plan" or "apply" or "rollback" or "restore" ? 60 : 3);

    private static JsonElement Command(SshClient client, Credentials credentials, string operation, IReadOnlyList<string> arguments, bool yes = false, TimeSpan? timeout=null)
    {
        using var command = client.CreateCommand(Commands.Build(operation, arguments, credentials.Username != "root", yes));
        command.CommandTimeout = timeout??DefaultCommandTimeout(operation,arguments);
        string stdout = command.Execute();
        if (string.IsNullOrWhiteSpace(stdout)) throw new InvalidOperationException("设备没有返回 CLI JSON；请先安装 OTA runtime，并检查管理员的 sudo 权限。");
        return Protocol.Decode(stdout);
    }

    public Task<Endpoint?> Reconnect(Device device, Credentials credentials, IReadOnlyList<string> ranges, CancellationToken cancellation = default, bool maintenance = false, Action<string>? progress = null)
        => NetworkReconnect.Find(device, ranges, async (endpoint, discovered, token) =>
        {
            var expected = discovered ? NetworkReconnect.DiscoveryIdentity(device) : device;
            if (maintenance)
            {
                var status = await MaintenanceStatus(endpoint, credentials, expected, token);
                NetworkReconnect.Remember(device, endpoint, Protocol.Text(status, "mode"));
            }
            else
            {
                var status = await Execute(endpoint, credentials, expected, "status", [], cancellation: token);
                if (discovered) ValidateMaintenanceIdentity(expected,status.Data,status.Fingerprint);
                NetworkReconnect.Remember(device, endpoint, status.Mode, status.Network);
            }
        }, cancellation, progress: progress, ready: Scanner.HasSshBanner);
}
