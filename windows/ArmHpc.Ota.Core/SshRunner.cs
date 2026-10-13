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
            AuthenticationMethod auth = credentials.PrivateKeyPath is { Length: > 0 }
                ? new PrivateKeyAuthenticationMethod(credentials.Username, new PrivateKeyFile(credentials.PrivateKeyPath, credentials.Passphrase))
                : new PasswordAuthenticationMethod(credentials.Username, credentials.Password);
            var info = new ConnectionInfo(endpoint.Address, endpoint.Port, credentials.Username, auth) { Timeout = TimeSpan.FromSeconds(8) };
            using var client = new SshClient(info);
            using var registration = cancellation.Register(() => client.Dispose());
            string fingerprint = "";
            client.HostKeyReceived += (_, args) =>
            {
                fingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(args.HostKey)).TrimEnd('=');
                args.CanTrust = expected?.IgnoreFingerprint==true || expected?.HostKeys.Values.Contains(fingerprint, StringComparer.Ordinal) == true ||
                                (approveHostKey?.Invoke(endpoint.Address, fingerprint) ?? false);
            };
            cancellation.ThrowIfCancellationRequested();
            client.Connect();
            // Identity is checked before any mutating CLI command, even at a previously known IP.
            JsonElement status = Command(client, credentials, "status", []);
            string id = Protocol.Text(status, "device_id"), mode = Protocol.Text(status, "mode");
            if (id.Length == 0 || mode is not ("system" or "rescue")) throw new InvalidOperationException("SSH 候选不是可管理的 ARMHPC OTA 设备。");
            if (expected?.Managed == true && expected.DeviceId != id) throw new InvalidOperationException("设备 ID 不匹配，拒绝在此 IP 执行操作。");
            if (expected?.IgnoreFingerprint!=true && expected?.HostKeys.TryGetValue(mode, out string? pin) == true && pin != fingerprint)
                throw new InvalidOperationException("当前环境的 SSH 主机密钥已改变。请单独核查后重新登记。");
            string hostname=Hostname(client);
            var network = operation == "status" ? NetworkMetadata.Read(client) : null;
            cancellation.ThrowIfCancellationRequested();
            JsonElement data = operation == "status" && arguments.Count == 0 ? (network?.Merge(status,hostname)??status) : Command(client, credentials, operation, arguments, yes);
            return new RemoteResult(data, fingerprint, mode, hostname, network);
        }, cancellation); }
        catch (Exception) when (cancellation.IsCancellationRequested) { throw new OperationCanceledException(cancellation); }
        catch (Exception error) when (error is SshConnectionException or SshOperationTimeoutException or SocketException)
        { throw new TransientConnectionException("SSH 连接中断；设备任务仍需通过持久 ID 查询。", error); }
    }

    private static JsonElement Command(SshClient client, Credentials credentials, string operation, IReadOnlyList<string> arguments, bool yes = false, TimeSpan? timeout=null)
    {
        using var command = client.CreateCommand(Commands.Build(operation, arguments, credentials.Username != "root", yes));
        command.CommandTimeout = timeout??TimeSpan.FromMinutes(operation is "download" or "apply" or "bootstrap" or "recover" or "tools" ? 60 : 3);
        string stdout = command.Execute();
        if (string.IsNullOrWhiteSpace(stdout)) throw new InvalidOperationException("设备没有返回 CLI JSON；请先安装 OTA runtime，并检查管理员的 sudo 权限。");
        return Protocol.Decode(stdout);
    }

    public async Task<Endpoint?> Reconnect(Device device, Credentials credentials, IReadOnlyList<string> ranges, CancellationToken cancellation = default, bool maintenance = false)
    {
        // First try the known address; scan only explicitly approved scopes if it has moved.
        var original = new Endpoint(device.Address, device.Port);
        try
        {
            if(maintenance) await MaintenanceStatus(original, credentials, device, cancellation);
            else await Execute(original, credentials, device, "status", [], cancellation: cancellation);
            return original;
        }
        catch (Exception) when (!cancellation.IsCancellationRequested) { }
        foreach (string range in ranges)
            foreach (Endpoint endpoint in await Scanner.Scan(range, device.Port, cancellation: cancellation))
            {
                if (endpoint == original) continue;
                try
                {
                    // A fingerprint bypass only authorizes the explicitly selected address.
                    // Discovery candidates still need a previously pinned key before authentication.
                    var discovery=new Device{DeviceId=device.DeviceId,Transport=device.Transport,HostKeys=new(device.HostKeys)};
                    // Unknown keys are rejected before credentials are sent.
                    if(maintenance) await MaintenanceStatus(endpoint, credentials, discovery, cancellation);
                    else await Execute(endpoint, credentials, discovery, "status", [], cancellation: cancellation);
                    return endpoint;
                }
                catch (Exception) when (!cancellation.IsCancellationRequested) { }
            }
        return null;
    }
}
