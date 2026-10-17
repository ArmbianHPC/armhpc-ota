// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArmHpc.Ota.Core;

public sealed record KnownAddress(string Address, int Port, string Mode);
public sealed record NetworkNeighbor(string Address, string MacAddress);

public sealed class DeviceIdentityMismatchException(string message) : InvalidOperationException(message);

public sealed class SshHostIdentityException(string message) : InvalidOperationException(message);

public static class NetworkReconnect
{
    public static async Task<T> ReadBound<T>(Func<Task<T>> read)
    {
        try { return await read().ConfigureAwait(false); }
        catch (DeviceIdentityMismatchException error)
        { throw new TransientConnectionException("旧地址已对应其他设备；继续按原设备 ID 重连查询。", error); }
        catch (Exception error) when (error is SshHostIdentityException or Renci.SshNet.Common.SshAuthenticationException)
        { throw new TransientConnectionException(FailureReason(error) + "；继续按原设备 ID 重连查询。", error); }
    }

    public static Device DiscoveryIdentity(Device device) => new()
    {
        DeviceId = device.DeviceId, Transport = "ssh", HostKeys = new(device.HostKeys),
    };

    public static bool UsableAddress(string value)
        => IPAddress.TryParse(value, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork &&
           !IPAddress.IsLoopback(ip) && ip.GetAddressBytes()[0] is > 0 and < 224 &&
           !ip.GetAddressBytes().Take(2).SequenceEqual(new byte[] { 169, 254 });

    public static void Remember(Device device, Endpoint endpoint, string mode, NetworkSnapshot? network = null)
    {
        if (!device.Managed || mode is not ("system" or "rescue") || !UsableAddress(endpoint.Address) || endpoint.Port is < 1 or > 65535) return;
        lock (device)
        {
            var addresses = new[] { endpoint.Address }.Concat(network?.Interfaces.SelectMany(p => p.Addresses) ?? [])
                .Where(UsableAddress).Distinct().Select(a => new KnownAddress(a, endpoint.Port, mode));
            device.KnownAddresses = addresses.Concat(device.KnownAddresses ?? []).Distinct()
                .Where(a => (a.Mode is "system" or "rescue") && UsableAddress(a.Address) && a.Port is >= 1 and <= 65535)
                .GroupBy(a => a.Mode).SelectMany(g => g.Take(4)).ToArray();
            device.MacAddresses = (network?.Interfaces.Select(p => p.MacAddress) ?? [])
                .Concat(device.MacAddresses ?? []).Append(device.MacAddress).Where(NetworkMetadata.ValidMac)
                .Select(m => m.ToLowerInvariant()).Distinct().Take(16).ToArray();
            if (network is not null) { device.MacAddress = network.MacAddress; device.NetworkDetail = network.Detail; }
        }
    }

    public static bool Contains(string cidr, string address)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var subnet) ||
            subnet.AddressFamily != AddressFamily.InterNetwork || !int.TryParse(parts[1], out int prefix) || prefix is < 0 or > 32 ||
            !IPAddress.TryParse(address, out var target) || target.AddressFamily != AddressFamily.InterNetwork) return false;
        byte[] a = subnet.GetAddressBytes(), b = target.GetAddressBytes();
        return Enumerable.Range(0, 4).All(i =>
        {
            int bits = Math.Clamp(prefix - i * 8, 0, 8), mask = (0xff << (8 - bits)) & 0xff;
            return ((a[i] ^ b[i]) & mask) == 0;
        });
    }

    public static IReadOnlyList<string> LocalRanges()
    {
        var result = new List<string>(); int total = 0;
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                foreach (var item in nic.GetIPProperties().UnicastAddresses)
                {
                    if (item.Address.AddressFamily != AddressFamily.InterNetwork || item.PrefixLength is < 22 or > 30) continue;
                    byte[] bytes = item.Address.GetAddressBytes();
                    bool local = bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 || bytes[0] == 192 && bytes[1] == 168;
                    if (!local) continue;
                    string cidr = item.Address + "/" + item.PrefixLength;
                    if (result.Any(r => Contains(r, item.Address.ToString()))) continue;
                    int count = (1 << (32 - item.PrefixLength)) - 2;
                    if (total + count > 1024) continue;
                    result.Add(cidr); total += count;
                }
            }
        }
        catch (Exception e) when (e is NetworkInformationException or PlatformNotSupportedException) { }
        return result;
    }

    public static IReadOnlyList<NetworkNeighbor> ParseNeighbors(string raw, bool windows)
    {
        var result = new List<NetworkNeighbor>();
        if (raw.Length > 1024 * 1024) return result;
        if (windows)
        {
            foreach (string line in raw.Split('\n'))
            {
                var match = Regex.Match(line, @"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\S+");
                if (match.Success) result.Add(new(match.Groups[1].Value, match.Groups[2].Value.Replace('-', ':').ToLowerInvariant()));
            }
        }
        else
        {
            try
            {
                using var data = JsonDocument.Parse(raw);
                if (data.RootElement.ValueKind != JsonValueKind.Array) return result;
                foreach (var row in data.RootElement.EnumerateArray())
                {
                    if (row.ValueKind != JsonValueKind.Object) continue;
                    if (row.TryGetProperty("state", out var state) && state.ToString().Contains("FAILED", StringComparison.OrdinalIgnoreCase)) continue;
                    result.Add(new(Protocol.Text(row, "dst"), Protocol.Text(row, "lladdr").ToLowerInvariant()));
                }
            }
            catch (JsonException) { }
        }
        return result.Where(r => UsableAddress(r.Address) && NetworkMetadata.ValidMac(r.MacAddress)).Distinct().ToArray();
    }

    public static async Task<IReadOnlyList<NetworkNeighbor>> Neighbors(CancellationToken token)
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux()) return [];
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(3));
        bool windows = OperatingSystem.IsWindows();
        var start = new ProcessStartInfo(windows ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "arp.exe") : "ip")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in windows ? new[] { "-a" } : new[] { "-j", "-4", "neighbor", "show" }) start.ArgumentList.Add(arg);
        using var process = new Process { StartInfo = start };
        try
        {
            process.Start();
            var stdout = process.StandardOutput.ReadToEndAsync(deadline.Token);
            var stderr = process.StandardError.ReadToEndAsync(deadline.Token);
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            string raw = await stdout.ConfigureAwait(false); await stderr.ConfigureAwait(false);
            return process.ExitCode == 0 ? ParseNeighbors(raw, windows) : [];
        }
        catch (Exception e) when (e is Win32Exception or IOException or OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(true); } catch (InvalidOperationException) { }
            token.ThrowIfCancellationRequested(); return [];
        }
    }

    public static string FailureReason(Exception error)
    {
        while (error is TransientConnectionException && error.InnerException is { } cause) error = cause;
        return error switch
        {
            DeviceIdentityMismatchException => "持久设备 ID 不匹配",
            SshHostIdentityException => "当前环境的 SSH 指纹未登记或已改变",
            SshLoginRejectedException rejection => rejection.Message,
            Renci.SshNet.Common.SshAuthenticationException => "SSH 登录认证失败，请核对该环境的登录设置",
            Renci.SshNet.Common.SshConnectionException => "SSH 连接或握手失败，请核对已登记指纹",
            Renci.SshNet.Common.SshOperationTimeoutException or TimeoutException or OperationCanceledException => "SSH 查询超时",
            SocketException => "SSH 地址或端口不可达",
            IOException => "连接中断或端口尚未就绪",
            RemoteRejectedException refusal => "设备拒绝状态查询：" + refusal.Code,
            _ => "身份或状态查询失败（" + error.GetType().Name + "）"
        };
    }

    public static async Task<Endpoint?> Find(Device device, IReadOnlyList<string> ranges,
        Func<Endpoint, bool, CancellationToken, Task> probe, CancellationToken token = default,
        Func<CancellationToken, Task<IReadOnlyList<NetworkNeighbor>>>? neighbors = null,
        Func<string, int, CancellationToken, Task<IReadOnlyList<Endpoint>>>? scan = null,
        Func<IReadOnlyList<string>>? localRanges = null, Action<string>? progress = null,
        Func<Endpoint, CancellationToken, Task<bool>>? ready = null)
    {
        if (!device.Managed) throw new ArgumentException("重连需要已登记的持久设备 ID。");
        neighbors ??= Neighbors;
        scan ??= (range, port, ct) => Scanner.Scan(range, port, cancellation: ct);
        localRanges ??= LocalRanges;
        foreach (string range in ranges) Scanner.Expand(range);
        var macs = (device.MacAddresses ?? []).Append(device.MacAddress).Where(NetworkMetadata.ValidMac).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var scopes = ranges.Count > 0 ? ranges : macs.Count > 0 ? localRanges() : [];
        var attempted = new HashSet<Endpoint>();
        var matched = new HashSet<Endpoint>();
        var failures = new Dictionary<Endpoint, string>();
        string? lastFailure = null, macFailure = null;
        void Report(string value) { device.LastReconnectDetail = value; progress?.Invoke(value); }
        void Failed(Endpoint endpoint, string source, string reason)
        {
            string value = $"重连 · {source} {endpoint.Address}:{endpoint.Port} · {reason}";
            failures[endpoint] = value; lastFailure = value;
            if (matched.Contains(endpoint)) macFailure = value;
            Report(value);
        }
        async Task<bool> Try(Endpoint endpoint, string source, bool discovered = true)
        {
            token.ThrowIfCancellationRequested();
            if (!attempted.Add(endpoint)) return false;
            Report($"重连 · {source} {endpoint.Address}:{endpoint.Port}");
            try
            {
                if (ready is not null && !await ready(endpoint, token).ConfigureAwait(false))
                { Failed(endpoint, source, "SSH 端口尚未就绪"); return false; }
                await probe(endpoint, discovered, token).ConfigureAwait(false);
                Report($"重连成功 · 已核对原设备 ID · {endpoint.Address}:{endpoint.Port}");
                return true;
            }
            catch (Exception error) when (!token.IsCancellationRequested)
            { Failed(endpoint, source, FailureReason(error)); return false; }
        }
        Report("重连 · 已登记 MAC：" + (macs.Count == 0 ? "无" : string.Join(", ", macs)) +
               " · SSH 指纹环境：" + (device.HostKeys.Count == 0 ? "无" : string.Join(", ", device.HostKeys.Keys)) +
               " · 扫描范围：" + (scopes.Count == 0 ? "无可用范围" : string.Join(", ", scopes)));
        var original = new Endpoint(device.Address, device.Port);
        if (await Try(original, "当前地址", false)) return original;
        foreach (var known in device.KnownAddresses ?? [])
        {
            if (!UsableAddress(known.Address) || known.Port is < 1 or > 65535 || known.Mode is not ("system" or "rescue")) continue;
            var endpoint = new Endpoint(known.Address, known.Port);
            if (await Try(endpoint, "历史 " + known.Mode + " 地址")) return endpoint;
        }
        async Task<Endpoint?> FromNeighbors()
        {
            foreach (var row in await neighbors(token).ConfigureAwait(false))
            {
                if (!macs.Contains(row.MacAddress) || !UsableAddress(row.Address) || !scopes.Any(r => Contains(r, row.Address))) continue;
                var endpoint = new Endpoint(row.Address, device.Port);
                matched.Add(endpoint);
                Report($"重连 · MAC 匹配 {row.MacAddress} → {row.Address}:{device.Port}");
                if (failures.TryGetValue(endpoint, out var previous)) macFailure = previous;
                if (await Try(endpoint, "MAC 匹配地址")) return endpoint;
            }
            return null;
        }
        if (macs.Count > 0 && await FromNeighbors() is { } cached) return cached;
        foreach (string range in scopes)
        {
            token.ThrowIfCancellationRequested();
            Report($"重连 · 扫描 {range} · SSH 端口 {device.Port}");
            var endpoints = await scan(range, device.Port, token).ConfigureAwait(false);
            Report($"重连 · 扫描 {range} 完成 · {endpoints.Count} 个 SSH 候选");
            // A service can become ready while scanning after a known-address probe failed.
            foreach (var endpoint in endpoints) attempted.Remove(endpoint);
            if (macs.Count > 0 && await FromNeighbors() is { } found) return found;
            foreach (var endpoint in endpoints)
                if (await Try(endpoint, "SSH 候选")) return endpoint;
        }
        token.ThrowIfCancellationRequested();
        Report($"重连未完成 · MAC 匹配 {matched.Count} 个地址 · " +
               (macFailure ?? lastFailure ?? (macs.Count == 0 ? "没有经认证的 MAC，请先认证设备或指定扫描范围" : "未发现可核对的 SSH 地址")));
        return null;
    }
}
