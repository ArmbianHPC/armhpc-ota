// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
namespace ArmHpc.Ota.Core;

public sealed record MacIpCandidate(string Address, int Port, string MacAddress, bool SshReady);
public sealed record MacDeviceMatch(string DeviceId, IReadOnlyList<MacIpCandidate> Candidates);
public sealed record MacScanReport(IReadOnlyList<string> Ranges, IReadOnlyList<MacDeviceMatch> Devices);

public static class MacDiscovery
{
    static HashSet<string> Macs(Device device) => (device.MacAddresses ?? []).Append(device.MacAddress)
        .Where(NetworkMetadata.ValidMac).ToHashSet(StringComparer.OrdinalIgnoreCase);

    public static async Task<MacScanReport> Scan(IReadOnlyList<Device> devices, IReadOnlyList<string> ranges,
        CancellationToken token = default, Action<string>? progress = null,
        Func<CancellationToken, Task<IReadOnlyList<NetworkNeighbor>>>? neighbors = null,
        Func<string, int, CancellationToken, Task<IReadOnlyList<Endpoint>>>? scan = null,
        Func<IReadOnlyList<string>>? localRanges = null)
    {
        if (devices.Count == 0 || devices.Any(d => !d.Managed || d.Transport != "ssh"))
            throw new ArgumentException("请选择已认证的 SSH 设备。串口设备请先登记 SSH 连接。");
        if (devices.Any(d => Macs(d).Count == 0))
            throw new ArgumentException("所选设备缺少已认证的 MAC；请先在可达地址认证或刷新设备状态。");
        if (devices.Any(d => d.Port is < 1 or > 65535)) throw new ArgumentException("设备 SSH 端口无效。");
        neighbors ??= NetworkReconnect.Neighbors;
        scan ??= (range, port, ct) => Scanner.Scan(range, port, cancellation: ct);
        var scopes = (ranges.Count > 0 ? ranges : (localRanges ?? NetworkReconnect.LocalRanges)()).Distinct().ToArray();
        if (scopes.Length == 0) throw new ArgumentException("没有可用的直连私有网段，请填写扫描范围，例如 192.168.100.0/24。");
        foreach (string range in scopes) Scanner.Expand(range);
        var ready = new HashSet<Endpoint>();
        foreach (string range in scopes)
            foreach (int port in devices.Select(d => d.Port).Distinct())
            {
                token.ThrowIfCancellationRequested();
                progress?.Invoke($"按 MAC 查找 IP · 扫描 {range} · SSH 端口 {port}");
                ready.UnionWith(await scan(range, port, token).ConfigureAwait(false));
            }
        token.ThrowIfCancellationRequested();
        var rows = await neighbors(token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var matches = devices.Select(device => new MacDeviceMatch(device.DeviceId,
            rows.Where(r => Macs(device).Contains(r.MacAddress) && NetworkReconnect.UsableAddress(r.Address) &&
                            scopes.Any(s => NetworkReconnect.Contains(s, r.Address)))
                .Select(r => new MacIpCandidate(r.Address, device.Port, r.MacAddress.ToLowerInvariant(),
                    ready.Contains(new Endpoint(r.Address, device.Port))))
                .Distinct().OrderByDescending(r => r.SshReady).ThenBy(r => r.Address, StringComparer.Ordinal).ToArray())).ToArray();
        foreach (var match in matches)
            foreach (var candidate in match.Candidates)
                progress?.Invoke($"MAC 匹配 {candidate.MacAddress} → {candidate.Address}:{candidate.Port} · " +
                                 (candidate.SshReady ? "SSH 已就绪，等待身份核对" : "邻居记录匹配，SSH 尚未就绪"));
        return new(scopes, matches);
    }

    public static void Accept(Device device, MacIpCandidate candidate, RemoteResult response,
        bool approvedNewFingerprint = false)
    {
        if (!device.Managed || device.Transport != "ssh" || !candidate.SshReady ||
            !Macs(device).Contains(candidate.MacAddress) || !NetworkReconnect.UsableAddress(candidate.Address) ||
            candidate.Port != device.Port) throw new ArgumentException("扫描候选与已登记设备不匹配。");
        if (Protocol.Text(response.Data, "device_id") != device.DeviceId)
            throw new DeviceIdentityMismatchException("扫描地址的持久设备 ID 与原设备不同。");
        if (response.Mode is not ("system" or "rescue") || response.Fingerprint.Length == 0)
            throw new SshHostIdentityException("扫描地址没有可核对的环境或 SSH 指纹。");
        if (device.HostKeys.TryGetValue(response.Mode, out var existing))
        {
            if (existing != response.Fingerprint) throw new SshHostIdentityException("此环境的 SSH 指纹已改变。");
        }
        else if (!device.HostKeys.ContainsValue(response.Fingerprint) && !approvedNewFingerprint)
            throw new SshHostIdentityException("请先明确确认此环境的 SSH 指纹。");
        device.HostKeys[response.Mode] = response.Fingerprint;
        device.Address = candidate.Address;
        NetworkReconnect.Remember(device, new(candidate.Address, candidate.Port), response.Mode, response.Network);
    }
}
