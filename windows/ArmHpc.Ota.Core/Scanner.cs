// SPDX-License-Identifier: GPL-3.0-only
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ArmHpc.Ota.Core;

public static class Scanner
{
    public static IReadOnlyList<string> Expand(string cidr)
    {
        var parts = cidr.Trim().Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], out int prefix) || prefix < 20 || prefix > 32)
            throw new ArgumentException("请明确指定 IPv4 CIDR（/20 至 /32），单次最多 4096 个地址。");
        byte[] bytes = ip.GetAddressBytes();
        uint value = (uint)bytes[0] << 24 | (uint)bytes[1] << 16 | (uint)bytes[2] << 8 | bytes[3];
        uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
        ulong first = value & mask, count = 1UL << (32 - prefix);
        ulong start = prefix < 31 ? 1UL : 0UL, end = prefix < 31 ? count - 1 : count;
        var result = new List<string>();
        for (ulong offset = start; offset < end; offset++)
        {
            uint address = (uint)(first + offset);
            result.Add($"{address >> 24}.{(address >> 16) & 255}.{(address >> 8) & 255}.{address & 255}");
        }
        return result;
    }

    public static async Task<IReadOnlyList<Endpoint>> Scan(string cidr, int port, Action<int, int>? progress = null, CancellationToken cancellation = default)
    {
        if (port is < 1 or > 65535) throw new ArgumentException("SSH 端口范围无效。");
        var addresses = Expand(cidr);
        var found = new System.Collections.Concurrent.ConcurrentBag<Endpoint>();
        int complete = 0;
        await Parallel.ForEachAsync(addresses, new ParallelOptions { MaxDegreeOfParallelism = 48, CancellationToken = cancellation }, async (address, token) =>
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(1200);
                using var client = new TcpClient(AddressFamily.InterNetwork);
                await client.ConnectAsync(address, port, timeout.Token);
                byte[] banner = new byte[256];
                int count = await client.GetStream().ReadAsync(banner, timeout.Token);
                if (Encoding.ASCII.GetString(banner, 0, count).StartsWith("SSH-2.0-", StringComparison.Ordinal)) found.Add(new(address, port));
            }
            catch (Exception error) when (error is SocketException or OperationCanceledException or IOException) { }
            finally { progress?.Invoke(Interlocked.Increment(ref complete), addresses.Count); }
        });
        return found.OrderBy(item => item.Address, StringComparer.Ordinal).ToArray();
    }
}
