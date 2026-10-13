// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace ArmHpc.Ota.Core;

public sealed record DiscoveredHost(Endpoint Endpoint, string Hostname = "", string NameSource = "");
public sealed record DiscoveryName(string Hostname, string Source);

/// <summary>Unauthenticated DNS names are inventory hints, never device identity.</summary>
public static class HostDiscovery
{
    public static string CleanName(string? name)
    {
        name = name?.Trim().TrimEnd('.') ?? "";
        if (name.Length is < 1 or > 253 || IPAddress.TryParse(name, out _) ||
            name.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)) ||
            name.Split('.').Any(label => label.Length is < 1 or > 63 ||
                label.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_')))) return "";
        return name;
    }

    public static async Task<DiscoveryName?> Resolve(string address, CancellationToken token = default)
    {
        if (!IPAddress.TryParse(address, out var target) || target.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Name discovery requires an IPv4 address.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));
        var dns = ResolveDns(target, deadline.Token);
        var mdns = ResolveMdns(target, deadline.Token);
        var pending = new List<Task<DiscoveryName?>> { dns, mdns };
        while (pending.Count > 0)
        {
            var finished = await Task.WhenAny(pending).ConfigureAwait(false);
            pending.Remove(finished);
            var result = await finished.ConfigureAwait(false);
            if (result is not null) { deadline.Cancel(); return result; }
        }
        token.ThrowIfCancellationRequested();
        return null;
    }

    private static async Task<DiscoveryName?> ResolveDns(IPAddress target, CancellationToken token)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(target).WaitAsync(token).ConfigureAwait(false);
            string name = CleanName(entry.HostName);
            return name.Length > 0 && entry.AddressList.Contains(target) ? new(name, "DNS") : null;
        }
        catch (Exception error) when (error is SocketException or OperationCanceledException or ArgumentException)
        { return null; }
    }

    public static string ReverseName(IPAddress address)
        => string.Join('.', address.GetAddressBytes().Reverse()) + ".in-addr.arpa";

    public static byte[] CreateQuery(IPAddress target, ushort identifier)
    {
        using var stream = new MemoryStream();
        byte[] header = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(0, 2), identifier);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4, 2), 1);
        stream.Write(header);
        foreach (string label in ReverseName(target).Split('.'))
        {
            byte[] bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((byte)bytes.Length); stream.Write(bytes);
        }
        stream.WriteByte(0); stream.Write([0, 12, 0, 1]);
        return stream.ToArray();
    }

    private static string ReadName(byte[] packet, ref int offset)
    {
        int cursor = offset, end = -1;
        var labels = new List<string>(); var visited = new HashSet<int>();
        for (int hops = 0; hops < 128; hops++)
        {
            if (cursor >= packet.Length || !visited.Add(cursor)) throw new FormatException("Invalid DNS name.");
            int length = packet[cursor++];
            if (length == 0) { offset = end >= 0 ? end : cursor; return string.Join('.', labels); }
            if ((length & 0xc0) == 0xc0)
            {
                if (cursor >= packet.Length) throw new FormatException("Truncated DNS pointer.");
                int next = ((length & 0x3f) << 8) | packet[cursor++];
                if (next >= packet.Length) throw new FormatException("Invalid DNS pointer.");
                if (end < 0) end = cursor; cursor = next; continue;
            }
            if (length > 63 || cursor + length > packet.Length) throw new FormatException("Invalid DNS label.");
            labels.Add(Encoding.UTF8.GetString(packet, cursor, length)); cursor += length;
        }
        throw new FormatException("Too many DNS pointers.");
    }

    public static string ParseResponse(byte[] packet, IPAddress target, ushort identifier)
    {
        if (packet.Length is < 12 or > 9000) return "";
        try
        {
            ushort id = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(0, 2));
            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2, 2));
            if (id != identifier || (flags & 0x8000) == 0 || (flags & 0x7a0f) != 0) return "";
            int questions = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2));
            int records = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2)) +
                BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(8, 2)) +
                BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(10, 2));
            if (questions > 16 || records > 128) return "";
            int offset = 12;
            for (int i = 0; i < questions; i++)
            {
                ReadName(packet, ref offset); if (offset + 4 > packet.Length) return ""; offset += 4;
            }
            string wanted = ReverseName(target);
            for (int i = 0; i < records; i++)
            {
                string owner = ReadName(packet, ref offset);
                if (offset + 10 > packet.Length) return "";
                int kind = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset, 2));
                int @class = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 2, 2)) & 0x7fff;
                uint ttl = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(offset + 4, 4));
                int length = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 8, 2)); offset += 10;
                if (offset + length > packet.Length) return "";
                if (kind == 12 && @class == 1 && ttl > 0 && owner.Equals(wanted, StringComparison.OrdinalIgnoreCase))
                {
                    int end = offset; string name = CleanName(ReadName(packet, ref end));
                    if (end <= offset + length && name.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) return name;
                }
                offset += length;
            }
        }
        catch (Exception error) when (error is FormatException or ArgumentException or IndexOutOfRangeException) { }
        return "";
    }

    private static IEnumerable<IPAddress> LocalInterfaces(IPAddress target)
    {
        byte[] remote = target.GetAddressBytes();
        foreach (var network in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (network.OperationalStatus != OperationalStatus.Up || network.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            foreach (var item in network.GetIPProperties().UnicastAddresses)
            {
                if (item.Address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(item.Address)) continue;
                byte[] local = item.Address.GetAddressBytes(), mask = item.IPv4Mask.GetAddressBytes();
                if (local.Length == 4 && mask.Length == 4 && Enumerable.Range(0, 4).All(i => (local[i] & mask[i]) == (remote[i] & mask[i]))) yield return item.Address;
            }
        }
    }

    private static async Task<DiscoveryName?> ResolveMdns(IPAddress target, CancellationToken token)
    {
        try
        {
            var attempts = LocalInterfaces(target).Distinct().Select(local => QueryInterface(local, target, token)).ToList();
            while (attempts.Count > 0)
            {
                var finished = await Task.WhenAny(attempts).ConfigureAwait(false); attempts.Remove(finished);
                string name = await finished.ConfigureAwait(false);
                if (name.Length > 0) return new(name, "mDNS");
            }
        }
        catch (Exception error) when (error is NetworkInformationException or SocketException or OperationCanceledException) { }
        return null;
    }

    private static async Task<string> QueryInterface(IPAddress local, IPAddress target, CancellationToken token)
    {
        try
        {
            using var client = new UdpClient(new IPEndPoint(local, 0));
            client.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
            client.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, local.GetAddressBytes());
            ushort identifier = (ushort)System.Security.Cryptography.RandomNumberGenerator.GetInt32(1, 65536);
            byte[] query = CreateQuery(target, identifier);
            await client.SendAsync(query, new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353), token).ConfigureAwait(false);
            while (!token.IsCancellationRequested)
            {
                var reply = await client.ReceiveAsync(token).ConfigureAwait(false);
                if (reply.RemoteEndPoint.Port != 5353 || !reply.RemoteEndPoint.Address.Equals(target)) continue;
                string name = ParseResponse(reply.Buffer, target, identifier);
                if (name.Length > 0) return name;
            }
        }
        catch (Exception error) when (error is SocketException or OperationCanceledException or ObjectDisposedException) { }
        return "";
    }
}
