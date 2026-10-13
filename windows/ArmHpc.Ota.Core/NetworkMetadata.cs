// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Renci.SshNet;

namespace ArmHpc.Ota.Core;

public sealed record NetworkPort(string Interface, string MacAddress, string[] Addresses);
public sealed record NetworkSnapshot(string MacAddress, IReadOnlyList<NetworkPort> Interfaces)
{
    public string Detail => string.Join(Environment.NewLine, Interfaces.Select(p => p.Interface + " · " + p.MacAddress +
        (p.Addresses.Length == 0 ? "" : " · " + string.Join(", ", p.Addresses))));
    public JsonElement Merge(JsonElement status, string hostname)
    {
        var value = status.EnumerateObject().ToDictionary(p => p.Name, p => (object)p.Value.Clone());
        value["mac_address"] = MacAddress;
        value["network_interfaces"] = Interfaces.Select(p => new { name = p.Interface, mac_address = p.MacAddress, addresses = p.Addresses }).ToArray();
        if (hostname.Length > 0) value["hostname"] = hostname;
        return JsonSerializer.SerializeToElement(value);
    }
}

public static class NetworkMetadata
{
    public const string ProbeCode = """
import json,os,subprocess,shutil
from pathlib import Path
try:rows=json.loads(subprocess.check_output([shutil.which('ip') or '/usr/sbin/ip','-j','address','show'],text=True,timeout=5))
except (OSError,subprocess.SubprocessError):rows=[]
addresses={r.get('ifname',''):[a['local'] for a in r.get('addr_info',[]) if a.get('scope')=='global'] for r in rows}
ports=[]
for path in sorted(Path('/sys/class/net').iterdir()):
 if path.name=='lo' or not (path/'device').exists():continue
 ports.append({'interface':path.name,'mac_address':(path/'address').read_text().strip(),'addresses':addresses.get(path.name,[])})
connection=os.environ.get('SSH_CONNECTION','').split()
print(json.dumps({'interfaces':ports,'local_address':connection[2] if len(connection)==4 else ''}))
""";
    public static string Command => "python3 -c " + Commands.Quote(ProbeCode);
    public static bool ValidMac(string value)
        => Regex.IsMatch(value, @"\A(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\z") &&
           value != "00:00:00:00:00:00" && (Convert.ToByte(value[..2], 16) & 1) == 0;

    public static NetworkSnapshot? Parse(string raw)
    {
        if (raw.Length is < 2 or > 65536) return null;
        try
        {
            using var document = JsonDocument.Parse(raw); var root = document.RootElement;
            if (!root.TryGetProperty("interfaces", out var array) || array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > 128) return null;
            var ports = new List<NetworkPort>(); var names = new HashSet<string>();
            foreach (var row in array.EnumerateArray())
            {
                string name = Protocol.Text(row, "interface"), mac = Protocol.Text(row, "mac_address");
                if (!Regex.IsMatch(name, @"\A[A-Za-z0-9_.:-]{1,15}\z") || name is "." or ".." or "lo" || !ValidMac(mac) || !names.Add(name)) continue;
                var addresses = row.TryGetProperty("addresses", out var values) && values.ValueKind == JsonValueKind.Array
                    ? values.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!)
                        .Where(v => IPAddress.TryParse(v, out _)).Distinct().Take(16).ToArray() : [];
                ports.Add(new(name, mac.ToLowerInvariant(), addresses));
            }
            if (ports.Count == 0) return null;
            string local = Protocol.Text(root, "local_address");
            var primary = ports.FirstOrDefault(p => p.Addresses.Contains(local)) ??
                ports.FirstOrDefault(p => p.Addresses.Any(a => IPAddress.Parse(a).AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)) ?? ports[0];
            return new(primary.MacAddress, ports);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or FormatException or ArgumentException) { return null; }
    }

    public static NetworkSnapshot? Read(SshClient client)
    {
        try
        {
            using var command = client.CreateCommand(Command); command.CommandTimeout = TimeSpan.FromSeconds(8);
            string raw = command.Execute();
            return command.ExitStatus == 0 ? Parse(raw) : null;
        }
        catch (Exception error) when (error is Renci.SshNet.Common.SshOperationTimeoutException or Renci.SshNet.Common.SshConnectionException or IOException)
        { return null; }
    }
}
