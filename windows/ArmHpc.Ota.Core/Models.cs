// SPDX-License-Identifier: GPL-3.0-only
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace ArmHpc.Ota.Core;

public sealed class Device : INotifyPropertyChanged
{
    public string DeviceId { get; set; } = "";
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IgnoreFingerprint {get;set;}

    private string address = "", mode = "candidate", state = "尚未认证", version = "", name = "", board = "";
    private bool selected;
    private string hostname="", hostnameSource="", macAddress="", networkDetail="";
    public string HostnameSource {get=>hostnameSource;set{hostnameSource=value;Changed();}}
    public string MacAddress {get=>macAddress;set{macAddress=value;Changed();}}
    public string[] MacAddresses { get; set; } = [];
    public KnownAddress[] KnownAddresses { get; set; } = [];
    [System.Text.Json.Serialization.JsonIgnore]
    public string LastReconnectDetail { get; set; } = "";
    public string NetworkDetail {get=>networkDetail;set{networkDetail=value;Changed();}}
    public string Hostname {get=>hostname;set{hostname=value;Changed();}}
    private string lastCommand="",commandSummary="",commandDetail="";
    public string LastCommand{get=>lastCommand;set{lastCommand=value;Changed();}}
    public string CommandSummary{get=>commandSummary;set{commandSummary=value;Changed();}}
    [System.Text.Json.Serialization.JsonIgnore]
    public string CommandDetail{get=>commandDetail;set{commandDetail=value;Changed();}}

    private string clockStatus="未提供",clockDetail="";
    public string ClockStatus{get=>clockStatus;set{clockStatus=value;Changed();}}
    [System.Text.Json.Serialization.JsonIgnore]
    public string ClockDetail{get=>clockDetail;set{clockDetail=value;Changed();}}
    private string nodeStatus="未提供",nodeDetail="设备未提供节点状态。";
    public string NodeStatus{get=>nodeStatus;set{nodeStatus=value;Changed();}}
    [System.Text.Json.Serialization.JsonIgnore]
    public string NodeDetail{get=>nodeDetail;set{nodeDetail=value;Changed();}}

    private string systemVersion = "", rescueVersion = "", rescueSlot = "";
    public string Address { get => address; set { address = value; Changed(); } }
    public int Port { get; set; } = 22;
    private string transport="ssh";
    public string Transport { get=>transport;set{transport=value;Changed();} }
    public int BaudRate { get; set; } = 115200;
    public string[] SerialPorts { get; set; } = [];
    public string Name { get => name; set { name = value; Changed(); } }
    public string Board { get => board; set { board = value; Changed(); } }
    public string Mode { get => mode; set { mode = value; Changed(); } }
    public string State { get => state; set { state = value; Changed(); } }
    public string Version { get => version; set { version = value; Changed(); } }
    public string SystemVersion { get => systemVersion; set { systemVersion = value; Changed(); } }
    public string RescueVersion { get => rescueVersion; set { rescueVersion = value; Changed(); } }
    public string RescueSlot { get => rescueSlot; set { rescueSlot = value; Changed(); } }
    public bool Selected { get => selected; set { selected = value; Changed(); } }
    public Dictionary<string, string> HostKeys { get; set; } = new();
    public bool Managed => DeviceId.Length > 0;
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed([CallerMemberName] string? property = null) => PropertyChanged?.Invoke(this, new(property));
}

public sealed record Credentials(string Username, string Password, string? PrivateKeyPath = null, string? Passphrase = null)
{
    [System.Text.Json.Serialization.JsonIgnore]
    public SshLoginContext? Ssh { get; init; }
}
public sealed record Endpoint(string Address, int Port = 22);
public sealed record RemoteResult(JsonElement Data, string Fingerprint, string Mode, string Hostname="", NetworkSnapshot? Network=null);

public static class Protocol
{
    public static JsonElement Decode(string raw)
    {
        using var document = JsonDocument.Parse(raw.Trim());
        var root = document.RootElement;
        if (root.GetProperty("protocol").GetInt32() != 1) throw new InvalidOperationException("设备 CLI 协议不兼容。");
        if (!root.GetProperty("ok").GetBoolean())
        {
            var error = root.GetProperty("error");
            throw new RemoteRejectedException(error.GetProperty("code").GetString()!, error.GetProperty("message").GetString()!);
        }
        return root.GetProperty("data").Clone();
    }
    public static string Text(JsonElement value, string property) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(property, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString()! : "";
}

public sealed record MaintenanceTask(string DeviceId,string RequestId,string[] Ranges,string Stage="submitting") { public bool Terminal=>Stage is "succeeded" or "rolled-back" or "incomplete" or "refused"; }
