// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
namespace ArmHpc.Ota.Core;

public static class NodePresentation
{
    static bool? Flag(JsonElement value,string key)=>value.ValueKind==JsonValueKind.Object && value.TryGetProperty(key,out var item) &&
        item.ValueKind is JsonValueKind.True or JsonValueKind.False?item.GetBoolean():null;
    static string Ready(bool? value)=>value switch{true=>"就绪",false=>"待处理",_=>"未提供"};
    public static ClockView Describe(JsonElement status)
    {
        if(!status.TryGetProperty("node_runtime",out var runtime) || Flag(runtime,"provided") is not true)
            return new("未提供","设备未提供内核能力、管理网络和持久状态恢复信息。");
        if(runtime.TryGetProperty("error",out var error))return new("查询失败",error.GetString()??"节点状态查询失败");
        runtime.TryGetProperty("kernel_capabilities",out var kernel);runtime.TryGetProperty("management_network",out var network);
        runtime.TryGetProperty("state_recovery",out var state);JsonElement installed=default;
        if(state.ValueKind==JsonValueKind.Object)state.TryGetProperty("installed",out installed);
        string caption="内核 "+Ready(Flag(kernel,"ready"))+" · 管理网络 "+Ready(Flag(network,"ready"));
        var lines=new List<string>{caption,"持久状态恢复："+Ready(Flag(installed,"ready"))};
        if(network.ValueKind==JsonValueKind.Object && network.TryGetProperty("policy",out var policy))
            lines.Add("管理接口："+Protocol.Text(policy,"interface")+" / "+Protocol.Text(policy,"family"));
        if(runtime.TryGetProperty("health",out var health) && Flag(health,"stale") is true)
            lines.Add("持久状态采集已过期或尚未完成，请查询 armhpc health。 ");
        if(kernel.ValueKind==JsonValueKind.Object && kernel.TryGetProperty("missing",out var missing) && missing.ValueKind==JsonValueKind.Object)
            lines.Add("内核缺项："+string.Join(", ",missing.EnumerateObject().Select(p=>p.Name)));
        return new(caption,string.Join(Environment.NewLine,lines));
    }
}
