// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
namespace ArmHpc.Ota.Core;

public static class DeviceInventory
{
    public static Device ApplyDiscovery(ICollection<Device> inventory, DiscoveredHost host)
    {
        var device = inventory.FirstOrDefault(d => d.Transport == "ssh" && d.Address == host.Endpoint.Address && d.Port == host.Endpoint.Port);
        if (device is null) { device = new Device { Address = host.Endpoint.Address, Port = host.Endpoint.Port }; inventory.Add(device); }
        if (!device.Managed && host.Hostname.Length > 0)
        {
            device.Hostname = host.Hostname; device.HostnameSource = host.NameSource;
            device.State = "SSH 候选 · " + host.NameSource + " 名称";
        }
        return device;
    }

    public static IReadOnlyList<Device> Remove(ICollection<Device> inventory, IEnumerable<Device> selected, bool busy = false)
    {
        if (busy) throw new InvalidOperationException("正在扫描、认证或执行操作；请先停止或等待完成，再删除本地主机。");
        var targets = selected.Distinct().Where(inventory.Contains).ToArray();
        if (targets.Length == 0) throw new InvalidOperationException("请选择要删除的本地主机。");
        foreach (var target in targets) inventory.Remove(target);
        return targets;
    }
}
