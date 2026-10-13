// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ArmHpc.Ota.Core;

namespace ArmHpc.Ota.Windows;
public partial class MainWindow
{
    private int RemoveLocalDevices(IReadOnlyList<Device> targets)
    {
        var removed=DeviceInventory.Remove(devices,targets,batching || scanning is not null || authenticating is not null);
        foreach(var device in removed)
        {
            ssh.Disconnect(device);
            bool sameConnection=devices.Any(d=>d.DeviceId==device.DeviceId && d.Transport==device.Transport);
            if(!sameConnection)
            {
                sessionCredentials.Remove(device.DeviceId+"/"+device.Transport);
                vault.ForgetConnection(device,!devices.Any(d=>d.DeviceId==device.DeviceId));
            }
            if(!devices.Any(d=>d.DeviceId==device.DeviceId))latestStatus.Remove(device.DeviceId);
        }
        DeviceGrid.UnselectAll();Save();RefreshSelectionSummary();
        return removed.Count;
    }
    private void RemoveDevicesClick(object sender,RoutedEventArgs e)
    {
        try
        {
            var targets=SelectedTargets(false);
            if(batching || scanning is not null || authenticating is not null)throw new InvalidOperationException("请先停止扫描或等待当前操作完成，再删除本地主机。");
            if(MessageBox.Show(this,$"从本地列表删除 {targets.Count} 台主机？设备上的任务和本地升级记录会保留。","删除本地主机",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
            int removed=RemoveLocalDevices(targets);StatusBar.Text=$"已删除 {removed} 台本地主机；重新扫描可再次发现。";
        }
        catch(Exception error){MessageBox.Show(this,error.Message,"删除未完成");}
    }
    private void DeviceGridKeyDown(object sender,KeyEventArgs e)
    {
        if(e.Key!=Key.Delete)return;e.Handled=true;RemoveDevicesClick(sender,new RoutedEventArgs());
    }
    private void DevelopmentPresetChanged(object sender,SelectionChangedEventArgs e) { }
    private void SendDevelopmentCommandClick(object sender,RoutedEventArgs e)
    {
        if(DevelopmentPreset.SelectedItem is not CommandPreset preset)return;
        CommandLine.Text=preset.Command;
        SendCommandClick(sender,e);
    }
}
