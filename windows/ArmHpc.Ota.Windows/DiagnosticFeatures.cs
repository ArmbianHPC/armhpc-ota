// SPDX-License-Identifier: GPL-3.0-only
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using ArmHpc.Ota.Core;
using Microsoft.Win32;
namespace ArmHpc.Ota.Windows;

public partial class MainWindow
{
    Device DiagnosticDevice()
    {
        var targets=SelectedTargets();
        if(targets.Count!=1 || ((ComboBoxItem)Concurrency.SelectedItem).Content.ToString()!="1")
            throw new InvalidOperationException("看门狗/BOOT 诊断请选择一台设备，并发设为 1。");
        return targets[0];
    }
    async Task<CommandReply> DiagnosticCommand(Device device,string command,bool confirm)
    {
        var request=ArmHpcCommands.Parse(command);
        if(confirm && MessageBox.Show(this,"此操作可能重启或停止喂狗。确认现场可断电恢复；SSH/COM 结果未知时仅查询原诊断 ID。\n\n"+command,
            "单节点复位诊断",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)throw new OperationCanceledException();
        device.LastCommand=command;device.CommandSummary="诊断提交中";
        try
        {
            var reply=await ssh.ExecuteArmHpc(Endpoint(device),CredentialsFor(device),device,request,closing.Token);
            device.CommandSummary=reply.ExitCode==0?"诊断已返回":"诊断拒绝";device.CommandDetail=reply.Output+"\n"+reply.Error;
            Show(JsonSerializer.SerializeToElement(reply));Save();return reply;
        }
        catch(CommandResultUnknownException)
        {device.CommandSummary="结果未知；按原诊断 ID 查询";Save();throw;}
    }
    private async void WatchdogQueryClick(object sender,RoutedEventArgs e)
    {
        try
        {
            var d=DiagnosticDevice();string action=(sender as Button)?.Tag?.ToString()??"status";
            await DiagnosticCommand(d,"armhpc watchdog "+action+" --json",false);
        }catch(Exception error){MessageBox.Show(this,error.Message,"诊断未完成");}
    }
    private async void WatchdogPrepareClick(object sender,RoutedEventArgs e)
    {
        try
        {
            var d=DiagnosticDevice();
            string? kind=Dialogs.Input(this,"准备诊断","expire / reboot / direct-restart / panic","expire");if(kind is null)return;
            if(kind is not ("expire" or "reboot" or "direct-restart" or "panic"))throw new ArgumentException("未知诊断类型。");
            string? sata=Dialogs.Input(this,"SATA 条件","present 或 absent；执行前需卸载 SATA，absent 要拔开数据与电源","present");if(sata is null)return;
            if(sata is not ("present" or "absent"))throw new ArgumentException("未知 SATA 条件。");
            await DiagnosticCommand(d,"armhpc-rescue watchdog prepare --kind "+kind+" --sata "+sata+" --yes --json",true);
        }catch(Exception error){MessageBox.Show(this,error.Message,"准备未完成");}
    }
    private async void WatchdogTestClick(object sender,RoutedEventArgs e)
    {
        try
        {
            var d=DiagnosticDevice();string? id=Dialogs.Input(this,"执行复位诊断","准备操作返回的 test_id；已提交的诊断不会再次触发");if(id is null)return;
            if(!Guid.TryParse(id,out _))throw new ArgumentException("诊断 ID 无效。");
            await DiagnosticCommand(d,"armhpc-rescue watchdog test --test-id "+id+" --checked-sata-power --yes --json",true);
        }catch(Exception error){MessageBox.Show(this,error.Message,"诊断结果待核对");}
    }
    private void DiagnosticComClick(object sender,RoutedEventArgs e)
    {
        try
        {
            var d=DiagnosticDevice();string? ports=Dialogs.Input(this,"允许的 USB COM 接管","明确允许登录的备用端口，逗号分隔；仅 Linux gadget 已启动时可用",string.Join(",",d.SerialPorts));if(ports is null)return;
            string[] selected=ports.Split(',',StringSplitOptions.TrimEntries|StringSplitOptions.RemoveEmptyEntries);
            if(selected.Any(p=>!System.Text.RegularExpressions.Regex.IsMatch(p,"^COM[1-9][0-9]*$",System.Text.RegularExpressions.RegexOptions.IgnoreCase)))
                throw new ArgumentException("COM 端口格式无效。");
            d.SerialPorts=selected;Save();Log("已登记所选节点的明确 COM 接管范围。");
        }catch(Exception error){MessageBox.Show(this,error.Message);}
    }
    private async void BootStatusClick(object sender,RoutedEventArgs e)
    {
        try{await DiagnosticCommand(DiagnosticDevice(),"armhpc ota boot status --json",false);}
        catch(Exception error){MessageBox.Show(this,error.Message);}
    }
    private async void UsbRescueClick(object sender,RoutedEventArgs e)
    {
        if(batching)return;
        try
        {
            var device=DiagnosticDevice();
            if(device.Board!="wxy-oesp-v22")throw new InvalidOperationException("USB 下载口恢复入口需要 OESP。");
            var exportPicker=new OpenFileDialog{Title="选择本机私有 BOOT 导出清单",Filter="BOOT 导出清单|BOOT-export.json"};
            if(exportPicker.ShowDialog(this)!=true)return;
            using var descriptor=JsonDocument.Parse(File.ReadAllText(exportPicker.FileName));
            if(Protocol.Text(descriptor.RootElement,"device_id")!=device.DeviceId)
                throw new InvalidOperationException("BOOT 导出不属于所选设备。");
            var toolPicker=new OpenFileDialog{Title="选择随包 USB 恢复工具",Filter="OESP USB 恢复工具|oesp-usb-rescue.py"};
            if(toolPicker.ShowDialog(this)!=true)return;
            string folder=Path.GetDirectoryName(toolPicker.FileName)!;
            Show(await UsbRescue.Run(folder,exportPicker.FileName,true,Log,closing.Token));
            if(MessageBox.Show(this,"关闭 USB Burning Tool，连接一台处于 USB 下载模式的 OESP。\n\n此步骤在内存中启动已确认 Rescue。之后按原设备身份重连，再恢复 BOOT。Windows 需以管理员身份启动本程序。",
                "USB 恢复",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
            batching=true;
            var result=await UsbRescue.Run(folder,exportPicker.FileName,false,Log,closing.Token);
            Show(result);device.State="USB 恢复已提交，等待 Linux 重连";Save();
        }
        catch(Exception error){MessageBox.Show(this,error.Message,"USB 恢复待核对");}
        finally{batching=false;}
    }
    private async void BootCandidateClick(object sender,RoutedEventArgs e)
    {
        if(batching)return;
        try
        {
            var d=DiagnosticDevice();var credentials=CredentialsFor(d);
            var picker=new OpenFileDialog{Title="签名 BOOT + 配套 Rescue 候选包",Filter="签名包|*.tar.xz"};
            if(picker.ShowDialog(this)!=true)return;
            if(d.Mode!="rescue")throw new InvalidOperationException("请先普通重启进入 Rescue，再维护 BOOT。");
            string hashOfBundle;
            using(var file=File.OpenRead(picker.FileName))hashOfBundle=Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(file));
            var current=await ssh.Execute(Endpoint(d),credentials,d,"boot",["status"],cancellation:closing.Token);
            string bindingDir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ARMHPC","OTA","boot-requests");
            Directory.CreateDirectory(bindingDir);string bindingFile=Path.Combine(bindingDir,Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(d.DeviceId)))+".json");
            string id;
            if(current.Data.TryGetProperty("task",out var existing) && existing.ValueKind==JsonValueKind.Object && Protocol.Text(existing,"stage") is not ("rolled-back" or "committed"))
            {
                if(Protocol.Text(existing,"bundle_sha256")!=hashOfBundle)throw new InvalidOperationException("现有 BOOT 任务绑定其他包，请先查询或回滚。");
                id=Protocol.Text(existing,"task_id");
                if(Protocol.Text(existing,"stage") is "awaiting-watchdog" or "preparing-system" or "updating-system")
                {Show(current.Data);return;}
            }
            else if(File.Exists(bindingFile))
            {
                using var saved=JsonDocument.Parse(File.ReadAllText(bindingFile));
                if(Protocol.Text(saved.RootElement,"sha256")!=hashOfBundle)throw new InvalidOperationException("本地待核对 BOOT 请求绑定其他包；先核对原请求。");
                id=Protocol.Text(saved.RootElement,"request_id");
            }
            else id=Guid.NewGuid().ToString("D");
            if(!Guid.TryParseExact(id,"D",out _))throw new InvalidOperationException("BOOT 任务 ID 无效。");
            File.WriteAllText(bindingFile,JsonSerializer.Serialize(new{request_id=id,sha256=hashOfBundle,device_id=d.DeviceId}));
            string remote=await ssh.Upload(Endpoint(d),credentials,d,picker.FileName,closing.Token);
            var preview=await ssh.Execute(Endpoint(d),credentials,d,"boot",["plan","--bundle",remote],cancellation:closing.Token);
            Show(preview.Data);
            if(MessageBox.Show(this,"先创建私有 BOOT 备份和强制 Rescue 恢复镜像，再下载校验；只有导出成功后才切换候选。\n永久引导链和分区表不写入。","BOOT 候选",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
            var prepared=await ssh.Execute(Endpoint(d),credentials,d,"boot",["apply","--bundle",remote,"--request-id",id],true,cancellation:closing.Token);
            var task=prepared.Data.GetProperty("task");
            string dir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ARMHPC","OTA","private-boot-backups",id);
            await ssh.DownloadBoot(Endpoint(d),credentials,d,task,dir,Log,closing.Token);
            Log("私有 BOOT 恢复备份已校验；目录："+dir);
            if(MessageBox.Show(this,"私有恢复文件已校验。现在安装备用 Rescue 并切换 BOOT 候选？\n请求："+id,"最后确认",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
            string hash=Protocol.Text(task.GetProperty("backups").GetProperty("BOOT-rescue.img.xz"),"sha256");
            var result=await ssh.Execute(Endpoint(d),credentials,d,"boot",["apply","--request-id",id,"--exported-backup-sha256",hash],true,cancellation:closing.Token);
            File.Delete(bindingFile);Show(result.Data);d.State="BOOT 等待启动确认";Save();
        }catch(Exception error){MessageBox.Show(this,error.Message,"BOOT 维护未完成；按原任务查询");}
    }
    private async void BootRollbackClick(object sender,RoutedEventArgs e)
    {
        try
        {
            var d=DiagnosticDevice();string? id=Dialogs.Input(this,"BOOT 回滚","原 BOOT task_id");if(id is null)return;
            if(!Guid.TryParse(id,out _))throw new ArgumentException("BOOT ID 无效。");
            await DiagnosticCommand(d,"armhpc-rescue ota boot rollback --request-id "+id+" --yes --json",true);
        }catch(Exception error){MessageBox.Show(this,error.Message,"回滚未完成");}
    }
    private async void BootRestoreClick(object sender,RoutedEventArgs e)
    {
        if(batching)return;
        try
        {
            var device=DiagnosticDevice();
            var current=await ssh.Execute(Endpoint(device),CredentialsFor(device),device,"boot",["status"],cancellation:closing.Token);
            string id=Protocol.Text(current.Data.GetProperty("task"),"task_id");
            if(!Guid.TryParseExact(id,"D",out _))throw new InvalidOperationException("缺少原 BOOT 任务 ID。");
            var preview=await ssh.Execute(Endpoint(device),CredentialsFor(device),device,"boot",["restore","--request-id",id],cancellation:closing.Token);
            Show(preview.Data);
            if(MessageBox.Show(this,"按已保存的设备身份和分区范围恢复 BOOT。\n\n恢复后仍停留在 Rescue，继续执行同任务的 BOOT 回滚。",
                "恢复 BOOT",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
            batching=true;
            Show((await ssh.Execute(Endpoint(device),CredentialsFor(device),device,"boot",["restore","--request-id",id,"--execute"],true,cancellation:closing.Token)).Data);
        }catch(Exception error){MessageBox.Show(this,error.Message,"BOOT 恢复待核对");}
        finally{batching=false;}
    }

    private async void BootCommitClick(object sender,RoutedEventArgs e)
    {
        if(batching)return;
        try
        {
            var device=DiagnosticDevice();
            var current=await ssh.Execute(Endpoint(device),CredentialsFor(device),device,"boot",["status"],cancellation:closing.Token);
            if(!current.Data.TryGetProperty("task",out var task) || task.ValueKind!=JsonValueKind.Object)
                throw new InvalidOperationException("设备没有待确认的 BOOT 任务。");
            string id=Protocol.Text(task,"task_id");
            if(!Guid.TryParseExact(id,"D",out _))throw new InvalidOperationException("设备 BOOT 任务 ID 无效。");
            if(Protocol.Text(task,"stage")=="committed"){Show(current.Data);return;}
            if(MessageBox.Show(this,"确认当前 BOOT 任务。设备会核对启动和复位诊断记录；包中包含配套系统时，将继续部署并健康确认 SATA 系统。\n\n任务："+id,
                "确认 BOOT 维护",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
            var result=await ssh.Execute(Endpoint(device),CredentialsFor(device),device,"boot",
                ["apply","--request-id",id,"--commit"],true,cancellation:closing.Token);
            device.LastCommand="BOOT 确认 / 配套系统更新";
            device.CommandSummary=Protocol.Text(result.Data.GetProperty("task"),"stage");
            Show(result.Data);Save();
        }catch(Exception error){MessageBox.Show(this,error.Message,"BOOT 任务按原 ID 继续查询");}
    }
}
