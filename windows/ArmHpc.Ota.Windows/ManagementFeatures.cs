// SPDX-License-Identifier: GPL-3.0-only
using System.ComponentModel;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using ArmHpc.Ota.Core;
using Microsoft.Win32;
namespace ArmHpc.Ota.Windows;

public partial class MainWindow
{
    ICollectionView? deviceView;Credentials? defaultLogin;CancellationTokenSource? authenticating;
    void InitializeManagement()
    {
        defaultLogin=vault.LoadDefault();
        foreach(string mode in new[]{"system","rescue"})if(vault.LoadDefaultEnvironment(mode) is {} saved)defaultEnvironmentLogins[mode]=saved;
        deviceView=CollectionViewSource.GetDefaultView(devices);
        deviceView.Filter=item=>item is Device d && DeviceSelection.Matches(d,HostFilter.Text,ExactHostname.IsChecked==true,(ModeFilter.SelectedItem as ComboBoxItem)?.Tag.ToString()??"all");
        DeviceGrid.ItemsSource=deviceView;CommandPreset.ItemsSource=ArmHpcCommands.ManagementPresets;
        CommandPreset.SelectedItem=ArmHpcCommands.ManagementPresets.First(p=>p.Command=="armhpc --help");
        DevelopmentPreset.ItemsSource=ArmHpcCommands.DevelopmentPresets;DevelopmentPreset.SelectedIndex=0;
        devices.CollectionChanged+=(_,e)=>
        {
            if(e.NewItems is not null)foreach(Device d in e.NewItems)d.PropertyChanged+=DevicePropertyChanged;
            if(e.OldItems is not null)foreach(Device d in e.OldItems)d.PropertyChanged-=DevicePropertyChanged;
            RefreshSelectionSummary();
        };
        foreach(var d in devices)d.PropertyChanged+=DevicePropertyChanged;
        RefreshDefaultLabel();RefreshSelectionSummary();
    }
    void DevicePropertyChanged(object? sender,PropertyChangedEventArgs e)
    {
        Dispatcher.InvokeAsync(()=>
        {
            if(e.PropertyName is "Hostname" or "Name" or "MacAddress" or "Address" or "Mode"){DeviceGrid.CommitEdit();DeviceGrid.CommitEdit();deviceView?.Refresh();}
            RefreshSelectionSummary();
        });
    }
    private void IgnoreFingerprintChanged(object sender,RoutedEventArgs e)
    {
        if(IgnoreSshFingerprint is null)return;
        foreach(var d in devices)d.IgnoreFingerprint=IgnoreSshFingerprint.IsChecked==true;
        if(IsLoaded)Log(IgnoreSshFingerprint.IsChecked==true?"临时忽略 SSH 指纹；跨 IP 自动发现仍使用已登记指纹。":"已恢复 SSH 指纹验证。");
    }
    void RefreshDefaultLabel()=>DefaultCredentialsStatus.Text=DefaultLoginSummary();
    IReadOnlyList<Device> Visible()=>deviceView?.Cast<Device>().ToArray()??[];
    IReadOnlyList<Device> SelectedTargets(bool managed=true)
    {
        DeviceGrid.CommitEdit();DeviceGrid.CommitEdit();var targets=DeviceSelection.Targets(Visible(),DeviceGrid.SelectedItems.Cast<Device>());
        if(targets.Count==0)throw new InvalidOperationException("请勾选当前筛选结果中的设备，或使用 Ctrl / Shift 选择设备行。");
        if(managed && targets.Any(d=>!d.Managed))throw new InvalidOperationException("所选设备中有尚未认证的候选，请先认证。");
        foreach(var d in targets)d.IgnoreFingerprint=IgnoreSshFingerprint.IsChecked==true;
        return targets;
    }
    void RefreshSelectionSummary()
    {
        if(deviceView is null || SelectionSummary is null)return;var visible=Visible();
        SelectionSummary.Text=$"共 {devices.Count} 台 · 筛选 {visible.Count} 台 · 勾选 {visible.Count(d=>d.Selected)} 台 · 行选择 {DeviceGrid.SelectedItems.Count} 台";
    }
    private void FilterChanged(object sender,RoutedEventArgs e){if(deviceView is null)return;DeviceGrid.CommitEdit();DeviceGrid.CommitEdit();deviceView.Refresh();RefreshSelectionSummary();}
    private void SelectVisibleClick(object sender,RoutedEventArgs e){foreach(var d in Visible())d.Selected=true;RefreshSelectionSummary();}
    private void InvertVisibleClick(object sender,RoutedEventArgs e){foreach(var d in Visible())d.Selected=!d.Selected;RefreshSelectionSummary();}
    private void ClearSelectionClick(object sender,RoutedEventArgs e){foreach(var d in devices)d.Selected=false;DeviceGrid.UnselectAll();RefreshSelectionSummary();}
    private void DeviceEdited(object sender,DataGridRowEditEndingEventArgs e)=>Dispatcher.InvokeAsync(Save);
    private void DefaultCredentialsClick(object sender,RoutedEventArgs e)
    {
        var c=Dialogs.Credentials(this,"默认登录",out bool save,defaultLogin,true);if(c is null)return;
        if(c.Username.Length==0){MessageBox.Show(this,"用户名不能为空。");return;}
        defaultLogin=c;if(save)vault.SaveDefault(c);else vault.ClearDefault();RefreshDefaultLabel();Log("默认登录已配置，账户信息保存在本机。");
    }
    private void ClearDefaultCredentialsClick(object sender,RoutedEventArgs e){defaultLogin=null;defaultEnvironmentLogins.Clear();vault.ClearDefault();RefreshDefaultLabel();Log("已清除默认登录；各设备单独保存的登录设置仍可使用。");}
    private void DeviceCredentialsClick(object sender,RoutedEventArgs e)
    {
        try{var d=Current();if(d.Transport=="ssh"){EditDeviceEnvironmentLogins(d);return;}var c=Dialogs.Credentials(this,d.Address+" · "+d.Mode,out bool save,ResolveCredentials(d));if(c is null)return;if(!d.Managed)throw new InvalidOperationException("候选设备请先使用默认账密或认证按钮登记。");RememberLogin(d,d.Mode,c,save);Log("已更新所选设备 "+d.Mode+" 的登录设置。");}catch(Exception error){MessageBox.Show(this,error.Message);}
    }
    bool TrustHost(string address,string fingerprint)=>Dispatcher.Invoke(()=>MessageBox.Show(this,$"SSH 主机：{address}\n指纹：{fingerprint}\n核对后信任并继续认证？","确认 SSH 身份",MessageBoxButton.YesNo)==MessageBoxResult.Yes);
    async Task Register(Device candidate,Credentials credentials,bool remember,CancellationToken token,bool primaryOnly=false)
    {
        void Progress(string phase)=>Dispatcher.InvokeAsync(()=>
        {
            candidate.State="认证 · "+phase;candidate.CommandSummary=phase;
            StatusBar.Text=candidate.Address+" · "+phase;Log(candidate.Address+" · "+phase);
        });
        var actualCredentials=LoginProfiles.Plain(credentials);
        var login=ConnectionCredentialsFor(candidate,credentials,primaryOnly,(_,_,actual)=>actualCredentials=actual);
        var response=await ssh.Authenticate(Endpoint(candidate),login,candidate,TrustHost,Progress,token);
        string id=Protocol.Text(response.Data,"device_id");var existing=devices.FirstOrDefault(d=>d.Managed && d.DeviceId==id);var device=existing??candidate;
        if(candidate.Transport=="ssh" && !candidate.IgnoreFingerprint && device.HostKeys.TryGetValue(response.Mode,out var prior) && prior!=response.Fingerprint)throw new InvalidOperationException("此设备环境的密钥与已登记值不同。");
        PreserveLoginForSwitch(device);
        if(candidate.Transport=="ssh")device.HostKeys[response.Mode]=response.Fingerprint;
        device.Transport=candidate.Transport;device.BaudRate=candidate.BaudRate;device.SerialPorts=candidate.SerialPorts;device.Address=candidate.Address;device.Selected|=candidate.Selected;
        Update(device,response);RememberLogin(device,response.Mode,actualCredentials,remember ||
            new[]{vault.LoadDefault(),vault.LoadDefaultEnvironment(response.Mode),vault.LoadConnection(device)}.Any(saved=>saved is not null && LoginProfiles.Same(saved,actualCredentials)));
        if(existing is not null && existing!=candidate){candidate.DeviceId=id;candidate.Hostname=device.Hostname;candidate.Mode=device.Mode;candidate.Name=device.Name;devices.Remove(candidate);}Save();Log("已登记 "+(device.Hostname.Length>0?device.Hostname:device.Name)+" · "+device.Mode);
    }
    async Task AuthenticateSelected(bool forceDefault)
    {
        if(batching)return;
        try
        {
            var targets=SelectedTargets(false);Credentials? common=forceDefault?defaultLogin:null;bool remember=false;
            if(forceDefault && targets.Any(d=>DefaultCredentialsFor(d.Mode) is null))throw new InvalidOperationException("请先设置通用默认登录，或所选环境的默认登录。");
            if(!forceDefault && targets.Any(d=>ResolveCredentials(d) is null))common=Dialogs.Credentials(this,"所选设备",out remember,defaultLogin);
            if(!forceDefault && targets.Any(d=>ResolveCredentials(d) is null) && common is null)return;
            var credentials=targets.ToDictionary(d=>d,d=>forceDefault?DefaultCredentialsFor(d.Mode)!:(ResolveCredentials(d)??common!));
            using var auth=CancellationTokenSource.CreateLinkedTokenSource(closing.Token);authenticating=auth;CancelAuthenticationButton.IsEnabled=true;
            try
            {
                await RunSelected("认证并读取主机名",targets,false,async d=>
                {
                    auth.Token.ThrowIfCancellationRequested();await Register(d,credentials[d],remember,auth.Token,forceDefault);
                    return new{hostname=d.Hostname,device_id=d.DeviceId,mode=d.Mode};
                });
            }
            finally{authenticating=null;CancelAuthenticationButton.IsEnabled=false;}
        }catch(Exception error){MessageBox.Show(this,error.Message,"认证未完成");}
    }
    private async void CancelAuthenticationClick(object sender,RoutedEventArgs e)
    {
        queue.Stop();if(authenticating is {} auth)await auth.CancelAsync();
        StatusBar.Text="认证已取消，正在释放本次串口连接。";
    }
    private async void DefaultConnectClick(object sender,RoutedEventArgs e)=>await AuthenticateSelected(true);
    async Task RunSelected(string label,IReadOnlyList<Device> targets,bool writes,Func<Device,Task<object>> execute,bool confirm=true,bool? pilot=null)
    {
        if(batching)throw new InvalidOperationException("已有批量任务运行，请等待或停止后续设备。");
        if(writes && confirm && MessageBox.Show(this,$"操作：{label}\n设备数：{targets.Count}\n目标：{string.Join(", ",targets.Select(d=>d.Hostname.Length>0?d.Hostname:d.Address))}\n确认发送？","批量操作",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
        var results=new List<object>();int succeeded=0,failed=0;batching=true;
        try
        {
            await queue.Run(targets,int.Parse(((ComboBoxItem)Concurrency.SelectedItem).Content.ToString()!),async d=>
            {
                string running=label+" · 执行中";d.State=running;d.LastCommand=label;d.CommandSummary="执行中";
                try{var value=await execute(d);results.Add(new{device=d.Hostname,address=d.Address,ok=true,data=value});succeeded++;d.CommandSummary="已返回";d.CommandDetail=JsonSerializer.Serialize(value,Pretty);if(d.State==running)d.State=label+" · 已返回";Log((d.Hostname.Length>0?d.Hostname:d.Address)+" · "+label+" 完成");return true;}
                catch(Exception error){results.Add(new{device=d.Hostname,address=d.Address,ok=false,error=error.Message});failed++;d.CommandSummary=error is OperationCanceledException?"已取消":"操作失败";d.CommandDetail=error.Message;d.State=error is OperationCanceledException?(label.StartsWith("认证")?"认证已取消":"已取消结果观察"):error is TransientConnectionException && writes?"提交结果未知，请查询":"操作失败";Log(d.Address+" · "+label+" · "+error.Message);return false;}
                finally{Show(JsonSerializer.SerializeToElement(results));Save();}
            },d=>{d.State="尚未执行";Log(d.Address+" · 后续操作已停止");},pilot:pilot??writes,stopOnFailure:writes);
            StatusBar.Text=$"{label}：成功 {succeeded}，失败 {failed}，未执行 {targets.Count-succeeded-failed}。";
        }finally{batching=false;RefreshSelectionSummary();}
    }
    async Task RunCliSelected(string operation)
    {
        if(batching)return;var targets=SelectedTargets();string[] args=operation is "plan" or "download" or "recover"?VersionArguments():[];
        bool writes=operation is "recover" or "retry" or "cancel";var credentials=targets.ToDictionary(d=>d,CredentialsFor);
        await RunSelected(operation,targets,writes,async d=>
        {
            string[] arguments=args;
            if(operation=="retry")
            {
                var s=await ssh.Execute(Endpoint(d),credentials[d],d,"status",[],cancellation:closing.Token);
                if(!s.Data.GetProperty("actions").GetProperty("can_retry").GetBoolean())throw new InvalidOperationException("任务不满足写盘前网络故障重试条件。");
                arguments=["--job",Protocol.Text(s.Data.GetProperty("job"),"job_id")];
            }
            if(operation=="recover")
            {
                var plan=await ssh.Execute(Endpoint(d),credentials[d],d,"plan",[..args,"--recovery"],cancellation:closing.Token);
                if(!plan.Data.GetProperty("write_allowed").GetBoolean())throw new InvalidOperationException("设备拒绝恢复计划。");
                string[] ranges=string.IsNullOrWhiteSpace(ScanRange.Text)?[]:[ScanRange.Text.Trim()];foreach(string range in ranges)Scanner.Expand(range);
                var task=new PendingTask(d.DeviceId,Guid.NewGuid().ToString("D"),Protocol.Text(plan.Data,"release"),Protocol.Text(plan.Data,"target"),"recover",Ranges:ranges);pendingTasks.Add(task);Save();
                if(!await Observe(d,task))throw new InvalidOperationException("恢复失败，请在 Rescue 中检查。");return new{task.JobId,stage="succeeded"};
            }
            var result=await ssh.Execute(Endpoint(d),credentials[d],d,operation,arguments,writes,cancellation:closing.Token);Update(d,result);return result.Data;
        });
    }
    private void CommandPresetChanged(object sender,SelectionChangedEventArgs e){if(CommandPreset?.SelectedItem is ArmHpc.Ota.Core.CommandPreset preset && CommandLine is not null)CommandLine.Text=preset.Command;}
    private async void SendCommandClick(object sender,RoutedEventArgs e)
    {
        if(batching)return;
        try
        {
            var request=ArmHpcCommands.Parse(CommandLine.Text);var targets=SelectedTargets();
            if(request.Interactive)
            {
                if(targets.Count!=1)throw new InvalidOperationException("交互配置需要逐台完成，请只选择一台。");
                new TerminalWindow(this,ssh,targets[0],CredentialsFor(targets[0]),request).Show();return;
            }
            var options=new CommandBatchOptions(int.Parse(((ComboBoxItem)Concurrency.SelectedItem).Content.ToString()!),IgnoreUnknownCommand.IsChecked==true,CommandPilot.IsChecked==true);
            if(request.Writes && MessageBox.Show(this,$"命令：{request.Label}\n设备数：{targets.Count}，并发：{options.Concurrency}\n未知结果继续：{options.IgnoreUnknown}\n确认发送？","并发命令",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
            var credentials=targets.ToDictionary(d=>d,CredentialsFor);var results=new List<CommandOutcome>();batching=true;
            try
            {
                var report=await CommandBatch.Run(targets,request,options,async d=>
                {
                    d.State="命令发送中";d.LastCommand=request.Label;d.CommandSummary="发送中";var reply=await ssh.ExecuteArmHpc(Endpoint(d),credentials[d],d,request,closing.Token,new(180,string.IsNullOrWhiteSpace(ScanRange.Text)?[]:[ScanRange.Text.Trim()]),stage=>Dispatcher.Invoke(()=>{d.State=stage;d.CommandSummary=stage;Log(d.Address+" · "+stage);}));
                    if(reply.Hostname.Length>0)d.Hostname=reply.Hostname;d.Mode=reply.Mode;return reply;
                },result=>Dispatcher.Invoke(()=>
                {
                    results.Add(result);var d=targets.Single(d=>d.DeviceId==result.DeviceId);
                    d.State=result.Status switch {"succeeded"=>result.Confirmation=="reboot_verified"?"重启已验证":"命令返回成功","unknown"=>result.UnknownIgnored?"结果未知 · 继续队列":"结果未知 · 暂停队列","skipped"=>"未发送",_=>"命令失败"};
                    d.CommandSummary=d.State+(result.ExitCode is not null?" · exit="+result.ExitCode:"");
                    d.CommandDetail="状态："+result.Status+"\n确认："+result.Confirmation+"\n退出码："+result.ExitCode+"\n"+result.Output+"\n"+result.Error;
                    Show(JsonSerializer.SerializeToElement(results));Log(d.Address+" · "+d.State);Save();
                }),queue,closing.Token);
                Show(JsonSerializer.SerializeToElement(report));StatusBar.Text=$"命令批次：成功 {report.Succeeded}，失败 {report.Failed}，未知 {report.Unknown}，未发送 {report.Skipped}。";
            }finally{batching=false;RefreshSelectionSummary();}
        }catch(Exception error){MessageBox.Show(this,error.Message,"命令未完成");}
    }
    private void TerminalClick(object sender,RoutedEventArgs e){try{var d=Current();if(!d.Managed)throw new InvalidOperationException("请先认证设备。");new TerminalWindow(this,ssh,d,CredentialsFor(d)).Show();}catch(Exception error){MessageBox.Show(this,error.Message);}}
    async Task MaintainSelected()
    {
        if(batching)return;var selected=SelectedTargets();
        if(selected.Any(d=>d.Transport=="ssh" && !d.IgnoreFingerprint && (!d.HostKeys.ContainsKey("system") || !d.HostKeys.ContainsKey("rescue"))))throw new InvalidOperationException("工具更新前请登记所选设备两种环境的 SSH 指纹。");
        string included=System.IO.Path.Combine(AppContext.BaseDirectory,"maintenance/maintenance.tar.xz");
        var picker=new OpenFileDialog{Filter="已签名维护包|maintenance.tar.xz|XZ archive|*.tar.xz",FileName=System.IO.File.Exists(included)?included:""};if(picker.ShowDialog(this)!=true)return;
        string[] ranges=string.IsNullOrWhiteSpace(ScanRange.Text)?[]:[ScanRange.Text.Trim()];foreach(string range in ranges)Scanner.Expand(range);
        await RunSelected("自动更新 OTA 工具",selected,true,async d=>
        {
            var existing=automaticTasks.FirstOrDefault(t=>t.DeviceId==d.DeviceId && !t.Terminal);
            if(existing is not null && !existing.Options.ToolsOnly)throw new InvalidOperationException("请先继续已有系统升级任务。");
            AutomaticTask task;
            if(existing is null)
            {
                task=AutomaticTask.Create(d.DeviceId,new UpgradeOptions("",Bundle:picker.FileName,Ranges:ranges,ToolsOnly:true));automaticTasks.Add(task);
            }
            else
            {
                JsonElement? remote=null;
                if(TaskFiles.Digest(picker.FileName)!=existing.Options.BundleSha256)
                    remote=await ssh.MaintenanceStatus(Endpoint(d),CredentialsFor(d),d,closing.Token);
                var selection=TaskFiles.SelectTools(existing,picker.FileName,remote);
                int index=automaticTasks.FindIndex(t=>t.TaskId==existing.TaskId);
                automaticTasks[index]=selection.Superseded??selection.Task;
                if(selection.Superseded is not null)automaticTasks.Add(selection.Task);
                task=selection.Task;Log(d.Address+" · "+(selection.Superseded is null?"维护包路径已更新，继续原任务 ID":"旧本地观察已保留，使用所选新包创建新维护"));
            }
            Save();
            if(!await RunAutomatic(d,task))throw new InvalidOperationException("工具维护未成功。");return new{task.TaskId,stage="succeeded"};
        });
    }
}
