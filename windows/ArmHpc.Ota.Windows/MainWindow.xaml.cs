// SPDX-License-Identifier: GPL-3.0-only
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using ArmHpc.Ota.Core;
using Microsoft.Win32;

namespace ArmHpc.Ota.Windows;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<Device> devices = [];
    private readonly Vault vault;
    private readonly ConnectionRouter ssh = new();
    private readonly BatchQueue queue = new();
    private readonly Dictionary<string, Credentials> sessionCredentials = [];
    private readonly Dictionary<string, JsonElement> latestStatus = [];
    private readonly List<PendingTask> pendingTasks = [];
    private readonly List<MaintenanceTask> maintenanceTasks = [];
    private readonly CancellationTokenSource closing = new();
    private CancellationTokenSource? scanning;
    private bool batching;
    private readonly List<AutomaticTask> automaticTasks = [];
    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };

    public MainWindow() : this(null) { }
    internal MainWindow(string? storage)
    {
        vault = new Vault(storage);
        InitializeComponent();
        foreach (var device in vault.LoadDevices()) { device.Selected = false; devices.Add(device); }
        InitializeManagement();
        pendingTasks.AddRange(vault.LoadTasks());
        maintenanceTasks.AddRange(vault.LoadMaintenance());
        automaticTasks.AddRange(vault.LoadAutomatic());
        int count = pendingTasks.Count(task => !task.Terminal);
        if (count > 0) StatusBar.Text = $"有 {count} 个持久任务可继续观察；重试使用原请求 ID。";
    }
    private void Log(string message) => Dispatcher.Invoke(() => { LogText.AppendText(DateTime.Now.ToString("HH:mm:ss") + " " + message + Environment.NewLine); LogText.ScrollToEnd(); });
    private void Show(JsonElement value) => ResultText.Text = JsonSerializer.Serialize(value, Pretty);
    private Device Current() => DeviceGrid.SelectedItem as Device ?? throw new InvalidOperationException("请先选择设备。");
    private static Endpoint Endpoint(Device device) => new(device.Address, device.Port);
    private void Save() { vault.SaveDevices(devices); vault.SaveTasks(pendingTasks); vault.SaveMaintenance(maintenanceTasks); vault.SaveAutomatic(automaticTasks); }
    private string TargetName => ((ComboBoxItem)Target.SelectedItem).Content.ToString()!;
    private string[] VersionArguments() => string.IsNullOrWhiteSpace(Release.Text) ? ["--target", TargetName] : ["--target", TargetName, "--release", Release.Text.Trim()];
    private Credentials CredentialsFor(Device device)
    {
        device.IgnoreFingerprint=IgnoreSshFingerprint.IsChecked==true;
        if (sessionCredentials.TryGetValue(device.DeviceId+"/"+device.Transport, out var cached)) return cached;
        var stored = (device.Managed ? vault.LoadConnection(device) : null)??defaultLogin;
        if (stored is not null) { sessionCredentials[device.DeviceId+"/"+device.Transport] = stored; return stored; }
        var credentials = Dialogs.Credentials(this, device.Address, out bool remember) ?? throw new OperationCanceledException("认证已取消。");
        if (device.Managed) { sessionCredentials[device.DeviceId+"/"+device.Transport] = credentials; if (remember) vault.SaveConnection(device, credentials); }
        return credentials;
    }

    private void Update(Device device, RemoteResult response)
    {
        device.Mode = response.Mode;
        if(response.Hostname.Length>0){device.Hostname=response.Hostname;device.HostnameSource=device.Transport=="serial"?"串口":"SSH";}
        if(response.Network is not null){device.MacAddress=response.Network.MacAddress;device.NetworkDetail=response.Network.Detail;}
        var status = response.Data;
        if (!status.TryGetProperty("agent_version", out _) || !status.TryGetProperty("device_id", out _)) return;
        string id = Protocol.Text(status, "device_id");
        latestStatus[id] = status;
        var clock=ClockPresentation.Describe(status,DateTimeOffset.Now);
        device.ClockStatus=clock.Caption;device.ClockDetail=clock.Detail;
        device.DeviceId = id; device.Board = Protocol.Text(status, "board");
        if (string.IsNullOrEmpty(device.Name)) device.Name = device.Hostname.Length>0?device.Hostname:id[..Math.Min(12, id.Length)];
        var versions = new List<string>();
        if (status.TryGetProperty("confirmed", out var confirmed))
            foreach (var entry in confirmed.EnumerateObject())
                if (entry.Value.TryGetProperty("boot", out var boot)) versions.Add(entry.Name + ":" + Protocol.Text(boot, "release"));
        device.Version = string.Join(" / ", versions);
        device.SystemVersion = versions.FirstOrDefault(v=>v.StartsWith("system:"))?.Substring(7)??"未确认";
        device.RescueSlot = status.TryGetProperty("rescue_slot",out var slot)?slot.GetString()??"":"";
        device.RescueVersion = (versions.FirstOrDefault(v=>v.StartsWith("rescue:"))?.Substring(7)??"未确认")+" · "+device.RescueSlot;
        if (status.TryGetProperty("tools",out var tools) && tools.TryGetProperty("consistent",out var consistency) && !consistency.GetBoolean()) device.State="工具维护未完成";
        if (status.TryGetProperty("job", out var job) && job.ValueKind != JsonValueKind.Null)
        {
            int? percent = JobMonitor.Progress(job);
            device.State = Protocol.Text(job, "stage") + (percent is null ? "" : $" · {percent}%");
        }
        else if (status.TryGetProperty("write_authorized", out var allowed)) device.State = allowed.GetBoolean() ? "就绪" : "操作受限";
        else if (status.TryGetProperty("hardware_gate", out var gate) && !gate.GetProperty("passed").GetBoolean()) device.State = "操作受限";
        else device.State = "就绪";
        if (status.TryGetProperty("tools",out var mt) && mt.TryGetProperty("consistent",out var ok) && !ok.GetBoolean()) device.State="工具维护未完成";
    }

    private async void ScanClick(object sender, RoutedEventArgs e)
    {
        if(batching || authenticating is not null){StatusBar.Text="请等待当前操作完成后扫描。";return;}
        scanning?.Cancel();
        using var session=CancellationTokenSource.CreateLinkedTokenSource(closing.Token);scanning=session;
        try
        {
            var found=await Scanner.ScanWithNames(ScanRange.Text,22,
                (done,total)=>Dispatcher.Invoke(()=>{if(scanning==session)StatusBar.Text=$"扫描 SSH {done}/{total} · 不登录设备";}),
                (done,total)=>Dispatcher.Invoke(()=>{if(scanning==session)StatusBar.Text=$"查询 DNS/mDNS 名称 {done}/{total}";}),
                host=>Dispatcher.Invoke(()=>{if(scanning==session && !session.IsCancellationRequested)DeviceInventory.ApplyDiscovery(devices,host);}),session.Token);
            if(scanning==session){StatusBar.Text=$"发现 {found.Count} 个 SSH 候选，{found.Count(h=>h.Hostname.Length>0)} 个有 DNS/mDNS 名称；扫描未登录设备。";Save();}
        }
        catch(OperationCanceledException){if(scanning==session)StatusBar.Text="扫描停止。";}
        catch(Exception error){if(scanning==session)MessageBox.Show(this,error.Message,"扫描失败");}
        finally{if(scanning==session)scanning=null;}
    }
    private void StopScanClick(object sender, RoutedEventArgs e) => scanning?.Cancel();
    private void AddClick(object sender, RoutedEventArgs e)
    {
        if (!IPAddress.TryParse(ManualAddress.Text.Trim(), out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) { MessageBox.Show(this, "请输入有效 IPv4 地址。"); return; }
        if (!devices.Any(d => d.Address == ip.ToString())) devices.Add(new Device { Address = ip.ToString() });
    }
    private void ImportClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "设备 CSV|*.csv" };
        if (dialog.ShowDialog(this) != true) return;
        try { foreach (var device in Csv.Import(File.ReadAllText(dialog.FileName))) if (!devices.Any(d => d.Address == device.Address && d.Port == device.Port)) devices.Add(device); }
        catch (Exception error) { MessageBox.Show(this, error.Message, "导入失败"); }
    }
    private void ExportClick(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Filter = "设备 CSV|*.csv", FileName = "armhpc-devices.csv" };
        if (dialog.ShowDialog(this) == true) File.WriteAllText(dialog.FileName, Csv.Export(devices));
    }
    private async void ConnectClick(object sender,RoutedEventArgs e)=>await AuthenticateSelected(false);
    private void PinsClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var device = Current();
            if (!device.Managed) throw new InvalidOperationException("先认证并获取持久设备 ID。");
            if(device.Transport=="serial")throw new InvalidOperationException("串口连接通过持久设备 ID 核对身份；SSH 指纹用于 SSH 连接。");
            foreach (string mode in new[] { "system", "rescue" })
            {
                string? value = Dialogs.Input(this, "SSH 身份 · " + mode, "输入经可信来源核对的 SHA256 主机密钥指纹。留空可清除此环境登记。", device.HostKeys.GetValueOrDefault(mode, ""));
                if (value is null) return;
                if (value.Length == 0) device.HostKeys.Remove(mode);
                else if (Regex.IsMatch(value, "^SHA256:[A-Za-z0-9+/]{43}$")) device.HostKeys[mode] = value;
                else throw new ArgumentException("SHA256 指纹格式不正确。");
            }
            Save(); Log("已更新 " + device.Name + " 的两套 SSH 身份。");
        }
        catch (Exception error) { MessageBox.Show(this, error.Message); }
    }
    private async void CommandClick(object sender,RoutedEventArgs e)
    {try{await RunCliSelected(((Button)sender).Tag.ToString()!);}catch(Exception error){MessageBox.Show(this,error.Message,"批量 CLI 操作未完成");}}
    private async void BootstrapClick(object sender,RoutedEventArgs e)
    {
        if(batching)return;
        try
        {
            var targets=SelectedTargets();var credentials=targets.ToDictionary(d=>d,CredentialsFor);
            string? initial=null,anchor=null;
            foreach(var d in targets)
            {
                var preview=await ssh.Execute(Endpoint(d),credentials[d],d,"bootstrap",[],cancellation:closing.Token);
                if(preview.Data.TryGetProperty("write_allowed",out var allowed) && !allowed.GetBoolean())throw new InvalidOperationException(d.Address+" 接入写盘未授权。");
                bool factory=preview.Data.TryGetProperty("factory_prepartitioned",out var pre)&&pre.GetBoolean();
                if(!factory && initial is null)
                {
                    initial=Dialogs.Input(this,"批量初始恢复基线","输入适配这些设备的已签名基线清单 URL 或设备文件路径：");if(initial is null)return;
                    anchor=Dialogs.Input(this,"批量固定引导包","输入已签名固定引导清单 URL 或设备文件路径：");if(anchor is null)return;
                }
            }
            await RunSelected("OTA 接入",targets,true,async d=>
            {
                var args=new List<string>{"--apply"};if(initial is not null)args.AddRange(["--manifest",initial,"--anchor-manifest",anchor!]);
                var result=await ssh.Execute(Endpoint(d),credentials[d],d,"bootstrap",args,true,cancellation:closing.Token);Update(d,result);return result.Data;
            },pilot:BootstrapPilot.IsChecked==true);
        }catch(Exception error){MessageBox.Show(this,error.Message,"批量接入未完成");}
    }
    private async void BatchClick(object sender, RoutedEventArgs e)
    {
        if (batching) return;
        try
        {
            DeviceGrid.CommitEdit(); DeviceGrid.CommitEdit();
            var selected = SelectedTargets().ToArray();
            if (selected.Length == 0 || selected.Any(d => !d.Managed)) throw new InvalidOperationException("请勾选已认证设备。");
            if (selected.Any(d => d.Transport=="ssh" && !d.IgnoreFingerprint && (!d.HostKeys.ContainsKey("system") || !d.HostKeys.ContainsKey("rescue")))) throw new InvalidOperationException("批量更新前请登记正常系统及 Rescue 的 SSH 指纹，以便重启后安全重连。");
            string[] ranges = string.IsNullOrWhiteSpace(ScanRange.Text) ? [] : [ScanRange.Text.Trim()];
            foreach (string range in ranges) Scanner.Expand(range);
            string[] arguments = VersionArguments();
            var approved = new Dictionary<string, string[]>();
            foreach (var device in selected)
            {
                CredentialsFor(device);
                var identity = await ssh.Execute(Endpoint(device), CredentialsFor(device), device, "status", [], cancellation: closing.Token);
                if (!identity.Data.TryGetProperty("capabilities", out var capabilities) || !capabilities.GetProperty("idempotent_apply").GetBoolean())
                    throw new InvalidOperationException(device.Name + " 需要安装支持持久重试的 OTA runtime。");
                var plan = await ssh.Execute(Endpoint(device), CredentialsFor(device), device, "plan", arguments, cancellation: closing.Token);
                Show(plan.Data);
                if (!plan.Data.GetProperty("write_allowed").GetBoolean()) throw new InvalidOperationException(device.Name + "  当前不允许执行该操作。");
                approved[device.DeviceId] = ["--target", Protocol.Text(plan.Data, "target"), "--release", Protocol.Text(plan.Data, "release")];
                Log(device.Name + " · 计划已核对。");
            }
            if (MessageBox.Show(this, $"确认更新 {selected.Length} 台设备？第一台成功后继续；写盘后的任务不能中止。\n重连范围：{string.Join(", ", ranges.DefaultIfEmpty("仅原 IP"))}", "执行已预览计划", MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
            batching = true; StartBatchButton.IsEnabled = false;
            int concurrency = int.Parse(((ComboBoxItem)Concurrency.SelectedItem).Content.ToString()!);
            await queue.Run(selected, concurrency, async device =>
            {
                try
                {
                    string[] values = approved[device.DeviceId];
                    var task = new PendingTask(device.DeviceId, Guid.NewGuid().ToString("D"), values[3], values[1], Ranges: ranges);
                    pendingTasks.Add(task); Save();
                    return await Observe(device, task);
                }
                catch (Exception error) { device.State = "需检查"; Log(device.Name + " · " + error.Message); return false; }
            }, device => { device.State = "队列暂停"; Log(device.Name + " · 尚未启动。"); });
            Save(); StatusBar.Text = queue.Stopped ? "队列已停止；已启动设备仍由设备服务完成。" : "批量任务完成。";
        }
        catch (Exception error) { MessageBox.Show(this, error.Message, "批量未启动"); }
        finally { batching = false; StartBatchButton.IsEnabled = true; }
    }
    private async Task<bool> Observe(Device device, PendingTask task)
    {
        var credentials = CredentialsFor(device);
        return await JobMonitor.Run(task,
            async () =>
            {
                var response = await ssh.Execute(Endpoint(device), credentials, device, "status", ["--job", task.JobId], cancellation: closing.Token);
                Update(device, response);
                return response.Data;
            },
            async () => (await ssh.Execute(Endpoint(device), credentials, device, task.Operation,
                ["--target", task.Target, "--release", task.Release, "--request-id", task.JobId], true, cancellation: closing.Token)).Data,
            async () =>
            {
                var endpoint = await ssh.Reconnect(device, credentials, task.Ranges ?? [], closing.Token);
                if (endpoint is not null) { device.Address = endpoint.Address; Save(); }
            }, (stage, percent) =>
            {
                int index = pendingTasks.FindIndex(item => item.JobId == task.JobId);
                if (index >= 0) pendingTasks[index] = task with { Stage = stage, Percent = percent };
                string state = stage + (percent is null ? "" : $" · {percent}%");
                if (device.State != state) Log(device.Name + " · " + state);
                device.State = state; Save();
            }, closing.Token);
    }

    private async void ResumeTasksClick(object sender, RoutedEventArgs e)
    {
        if (batching) return;
        try
        {
            var targetIds=SelectedTargets().Select(d=>d.DeviceId).ToHashSet();batching=true;
            foreach(var automation in automaticTasks.Where(t=>!t.Terminal && targetIds.Contains(t.DeviceId)).ToArray())
                await RunAutomatic(devices.Single(d=>d.DeviceId==automation.DeviceId),automation);
            foreach(var maintenance in maintenanceTasks.Where(t=>!t.Terminal && targetIds.Contains(t.DeviceId)).ToArray())
                await ObserveMaintenance(devices.Single(d=>d.DeviceId==maintenance.DeviceId),maintenance);
            var active = pendingTasks.Where(task => !task.Terminal && targetIds.Contains(task.DeviceId)).ToArray();
            if (active.Length == 0) { StatusBar.Text = "没有待观察的持久任务。"; return; }
            foreach (var task in active)
            {
                var device = devices.Single(item => item.DeviceId == task.DeviceId);
                if (device.Transport=="ssh" && !device.IgnoreFingerprint && (!device.HostKeys.ContainsKey("system") || !device.HostKeys.ContainsKey("rescue")))
                    throw new InvalidOperationException("继续前请登记 " + device.Name + " 的两套 SSH 身份。");
                CredentialsFor(device);
            }
            batching = true; StartBatchButton.IsEnabled = false;
            using var semaphore = new SemaphoreSlim(int.Parse(((ComboBoxItem)Concurrency.SelectedItem).Content.ToString()!));
            await Task.WhenAll(active.Select(async task =>
            {
                await semaphore.WaitAsync(closing.Token);
                try { await Observe(devices.Single(item => item.DeviceId == task.DeviceId), task); }
                finally { semaphore.Release(); }
            }));
            StatusBar.Text = "持久任务观察结束；可按设备查询详细状态。";
        }
        catch (Exception error) { MessageBox.Show(this, error.Message, "任务观察停止"); }
        finally { batching = false; StartBatchButton.IsEnabled = true; }
    }

    private async void ToolsStatusClick(object sender,RoutedEventArgs e)
    {try{await RunSelected("工具维护状态",SelectedTargets(),false,async d=>await ssh.MaintenanceStatus(Endpoint(d),CredentialsFor(d),d,closing.Token));}catch(Exception error){MessageBox.Show(this,error.Message);}}
    private async void ToolsRollbackClick(object sender,RoutedEventArgs e)
    {try{await RunSelected("回退工具维护",SelectedTargets(),true,async d=>await ssh.MaintenanceStatus(Endpoint(d),CredentialsFor(d),d,closing.Token,true));}catch(Exception error){MessageBox.Show(this,error.Message);}}
    private void PublishClick(object sender,RoutedEventArgs e)=>new PublishWindow {Owner=this}.Show();
    private async void SourceClick(object sender,RoutedEventArgs e)
    {
        try {
            var device=Current();if(!device.Managed)throw new InvalidOperationException("先认证设备。");
            string? url=Dialogs.Input(this,"内网更新源","输入 ota-index.json 的完整 HTTP/HTTPS URL：");if(url is null)return;
            var uri=new Uri(url);bool http=uri.Scheme=="http";
            if(MessageBox.Show(this,"登记更新源："+url+"\n"+(http?"明确允许此内网 HTTP 地址；更新仍必须通过签名验证。":"HTTPS 将验证证书和主机名。"),"确认更新源",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
            var arguments=new List<string>{"set","--url",url};if(http)arguments.Add("--allow-http");
            if(!http && MessageBox.Show(this,"是否导入此源的专用 CA 公共证书？","HTTPS CA",MessageBoxButton.YesNo)==MessageBoxResult.Yes)
            {
                var d=new OpenFileDialog{Filter="CA 公共证书|*.pem;*.crt"};if(d.ShowDialog(this)!=true)return;
                string uploaded=await ssh.Upload(Endpoint(device),CredentialsFor(device),device,d.FileName,closing.Token);arguments.AddRange(["--ca",uploaded]);
            }
            Show((await ssh.Execute(Endpoint(device),CredentialsFor(device),device,"source",arguments,true,cancellation:closing.Token)).Data);
            Show((await ssh.Execute(Endpoint(device),CredentialsFor(device),device,"source",["test"],cancellation:closing.Token)).Data);
        }catch(Exception error){MessageBox.Show(this,error.Message,"更新源未完成；旧版 agent 请先安装新版工具。");}
    }
    private void ToolsClick(object sender,RoutedEventArgs e)=>AutomaticToolsClick(sender,e);
    private async Task ObserveMaintenance(Device device,MaintenanceTask task)
    {
        for(int i=0;i<600;i++)
        {
            closing.Token.ThrowIfCancellationRequested();
            try {
                var value=await ssh.MaintenanceStatus(Endpoint(device),CredentialsFor(device),device,closing.Token);
                if(value.TryGetProperty("maintenance",out var maintenance) && maintenance.ValueKind==JsonValueKind.Object)
                {
                    if(Protocol.Text(maintenance,"task_id")!=task.RequestId)throw new InvalidOperationException("维护请求 ID 不匹配。");
                    string stage=Protocol.Text(maintenance,"stage");int index=maintenanceTasks.FindIndex(t=>t.RequestId==task.RequestId);
                    if(index>=0)maintenanceTasks[index]=task with {Stage=stage};device.State="工具 · "+stage;Save();Show(value);
                    if(stage is "succeeded" or "rolled-back" or "incomplete")return;
                }
            } catch(Exception error) when(error is IOException or Renci.SshNet.Common.SshException or System.Net.Sockets.SocketException)
            {
                var endpoint=await ssh.Reconnect(device,CredentialsFor(device),task.Ranges,closing.Token,true);
                if(endpoint is not null){device.Address=endpoint.Address;Save();}
            }
            await Task.Delay(3000,closing.Token);
        }
        throw new TimeoutException("设备维护仍需检查；任务在设备端继续，可重新观察。");
    }
    private void PortsClick(object sender,RoutedEventArgs e)
    {
        try
        {
            string? port=Dialogs.Input(this,"添加 USB / 串口","可用端口："+string.Join(", ",SerialRunner.Ports())+"。输入设备的 COM 端口。", "COM8");
            if(port is null)return;if(!Regex.IsMatch(port,"^COM[1-9][0-9]*$",RegexOptions.IgnoreCase))throw new ArgumentException("COM 端口格式无效。");
            string? baud=Dialogs.Input(this,"串口速率","USB OTG 虚拟串口默认 115200；硬件 UART 按板卡实际配置。", "115200");if(baud is null)return;
            string? alternatives=Dialogs.Input(this,"重启后串口","显式允许的备用 COM 端口，以逗号分隔；留空只使用当前端口。", "");if(alternatives is null)return;
            var ports=alternatives.Split(',',StringSplitOptions.TrimEntries|StringSplitOptions.RemoveEmptyEntries);if(ports.Any(p=>!Regex.IsMatch(p,"^COM[1-9][0-9]*$",RegexOptions.IgnoreCase)))throw new ArgumentException("备用端口格式无效。");
            var device=new Device{Transport="serial",Address=port.ToUpperInvariant(),BaudRate=int.Parse(baud),SerialPorts=ports};devices.Add(device);DeviceGrid.SelectedItem=device;
        }catch(Exception error){MessageBox.Show(this,error.Message,"串口设置");}
    }
    private void DisconnectClick(object sender,RoutedEventArgs e){try{var d=Current();ssh.Disconnect(d);Log(d.Name+" · 串口已释放；设备服务任务继续。");}catch(Exception error){MessageBox.Show(this,error.Message);}}
    private async Task<bool> RunAutomatic(Device device,AutomaticTask task)
    {
        var connection=new UpgradeConnection(ssh,device,CredentialsFor(device),task.Options.Ranges??[]);
        var completed=await AutomaticUpgrade.Run(task,connection,value=>
        {
            int index=automaticTasks.FindIndex(t=>t.TaskId==value.TaskId);if(index>=0)automaticTasks[index]=value;else automaticTasks.Add(value);Save();
        },stage=>{device.State="自动 · "+stage;device.CommandSummary=device.State;Log(device.Name+" · "+stage);},closing.Token);
        var refreshDeadline=System.Diagnostics.Stopwatch.StartNew();
        while(refreshDeadline.Elapsed<TimeSpan.FromMinutes(3))
        {
            try
            {
                var status=await ssh.Execute(Endpoint(device),CredentialsFor(device),device,"status",[],cancellation:closing.Token);
                Update(device,status);Show(status.Data);Save();return completed.Stage=="succeeded";
            }
            catch(TransientConnectionException)
            {
                device.State="升级结果已记录 · 等待重连刷新";device.CommandSummary=device.State;Save();
                try{await ssh.Reconnect(device,CredentialsFor(device),task.Options.Ranges??[],closing.Token);}catch(TransientConnectionException){}
                await Task.Delay(3000,closing.Token);
            }
        }
        device.State=completed.Stage=="succeeded"?"升级已确认，待连接恢复后刷新":"失败待恢复，待连接恢复后刷新";
        device.CommandSummary=device.State;Save();return completed.Stage=="succeeded";
    }
    private async void AutomaticClick(object sender,RoutedEventArgs e)
    {
        if(batching)return;
        try
        {
            var selected=SelectedTargets().ToArray();
            if(selected.Any(d=>!d.Managed))throw new InvalidOperationException("请先认证所选设备。");
            if(selected.Any(d=>d.Transport=="ssh" && !d.IgnoreFingerprint && (!d.HostKeys.ContainsKey("system") || !d.HostKeys.ContainsKey("rescue"))))throw new InvalidOperationException("自动重启前请登记两种环境的 SSH 指纹。");
            var existing=automaticTasks.FirstOrDefault(t=>t.DeviceId==selected[0].DeviceId && !t.Terminal);
            if(selected.Length==1 && existing is not null)
            {
                if(existing.Options.Bundle is {} oldPath && !File.Exists(oldPath) && existing.Release is null)
                {
                    var relocation=new OpenFileDialog{Filter="原签名维护包（须匹配 SHA256）|maintenance.tar.xz|XZ archive|*.tar.xz",Title="原维护包已移动：选择相同内容以继续原任务"};
                    if(relocation.ShowDialog(this)!=true)return;
                    existing=TaskFiles.RelocateBundle(existing,relocation.FileName);
                    int index=automaticTasks.FindIndex(t=>t.TaskId==existing.TaskId);automaticTasks[index]=existing;Save();
                }
                batching=true;await RunAutomatic(selected[0],existing);return;
            }
            if(automaticTasks.Any(t=>selected.Any(d=>d.DeviceId==t.DeviceId) && !t.Terminal))throw new InvalidOperationException("请先继续所选设备已有的自动任务。");
            var dialog=new AutomaticWindow(this,Release.Text.Trim(),TargetName,ScanRange.Text.Trim());if(dialog.ShowDialog()!=true)return;
            // Serial package delivery uses the same signed engine on agent 0.3.4+.
            foreach(var device in selected)CredentialsFor(device);
            var pilot=AutomaticTask.Create(selected[0].DeviceId,dialog.Options!);var frozen=pilot.Options;
            if(MessageBox.Show(this,"设备数："+selected.Length+"\n本地包／源："+(dialog.Options!.Package??dialog.Options.Source)+"\n按需更新 OTA 工具，验证载荷并提交系统升级；设备会重启。第一台成功后继续，失败暂停队列。确认开始？","自动升级",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
            batching=true;int concurrency=int.Parse(((ComboBoxItem)Concurrency.SelectedItem).Content.ToString()!);
            await queue.Run(selected,concurrency,async device=>
            {
                try
                {
                    device.LastCommand="OTA 推送升级";device.CommandSummary="准备中";
                    var task=device.DeviceId==pilot.DeviceId?pilot:AutomaticTask.Create(device.DeviceId,frozen);automaticTasks.Add(task);Save();Log("自动升级任务："+task.TaskId);
                    bool success=await RunAutomatic(device,task);
                    if(success && device.DeviceId==pilot.DeviceId)frozen=frozen with {Release=automaticTasks.Single(t=>t.TaskId==task.TaskId).Release};
                    return success;
                }
                catch(Exception error){Log(device.Name+" · 自动流程暂停："+error.Message);return false;}
            },pilot:OtaPilot.IsChecked==true);
        }catch(Exception error){MessageBox.Show(this,error.Message,"自动流程暂停；可继续原任务，已提交的设备服务任务继续。");}
        finally{batching=false;}
    }
    private async void AutomaticToolsClick(object sender,RoutedEventArgs e)
    {try{await MaintainSelected();}catch(Exception error){MessageBox.Show(this,error.Message,"批量工具更新未完成");}}
    private void StopBatchClick(object sender, RoutedEventArgs e) { queue.Stop(); Log("停止后续设备；已启动设备任务继续执行。"); }
    private void SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        RefreshSelectionSummary();
        if (DeviceGrid.SelectedItem is Device device)
        {
            if (!string.IsNullOrWhiteSpace(device.CommandDetail)) ResultText.Text = device.CommandDetail;
            else if (latestStatus.TryGetValue(device.DeviceId, out var status)) Show(status);
        }
    }
    private void WindowClosing(object? sender, CancelEventArgs e)
    {
        queue.Stop(); scanning?.Cancel(); closing.Cancel(); Save(); sessionCredentials.Clear();
        // No remote cancellation: SSH/GUI exit cannot terminate the persistent device service.
    }
}
