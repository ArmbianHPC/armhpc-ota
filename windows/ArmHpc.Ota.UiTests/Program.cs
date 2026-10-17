// SPDX-License-Identifier: GPL-3.0-only
using System.Collections.ObjectModel;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using ArmHpc.Ota.Core;
using ArmHpc.Ota.Windows;

internal sealed class Suite
{
    readonly MainWindow window;
    readonly ObservableCollection<Device> devices;
    public Suite(MainWindow w){window=w;devices=(ObservableCollection<Device>)typeof(MainWindow).GetField("devices",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(w)!;}
    object? Call(string name,params object[] args){try{return typeof(MainWindow).GetMethod(name,BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(window,args);}catch(TargetInvocationException e){throw e.InnerException!;}}
    List<Device> Visible()=>((IEnumerable<Device>)Call("Visible")!).ToList();
    List<Device> SelectedTargets()=>((IEnumerable<Device>)Call("SelectedTargets",true)!).ToList();
    void SelectVisibleClick(object a,RoutedEventArgs b)=>Call("SelectVisibleClick",a,b);
    void ClearSelectionClick(object a,RoutedEventArgs b)=>Call("ClearSelectionClick",a,b);
    void Update(Device a,RemoteResult b)=>Call("Update",a,b);
    DataGrid DeviceGrid=>(DataGrid)window.FindName("DeviceGrid");
    TextBox HostFilter=>(TextBox)window.FindName("HostFilter");
    CheckBox ExactHostname=>(CheckBox)window.FindName("ExactHostname");
    ComboBox ModeFilter=>(ComboBox)window.FindName("ModeFilter");
    ComboBox CommandPreset=>(ComboBox)window.FindName("CommandPreset");
    TextBox CommandLine=>(TextBox)window.FindName("CommandLine");
    ComboBox Concurrency=>(ComboBox)window.FindName("Concurrency");
    CheckBox IgnoreUnknownCommand=>(CheckBox)window.FindName("IgnoreUnknownCommand");
    CheckBox CommandPilot=>(CheckBox)window.FindName("CommandPilot");
    CheckBox IgnoreSshFingerprint=>(CheckBox)window.FindName("IgnoreSshFingerprint");
    CheckBox OtaPilot=>(CheckBox)window.FindName("OtaPilot");
    CheckBox BootstrapPilot=>(CheckBox)window.FindName("BootstrapPilot");
    Button CancelAuthenticationButton=>(Button)window.FindName("CancelAuthenticationButton");
    internal int VerifyManagement()
    {
        int checks=0;
        void Check(bool value,string label){if(!value)throw new InvalidOperationException("GUI check failed: "+label);checks++;}
        string release = ApplicationVersion.Number;
        Check(release.StartsWith(typeof(Suite).Assembly.GetName().Version!.ToString(3)+"-"),"build revision is visible while numeric compatibility version remains stable");
        Check(window.Title == $"ARMHPC OTA {release} · 批量管理与命令", "window title matches the release assembly version");
        Check(((TextBlock)window.FindName("ApplicationVersionLabel")).Text == $"{release}   ·   SSH / USB 串口   ·   并发 1–8", "visible header matches the release assembly version");
        devices.Clear();DeviceGrid.UnselectAll();
        var a=new Device{DeviceId="a",Hostname="armhpc-rescue-72ac",Mode="rescue",Address="192.168.1.10"};
        var b=new Device{DeviceId="b",Hostname="armhpc-010f",Mode="system",Address="192.168.1.11"};devices.Add(a);devices.Add(b);
        Check(DeviceGrid.SelectionMode==DataGridSelectionMode.Extended,"multiple selection enabled");
        HostFilter.Text="rescue";Check(Visible().Count==1 && Visible()[0]==a,"hostname filter reaches bound collection");
        SelectVisibleClick(this,new());Check(a.Selected && !b.Selected,"select visible only");
        HostFilter.Text="010f";DeviceGrid.UnselectAll();bool noHidden=false;try{SelectedTargets();}catch(InvalidOperationException){noHidden=true;}Check(noHidden,"hidden checkbox never executes");
        DeviceGrid.SelectedItem=b;Check(SelectedTargets().Single()==b,"highlighted visible row becomes target");
        HostFilter.Text="ARMHPC-010F";ExactHostname.IsChecked=true;Check(Visible().Count==1,"exact case insensitive search");
        ModeFilter.SelectedIndex=2;Check(Visible().Count==0,"environment filter applied");
        ModeFilter.SelectedIndex=0;ExactHostname.IsChecked=false;HostFilter.Text="";ClearSelectionClick(this,new());Check(!a.Selected && !b.Selected && DeviceGrid.SelectedItems.Count==0,"clear checks and highlighted rows");
        SelectVisibleClick(this,new());Check(SelectedTargets().Count==2,"batch contains all visible selected hosts");
        Check(CommandPreset.Items.Count>=20 && ArmHpcCommands.Parse(CommandLine.Text) is not null,"preset binding and editor ready");
        Check(((Button)window.FindName("BackupStorageButton")).Content.ToString()=="备份与共享空间","backup and shared-storage entry is available in the OTA toolbar");
        Check(BackupStorageWindow.WorkflowStages.SequenceEqual(new[]{"导出原始备份","上位机压缩","校验压缩包","预览清理","确认清理"}),"backup workflow verifies the host archive before cleanup");
        Check(Concurrency.Items.Count==8,"all eight concurrency choices exposed");
        Check(IgnoreUnknownCommand.IsChecked!=true && CommandPilot.IsChecked!=true,"command policy defaults to parallel send without ignoring unknown");
        IgnoreUnknownCommand.IsChecked=true;CommandPilot.IsChecked=true;
        Check(IgnoreUnknownCommand.IsChecked==true && CommandPilot.IsChecked==true,"unknown continuation and pilot controls selectable");
        IgnoreUnknownCommand.IsChecked=false;CommandPilot.IsChecked=false;
        Check(IgnoreSshFingerprint.IsChecked!=true,"fingerprint validation enabled by default");
        IgnoreSshFingerprint.IsChecked=true;Check(a.IgnoreFingerprint && b.IgnoreFingerprint,"explicit GUI bypass applies to selected-session devices");
        IgnoreSshFingerprint.IsChecked=false;Check(!a.IgnoreFingerprint && !b.IgnoreFingerprint,"GUI restores fingerprint checking");
        Check(OtaPilot.IsChecked==true && BootstrapPilot.IsChecked==true,"OTA/bootstrap pilots enabled by default");
        OtaPilot.IsChecked=false;BootstrapPilot.IsChecked=false;Check(OtaPilot.IsChecked==false && BootstrapPilot.IsChecked==false,"parallel without pilot selectable for OTA and bootstrap");
        OtaPilot.IsChecked=true;BootstrapPilot.IsChecked=true;
        Check(System.Windows.Controls.ScrollViewer.GetHorizontalScrollBarVisibility(DeviceGrid)==System.Windows.Controls.ScrollBarVisibility.Visible,"device table horizontal scrollbar explicit");
        Check(DeviceGrid.Columns.Any(c=>c.Header.ToString()=="返回概况") && DeviceGrid.Columns.Any(c=>c.Header.ToString()=="最近命令"),"command summary columns present");
        Check(DeviceGrid.RowDetailsTemplate is null && DeviceGrid.RowDetailsVisibilityMode==DataGridRowDetailsVisibilityMode.Collapsed,"device selection cannot expand a row details panel");
        DeviceGrid.UnselectAll();b.CommandDetail="saved command output";DeviceGrid.SelectedItem=b;
        Check(((TextBox)window.FindName("ResultText")).Text==b.CommandDetail,"selected command output stays in the separate result panel");
        b.CommandDetail="";
        Check(DeviceGrid.Columns.Any(c=>c.Header.ToString()=="MAC 地址") && !DeviceGrid.Columns.Any(c=>new[]{"备注","连接","时间状态"}.Contains(c.Header.ToString())),"MAC column replaces removed note, transport and clock columns");
        var development=(TabItem)window.FindName("DevelopmentTab");
        var developmentPreset=(ComboBox)window.FindName("DevelopmentPreset");
        Check(development.Header.ToString()=="开发与诊断" && developmentPreset.Items.Cast<CommandPreset>().All(p=>p.Development),"development command picker is grouped separately");
        Check(CommandPreset.Items.Cast<CommandPreset>().All(p=>!p.Development),"daily command picker excludes development presets");
        Check(window.FindName("RemoveDevicesButton") is Button,"local inventory deletion exposed");
        Check(window.FindName("MacScanButton") is Button { Content: "按 MAC 查找 IP", IsEnabled: true }, "manual MAC discovery button is available");
        var macCandidate = new MacIpCandidate("192.168.1.125", 22, "02:00:00:00:00:07", true);
        var pinnedDevice = new Device { DeviceId="mac-ui", Address="192.168.1.18", MacAddress=macCandidate.MacAddress, HostKeys=new() { ["rescue"]="trusted-rescue" } };
        devices.Add(pinnedDevice);
        var macTasks=(List<PendingTask>)typeof(MainWindow).GetField("pendingTasks",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(window)!;
        var originalMacTask=new PendingTask(pinnedDevice.DeviceId,Guid.NewGuid().ToString("D"),"existing-release","all");macTasks.Add(originalMacTask);
        Call("ApplyMacAddress",pinnedDevice,macCandidate,new RemoteResult(JsonSerializer.SerializeToElement(new{agent_version="1.2.3",device_id="mac-ui"}),"trusted-rescue","rescue","mac-rescue"),false);
        Check(pinnedDevice.Address==macCandidate.Address && pinnedDevice.Mode=="rescue" && pinnedDevice.Hostname=="mac-rescue" && macTasks.Contains(originalMacTask), "manual verified IP update preserves the original device and deployment task");
        bool macRejected=false;
        try { Call("ApplyMacAddress",pinnedDevice,macCandidate with { Address="192.168.1.126" },new RemoteResult(JsonSerializer.SerializeToElement(new{agent_version="1.2.3",device_id="wrong-ui-device"}),"trusted-rescue","rescue"),false); }
        catch(DeviceIdentityMismatchException) { macRejected=true; }
        Check(macRejected && pinnedDevice.Address==macCandidate.Address && pinnedDevice.DeviceId=="mac-ui", "manual IP update refuses another device before modifying the GUI inventory");
        devices.Remove(pinnedDevice);macTasks.Remove(originalMacTask);
        var loginDevice=new Device{DeviceId="login-ui",Mode="system",Address="192.168.1.18"};devices.Add(loginDevice);
        var systemLogin=new Credentials("root","","system-ui-key");var rescueLogin=new Credentials("root","rescue-ui-password");
        var loginVault=(Vault)typeof(MainWindow).GetField("vault",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(window)!;
        typeof(MainWindow).GetField("defaultLogin",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(window,rescueLogin);
        loginVault.SaveDefault(rescueLogin);
        loginVault.Save(loginDevice.DeviceId+"/ssh",systemLogin);
        var loginPlan=(Credentials)Call("CredentialsFor",loginDevice)!;
        Check(LoginProfiles.Choices(loginPlan,"rescue").Single().Credentials==rescueLogin,"GUI forwards the saved default password to Rescue discovery");
        loginPlan.Ssh!.Verified!(loginDevice.DeviceId,"rescue",rescueLogin);
        loginDevice.Mode="rescue";
        var rescuePlan=(Credentials)Call("CredentialsFor",loginDevice)!;
        Check(LoginProfiles.Plain(rescuePlan)==rescueLogin && LoginProfiles.Choices(rescuePlan,"system").First().Credentials==systemLogin,"GUI remembers the Rescue password without losing the System key");
        Check(loginVault.LoadEnvironmentConnection(loginDevice.DeviceId,"system")==systemLogin && loginVault.LoadEnvironmentConnection(loginDevice.DeviceId,"rescue")==rescueLogin,"GUI migrates the legacy System key and preserves both environment settings in encrypted storage");
        var registrationDevice=new Device{DeviceId="registration-login-ui",Mode="system",Address="192.168.1.19"};
        loginVault.Save(registrationDevice.DeviceId+"/ssh",systemLogin);
        Call("PreserveLoginForSwitch",registrationDevice);
        Check(loginVault.LoadEnvironmentConnection(registrationDevice.DeviceId,"system")==systemLogin && registrationDevice.Mode=="system","manual reauthentication preserves the previous environment login before changing modes");
        loginVault.ForgetConnection(registrationDevice,true);
        devices.Remove(loginDevice);loginVault.ForgetConnection(loginDevice,true);loginVault.ClearDefault();
        typeof(MainWindow).GetField("defaultLogin",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(window,null);



        Check(window.FindName("DefaultEnvironmentCredentialsButton") is Button {Content:"System / Rescue 默认登录"},
              "separate default environment login settings are available before switching the device");
        var dualDefault=new Credentials("system-admin","gui-password-fixture","gui-key-fixture","gui-passphrase-fixture");
        var rescueDefault=new Credentials("rescue-admin","gui-rescue-default-fixture");
        Call("SaveDefaultEnvironmentLogins",new Dictionary<string,Credentials>{{"system",dualDefault},{"rescue",rescueDefault}});
        Check(loginVault.LoadDefaultEnvironment("system")==dualDefault && loginVault.LoadDefaultEnvironment("rescue")==rescueDefault,
              "GUI persists distinct default System and Rescue accounts without a device login");
        Check(((TextBlock)window.FindName("DefaultCredentialsStatus")).Text.Contains("system-admin") &&
              ((TextBlock)window.FindName("DefaultCredentialsStatus")).Text.Contains("rescue-admin") &&
              !((TextBlock)window.FindName("DefaultCredentialsStatus")).Text.Contains(dualDefault.Password),
              "default login summary shows environments and methods without passwords");
        var editDevice=new Device{DeviceId="environment-editor-ui",Mode="system",Address="192.0.2.8"};devices.Add(editDevice);
        var independentRescue=new Credentials("node-rescue","node-rescue-password-fixture");
        Call("SaveDeviceEnvironmentLogins",editDevice,new Dictionary<string,Credentials>{{"system",dualDefault},{"rescue",independentRescue}});
        Check(editDevice.Mode=="system" && loginVault.LoadEnvironmentConnection(editDevice.DeviceId,"rescue")==independentRescue &&
              loginVault.LoadEnvironmentConnection(editDevice.DeviceId,"system")==dualDefault,
              "both device accounts can be configured from System without changing the boot environment or connecting");
        var environmentPlan=(Credentials)Call("CredentialsFor",editDevice)!;
        Check(LoginProfiles.Choices(environmentPlan,"rescue").First().Credentials==independentRescue &&
              LoginProfiles.Choices(environmentPlan,"system").Take(2).Select(choice=>choice.Authentication).SequenceEqual(new[]{SshAuthenticationKind.PrivateKey,SshAuthenticationKind.Password}),
              "the GUI connection plan uses the selected environment account and both configured authentication methods");
        environmentPlan.Ssh!.Verified!(editDevice.DeviceId,"system",dualDefault);
        Check(loginVault.LoadEnvironmentConnection(editDevice.DeviceId,"system")==dualDefault,
              "verified authentication does not discard the configured fallback password or key");
        _ = new System.Windows.Interop.WindowInteropHelper(window).EnsureHandle();
        var editor=new EnvironmentLoginDialog(window,"Environment editor",new Dictionary<string,Credentials>{{"system",dualDefault}},mode=>mode=="rescue"?rescueDefault:dualDefault);
        editor.EnabledEnvironments["rescue"].IsChecked=true;
        editor.Editors["rescue"].UsernameBox.Text="changed-rescue-user";
        editor.Editors["rescue"].PasswordBox.Password="changed-rescue-password-fixture";
        var edited=editor.Read();
        Check(edited["system"]==dualDefault && edited["rescue"].Username=="changed-rescue-user" && edited["rescue"].Password=="changed-rescue-password-fixture",
              "the actual environment dialog has independent editable usernames and masked passwords for both tabs");
        editor.EnabledEnvironments["system"].IsChecked=false;
        Check(editor.Read().Keys.Single()=="rescue" && !editor.Editors["system"].IsEnabled,
              "unselected environment tabs are not overwritten when saving another environment");
        editor.Close();
        var legacyDialogFields=new LoginCredentialFields(dualDefault);
        Check(legacyDialogFields.Read()==dualDefault,"the common default editor retains private key and account password together");
        bool badEnvironment=false;
        try{Call("SaveDeviceEnvironmentLogins",editDevice,new Dictionary<string,Credentials>{{"system",new("replacement","replacement")},{"invalid",independentRescue}});}
        catch(ArgumentException){badEnvironment=true;}
        Check(badEnvironment && loginVault.LoadEnvironmentConnection(editDevice.DeviceId,"system")==dualDefault,
              "all environment settings are validated before changing an existing account");
        devices.Remove(editDevice);loginVault.ForgetConnection(editDevice,true);loginVault.ClearDefault();
        ((Dictionary<string,Credentials>)typeof(MainWindow).GetField("defaultEnvironmentLogins",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(window)!).Clear();

        Check(window.FindName("CancelPausedTasksButton") is Button { Content: "取消暂停任务" } &&
              window.FindName("AutomaticTaskHistoryButton") is Button { Content: "自动流程历史" },
              "paused cancellation and retained automatic history are available in the GUI");
        var localAutomations=(List<AutomaticTask>)typeof(MainWindow).GetField("automaticTasks",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(window)!;
        var pausedA=new AutomaticTask(Guid.NewGuid().ToString("D"),a.DeviceId,new UpgradeOptions(""),Guid.NewGuid().ToString("D"),Guid.NewGuid().ToString("D"),Stage:"paused",Error:"boot_agent",Phase:"uploading-package");
        var pausedB=pausedA with {TaskId=Guid.NewGuid().ToString("D"),DeviceId=b.DeviceId};
        var activeA=pausedA with {TaskId=Guid.NewGuid().ToString("D"),Stage="maintaining",Phase="maintaining"};
        var finishedA=pausedA with {TaskId=Guid.NewGuid().ToString("D"),Stage="succeeded",Phase="succeeded"};
        localAutomations.AddRange([pausedA,pausedB,activeA,finishedA]);
        var deviceJob=new PendingTask(a.DeviceId,Guid.NewGuid().ToString("D"),"device-operation","all");macTasks.Add(deviceJob);
        Call("Save");
        string stateRoot=(string)typeof(Vault).GetField("directory",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(loginVault)!;
        var remoteRecords=new[]{"tasks.json","maintenance.json"}.ToDictionary(name=>name,name=>File.ReadAllBytes(Path.Combine(stateRoot,name)));
        HostFilter.Text=a.Hostname;DeviceGrid.UnselectAll();a.Selected=true;b.Selected=true;
        var visibleHistory=(IReadOnlyList<AutomaticTask>)Call("AutomaticTasksForSelection")!;
        Check(visibleHistory.Count==3 && visibleHistory.All(task=>task.DeviceId==a.DeviceId),"local history and cancellation selection exclude hidden checked devices");
        var cancelledRows=(IReadOnlyList<AutomaticTask>)Call("CancelPausedAutomaticTasks",(object)new[]{pausedA.TaskId})!;
        Check(cancelledRows.Count==1 && cancelledRows[0].Stage=="cancelled" && cancelledRows[0].CancelledAt is not null &&
              cancelledRows[0].TaskId==pausedA.TaskId && cancelledRows[0].Error=="boot_agent" && cancelledRows[0].Phase=="uploading-package",
              "GUI cancellation retains the original task identity, paused phase and error with a timestamp");
        Check(localAutomations.Count==4 && localAutomations.Contains(pausedB) && localAutomations.Contains(activeA) && localAutomations.Contains(finishedA),
              "cancelling a paused local task preserves other hosts, running flows and completed history");
        Check(remoteRecords.All(pair=>pair.Value.SequenceEqual(File.ReadAllBytes(Path.Combine(stateRoot,pair.Key)))) && macTasks.Contains(deviceJob),
              "GUI local cancellation never alters separately recorded device or maintenance operations");
        var reopenedHistory=loginVault.LoadAutomatic();
        Check(reopenedHistory.Count==4 && reopenedHistory.Single(task=>task.TaskId==pausedA.TaskId)==cancelledRows[0],
              "cancelled history is persisted for the next application launch");
        Check(a.State=="上位机自动流程已取消" && a.CommandSummary.Contains("设备端已提交的操作继续执行"),
              "visible cancellation results distinguish the local flow from continuing device work");
        ((Button)window.FindName("AutomaticTaskHistoryButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        var historyOutput=JsonSerializer.Deserialize<JsonElement>(((TextBox)window.FindName("ResultText")).Text);
        Check(historyOutput.GetProperty("scope").GetString()=="controller" && historyOutput.GetProperty("device_operations_continue").GetBoolean() &&
              historyOutput.GetProperty("tasks").GetArrayLength()==3 && historyOutput.GetProperty("tasks").EnumerateArray().Any(task=>task.GetProperty("task_id").GetString()==pausedA.TaskId && task.GetProperty("stage").GetString()=="cancelled"),
              "the wired history button displays retained cancelled tasks without a connection or credentials");
        bool busyCancellation=false;
        typeof(MainWindow).GetField("batching",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(window,true);
        try { Call("CancelPausedAutomaticTasks",(object)new[]{pausedB.TaskId}); } catch(InvalidOperationException) { busyCancellation=true; }
        finally { typeof(MainWindow).GetField("batching",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(window,false); }
        Check(busyCancellation && localAutomations.Contains(pausedB),"local cancellation refuses to race an active controller operation");
        bool changedCancellation=false;
        try { Call("CancelPausedAutomaticTasks",(object)new[]{pausedB.TaskId,activeA.TaskId}); } catch(InvalidOperationException) { changedCancellation=true; }
        Check(changedCancellation && localAutomations.Contains(pausedB) && loginVault.LoadAutomatic().Single(task=>task.TaskId==pausedB.TaskId).Stage=="paused",
              "a changed task selection fails before partially cancelling or persisting another task");
        ((Button)window.FindName("CancelPausedTasksButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Check(((TextBlock)window.FindName("StatusBar")).Text.Contains("没有暂停") && localAutomations.Single(task=>task.TaskId==pausedA.TaskId)==cancelledRows[0],
              "the wired cancel button reports an empty paused selection without changing existing history");
        localAutomations.Clear();loginVault.SaveAutomatic(localAutomations);macTasks.Remove(deviceJob);loginVault.SaveTasks(macTasks);
        HostFilter.Text="";ClearSelectionClick(this,new());

        Update(a,new RemoteResult(JsonSerializer.SerializeToElement(new{agent_version="0.3.2",device_id="a",clock=new{quality="estimated",source="restored-shared-time",epoch=1791570000,last_saved_epoch=1791569000}}),"","rescue"));
        Check(a.ClockStatus=="估计时间" && a.ClockDetail.Contains("电脑接收时间"),"actual WPF status updates clock diagnosis");
        Update(b,new RemoteResult(JsonSerializer.SerializeToElement(new{agent_version="0.3.1",device_id="b"}),"","system"));
        Check(b.ClockStatus=="未提供","actual WPF accepts old agent clock omission");
        Check(CancelAuthenticationButton is not null && !CancelAuthenticationButton.IsEnabled,"authentication cancellation exposed and idle by default");
        var metadata=NetworkMetadata.Parse("{\"interfaces\":[{\"interface\":\"eth0\",\"mac_address\":\"02:00:00:00:00:07\",\"addresses\":[\"192.168.1.10\"]}]}")!;
        Update(a,new RemoteResult(JsonSerializer.SerializeToElement(new{agent_version="1.0.1",device_id="a"}),"","rescue","verified-node",metadata));
        Check(a.MacAddress=="02:00:00:00:00:07" && a.HostnameSource=="SSH" && a.NetworkDetail.Contains("eth0"),"actual WPF update displays authenticated MAC and hostname source");
        var candidate=DeviceInventory.ApplyDiscovery(devices,new(new Endpoint("192.168.1.12"),"scan-node.local","mDNS"));
        Check(candidate.Hostname=="scan-node.local" && !candidate.Managed,"scan names appear without device registration");
        int removed=(int)Call("RemoveLocalDevices",new List<Device>{candidate})!;
        Check(removed==1 && !devices.Contains(candidate),"unregistered scanned hosts can be deleted locally");
        var tasks=(List<PendingTask>)typeof(MainWindow).GetField("pendingTasks",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(window)!;
        var pending=new PendingTask(a.DeviceId,Guid.NewGuid().ToString("D"),"existing-release","all");tasks.Add(pending);
        removed=(int)Call("RemoveLocalDevices",new List<Device>{a})!;
        Check(removed==1 && tasks.Any(t=>t.JobId==pending.JobId),"managed host removal preserves existing upgrade records");
        return checks;
    }
}
internal static class Program
{
    [STAThread] static int Main(string[] args)
    {
        string output=Path.GetFullPath(args.Length>0?args[0]:Path.Combine(Path.GetTempPath(),"armhpc-ui-"+Guid.NewGuid().ToString("N"),"ui-result.png"));Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var app=new App();app.InitializeComponent();
        var window=new MainWindow(Path.Combine(Path.GetDirectoryName(output)!,"ui-state-"+Guid.NewGuid().ToString("N")));
        if(window.DeviceGrid.Items.Count!=0)throw new InvalidOperationException("Fresh application must have no fabricated devices");
        int checks=new Suite(window).VerifyManagement();
        var data=(ObservableCollection<Device>)typeof(MainWindow).GetField("devices",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(window)!;
        data.Clear();data.Add(new Device{Address="192.168.1.10",Hostname="armhpc-example",DeviceId="fixture-only",Mode="system",State="就绪",SystemVersion="1.0.1",RescueVersion="1.0.1 · a",MacAddress="02:00:00:00:00:07",HostnameSource="SSH",ClockStatus="已校准"});
        window.DeviceGrid.SelectedItem=data[0];
        var content=(FrameworkElement)window.Content;((Grid)content).Background=window.Background;content.Measure(new Size(1320,900));content.Arrange(new Rect(0,0,1320,900));content.UpdateLayout();
        var image=new RenderTargetBitmap(1320,900,96,96,PixelFormats.Pbgra32);image.Render(content);var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(image));using(var f=File.Create(output))encoder.Save(f);
        File.WriteAllText(Path.ChangeExtension(output,".json"),JsonSerializer.Serialize(new{checks=checks+1,passed=true,network_accessed=false,application_version=ApplicationVersion.Number,window_title=window.Title,version_header=((TextBlock)window.FindName("ApplicationVersionLabel")).Text}));
        Console.WriteLine($"WPF {checks+1} checks passed");app.Shutdown();return 0;
    }
}
