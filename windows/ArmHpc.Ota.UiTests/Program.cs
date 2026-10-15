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
        File.WriteAllText(Path.ChangeExtension(output,".json"),JsonSerializer.Serialize(new{checks=checks+1,passed=true,network_accessed=false}));
        Console.WriteLine($"WPF {checks+1} checks passed");app.Shutdown();return 0;
    }
}
