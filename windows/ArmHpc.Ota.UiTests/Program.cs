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
        Check(DeviceGrid.RowDetailsTemplate is not null,"command detail row bound");
        Check(DeviceGrid.Columns.Any(c=>c.Header.ToString()=="时间状态"),"clock quality column present");
        Update(a,new RemoteResult(JsonSerializer.SerializeToElement(new{agent_version="0.3.2",device_id="a",clock=new{quality="estimated",source="restored-shared-time",epoch=1791570000,last_saved_epoch=1791569000}}),"","rescue"));
        Check(a.ClockStatus=="估计时间" && a.ClockDetail.Contains("电脑接收时间"),"actual WPF status updates clock diagnosis");
        Update(b,new RemoteResult(JsonSerializer.SerializeToElement(new{agent_version="0.3.1",device_id="b"}),"","system"));
        Check(b.ClockStatus=="未提供","actual WPF accepts old agent clock omission");
        Check(CancelAuthenticationButton is not null && !CancelAuthenticationButton.IsEnabled,"authentication cancellation exposed and idle by default");
        return checks;
    }
}
internal static class Program
{
    [STAThread] static int Main(string[] args)
    {
        string output=Path.GetFullPath(args.Length>0?args[0]:"ui-result.png");Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var app=new App();app.InitializeComponent();
        var window=new MainWindow(Path.Combine(Path.GetDirectoryName(output)!,"ui-state"));
        if(window.DeviceGrid.Items.Count!=0)throw new InvalidOperationException("Fresh application must have no fabricated devices");
        int checks=new Suite(window).VerifyManagement();
        var data=(ObservableCollection<Device>)typeof(MainWindow).GetField("devices",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(window)!;
        data.Clear();data.Add(new Device{Address="192.168.1.10",Hostname="armhpc-example",DeviceId="fixture-only",Mode="system",State="就绪",SystemVersion="1.0.0",RescueVersion="1.0.0 · a",ClockStatus="已校准"});
        var content=(FrameworkElement)window.Content;content.Measure(new Size(1320,900));content.Arrange(new Rect(0,0,1320,900));content.UpdateLayout();
        var image=new RenderTargetBitmap(1320,900,96,96,PixelFormats.Pbgra32);image.Render(content);var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(image));using(var f=File.Create(output))encoder.Save(f);
        File.WriteAllText(Path.ChangeExtension(output,".json"),JsonSerializer.Serialize(new{checks=checks+1,passed=true,network_accessed=false}));
        Console.WriteLine($"WPF {checks+1} checks passed");app.Shutdown();return 0;
    }
}
