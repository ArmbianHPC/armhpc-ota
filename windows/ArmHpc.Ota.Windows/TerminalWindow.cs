// SPDX-License-Identifier: GPL-3.0-only
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using ArmHpc.Ota.Core;
namespace ArmHpc.Ota.Windows;

public sealed class TerminalWindow:Window
{
    readonly TextBox output=new(){IsReadOnly=true,AcceptsReturn=true,TextWrapping=TextWrapping.Wrap,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,FontFamily=new("Consolas"),Background=System.Windows.Media.Brushes.Black,Foreground=System.Windows.Media.Brushes.White};
    readonly TextBox input=new();readonly PasswordBox secret=new();readonly CheckBox hidden=new(){Content="隐藏输入（密码 / token）"};
    readonly CancellationTokenSource stopping=new();readonly DispatcherTimer timer=new(){Interval=TimeSpan.FromMilliseconds(80)};
    SshTerminal? terminal;string? initial;string tail="";
    public TerminalWindow(Window owner,ConnectionRouter router,Device device,Credentials credentials,ArmHpcRequest? request=null)
    {
        Owner=owner;Title="SSH 终端 · "+(device.Hostname.Length>0?device.Hostname:device.Address);Width=960;Height=680;
        var grid=new Grid{Margin=new Thickness(12)};grid.RowDefinitions.Add(new(){Height=GridLength.Auto});grid.RowDefinitions.Add(new(){Height=new GridLength(1,GridUnitType.Star)});grid.RowDefinitions.Add(new(){Height=GridLength.Auto});
        var info=new TextBlock{Text="使用已登记身份和所选登录凭据。输出仅显示在当前窗口；关闭会断开交互会话。",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,0,0,8)};grid.Children.Add(info);Grid.SetRow(output,1);grid.Children.Add(output);
        var panel=new DockPanel{Margin=new Thickness(0,10,0,0)};Grid.SetRow(panel,2);grid.Children.Add(panel);
        var send=new Button{Content="发送",Width=65};DockPanel.SetDock(send,Dock.Right);panel.Children.Add(send);DockPanel.SetDock(hidden,Dock.Right);panel.Children.Add(hidden);
        var ctrlC=new Button{Content="Ctrl+C",Width=65};DockPanel.SetDock(ctrlC,Dock.Right);panel.Children.Add(ctrlC);
        var fields=new Grid();fields.Children.Add(input);fields.Children.Add(secret);secret.Visibility=Visibility.Collapsed;panel.Children.Add(fields);
        hidden.Checked+=(_,_)=>{input.Visibility=Visibility.Collapsed;secret.Visibility=Visibility.Visible;secret.Focus();};hidden.Unchecked+=(_,_)=>{secret.Visibility=Visibility.Collapsed;input.Visibility=Visibility.Visible;input.Focus();};
        void Send(){if(terminal is null)return;try{terminal.Send((hidden.IsChecked==true?secret.Password:input.Text)+"\r");}catch(Exception e){output.AppendText("\n发送失败："+e.Message);}finally{input.Clear();secret.Clear();}}
        send.Click+=(_,_)=>Send();ctrlC.Click+=(_,_)=>terminal?.Send("\x03");input.KeyDown+=(_,e)=>{if(e.Key==Key.Enter){e.Handled=true;Send();}};secret.KeyDown+=(_,e)=>{if(e.Key==Key.Enter){e.Handled=true;Send();}};
        timer.Tick+=(_,_)=>
        {
            try
            {
                string text=terminal?.Read()??"";if(text.Length==0)return;tail=(tail+text);if(tail.Length>8192)tail=tail[^8192..];
                output.AppendText(Regex.Replace(text,@"\x1b\[[0-9;?]*[A-Za-z]",""));if(output.Text.Length>2*1024*1024)output.Text=output.Text[^1048576..];output.ScrollToEnd();
                if(initial is not null && ConsoleProtocol.Prompt(tail)=="shell"){terminal!.Send(initial+"\r");initial=null;}
            }catch(Exception e){timer.Stop();output.AppendText("\n连接结束："+e.Message);terminal?.Dispose();terminal=null;}
        };
        Loaded+=async(_,_)=>
        {
            try{terminal=await router.OpenTerminal(new(device.Address,device.Port),credentials,device,stopping.Token);device.Mode=terminal.Mode;if(terminal.Hostname.Length>0)device.Hostname=terminal.Hostname;initial=request?.Build(terminal.Mode,credentials.Username!="root");timer.Start();input.Focus();}
            catch(Exception e){output.AppendText("连接失败："+e.Message);}
        };
        Closed+=(_,_)=>{stopping.Cancel();timer.Stop();terminal?.Dispose();stopping.Dispose();};Content=grid;
    }
}
