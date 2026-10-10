// SPDX-License-Identifier: GPL-3.0-only
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using ArmHpc.Ota.Core;
namespace ArmHpc.Ota.Windows;

public sealed class AutomaticWindow:Window
{
    public UpgradeOptions? Options{get;private set;}
    public AutomaticWindow(Window owner,string release,string target,string range)
    {
        Owner=owner;Title="上位机推送并升级";Width=700;Height=580;WindowStartupLocation=WindowStartupLocation.CenterOwner;
        var panel=new StackPanel{Margin=new Thickness(20)};var package=new TextBox();var version=new TextBox();var bundle=new TextBox();
        string included=System.IO.Path.Combine(AppContext.BaseDirectory,"maintenance","maintenance.tar.xz");
        if(System.IO.File.Exists(included))bundle.Text=included;
        var source=new TextBox{Text=""};var http=new CheckBox{Content="明确允许该内网 HTTP 地址"};
        var local=new CheckBox{Content="上位机推送本地签名包（推荐，无需发布服务）",IsChecked=true,Margin=new Thickness(0,8,0,8)};
        void Field(string label,TextBox box,Panel? container=null){var parent=container??panel;parent.Children.Add(new TextBlock{Text=label,Margin=new Thickness(0,8,0,3)});parent.Children.Add(box);}
        panel.Children.Add(new TextBlock{Text="电脑通过 SSH/SFTP 传送文件。设备核对签名和哈希后执行升级，电脑 IP 可变化。",TextWrapping=TextWrapping.Wrap});panel.Children.Add(local);
        Field("完整签名 OTA 包（.tar.xz），或包含 releases 和 blobs 的本地目录",package);
        var select=new Button{Content="选择本地 OTA 包",HorizontalAlignment=HorizontalAlignment.Left};select.Click+=(_,_)=>{var d=new OpenFileDialog{Filter="签名系统 OTA 包|*.tar.xz"};if(d.ShowDialog(this)==true)package.Text=d.FileName;};panel.Children.Add(select);
        Field("系统版本（包内只有一个版本时可留空）",version);
        Field("签名工具维护包（设备 agent 低于 0.3.3 时需要）",bundle);
        var tools=new Button{Content="选择 maintenance.tar.xz",HorizontalAlignment=HorizontalAlignment.Left};tools.Click+=(_,_)=>{var d=new OpenFileDialog{Filter="工具维护包|maintenance.tar.xz|XZ archive|*.tar.xz",InitialDirectory=System.IO.Path.Combine(AppContext.BaseDirectory,"maintenance")};if(d.ShowDialog(this)==true)bundle.Text=d.FileName;};panel.Children.Add(tools);
        var sourceFields=new StackPanel{Visibility=Visibility.Collapsed};panel.Children.Add(sourceFields);
        Field("兼容旧拉取模式：索引地址",source,sourceFields);sourceFields.Children.Add(http);
        local.Checked+=(_,_)=>sourceFields.Visibility=Visibility.Collapsed;local.Unchecked+=(_,_)=>sourceFields.Visibility=Visibility.Visible;
        panel.Children.Add(new TextBlock{Text="目标："+target+"。全部载荷验证完整后才提交；普通系统进入 Rescue 更新，初始恢复基线和 DATA 保留。",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,8,0,8)});
        var submit=new Button{Content="确认参数并继续",IsDefault=true};submit.Click+=(_,_)=>
        {
            bool push=local.IsChecked==true;
            if(push && string.IsNullOrWhiteSpace(package.Text)){MessageBox.Show(this,"请选择完整本地 OTA 包。");return;}
            Options=new(push?"":source.Text.Trim(),string.IsNullOrWhiteSpace(version.Text)?null:version.Text.Trim(),target,!push && http.IsChecked==true,
                string.IsNullOrWhiteSpace(bundle.Text)?null:bundle.Text.Trim(),Ranges:string.IsNullOrWhiteSpace(range)?[]:[range.Trim()],Package:push?package.Text.Trim():null);
            DialogResult=true;
        };panel.Children.Add(submit);Content=new ScrollViewer{Content=panel,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
    }
}
