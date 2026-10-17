// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Collections.ObjectModel;
using System.IO;
using System.ComponentModel;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using ArmHpc.Ota.Core;
using Microsoft.Win32;

namespace ArmHpc.Ota.Windows;

public sealed class BackupStorageWindow:Window
{
    public static readonly string[] WorkflowStages=["导出原始备份","上位机压缩","校验压缩包","预览清理","确认清理"];
    public sealed class Row
    {
        public bool Selected {get;set;}=true;
        public string Id {get;init;}="";
        public string Kind {get;init;}="";
        public string Task {get;init;}="";
        public string Size {get;init;}="";
        public string Exported {get;init;}="";
        public string Retained {get;init;}="";
    }
    readonly ConnectionRouter router;readonly Device device;readonly Credentials credentials;readonly Action<string> log;
    readonly ObservableCollection<Row> rows=[];readonly CancellationTokenSource cancellation=new();
    readonly TextBlock summary=new(){TextWrapping=TextWrapping.Wrap,Margin=new(0,0,0,10)};
    readonly TextBox detail=new(){IsReadOnly=true,AcceptsReturn=true,TextWrapping=TextWrapping.Wrap,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
    readonly Button refresh=new(){Content="刷新备份与清理预览",Margin=new(0,0,10,10)};
    readonly Button export=new(){Content="导出、压缩并清理",Margin=new(0,0,10,10)};
    bool busy;readonly bool pendingControllerTasks;readonly BackupStorageSession storage;
    static string Bytes(long n)=>$"{n/1024d/1024/1024:0.00} GiB";
    Endpoint Endpoint=>new(device.Address,device.Port);
    public BackupStorageWindow(ConnectionRouter connection,Device target,Credentials login,Action<string> progress,bool pendingTasks=false)
    {
        router=connection;device=target;credentials=login;log=progress;pendingControllerTasks=pendingTasks;
        storage=new(connection,target,login,Path.Combine(AppContext.BaseDirectory,"maintenance/maintenance.tar.xz"),Progress);
        Title="备份与共享空间 · "+target.Name;Width=1040;Height=690;MinWidth=850;MinHeight=580;WindowStartupLocation=WindowStartupLocation.CenterOwner;
        var root=new DockPanel{Margin=new(18)};Content=root;
        var header=new StackPanel();DockPanel.SetDock(header,Dock.Top);root.Children.Add(header);
        header.Children.Add(summary);
        header.Children.Add(new TextBlock{Text="Rescue 只传输原始文件；压缩和解压校验在本机完成。备份含设备私有信息，请选择受控目录。",TextWrapping=TextWrapping.Wrap,Margin=new(0,0,0,10)});
        header.Children.Add(new TextBlock{Text=string.Join(" → ",WorkflowStages),Margin=new(0,0,0,12)});
        var buttons=new StackPanel{Orientation=Orientation.Horizontal};buttons.Children.Add(refresh);buttons.Children.Add(export);header.Children.Add(buttons);
        var grid=new DataGrid{ItemsSource=rows,AutoGenerateColumns=false,CanUserAddRows=false,CanUserDeleteRows=false,Height=205,Margin=new(0,0,0,12)};
        grid.Columns.Add(new DataGridCheckBoxColumn{Header="导出",Binding=new Binding(nameof(Row.Selected)){UpdateSourceTrigger=UpdateSourceTrigger.PropertyChanged}});
        foreach(var (name,label,width) in new[]{("Kind","类型",80d),("Task","任务",285d),("Size","大小",95d),("Exported","已导出",65d),("Retained","保留规则",270d)})
            grid.Columns.Add(new DataGridTextColumn{Header=label,Binding=new Binding(name),Width=width,IsReadOnly=true});
        header.Children.Add(grid);root.Children.Add(detail);
        refresh.Click+=async(_,_)=>await Refresh();export.Click+=async(_,_)=>await Export();Loaded+=async(_,_)=>await Refresh();
        Closing+=(_,_)=>cancellation.Cancel();
    }
    Task<JsonElement> Command(params string[] args)=>storage.Command(args,token:cancellation.Token);
    void Busy(bool value){busy=value;refresh.IsEnabled=!value;export.IsEnabled=!value;}
    void Progress(string line){Dispatcher.InvokeAsync(()=>{detail.AppendText(line+Environment.NewLine);detail.ScrollToEnd();log(device.Name+" · "+line);});}
    async Task<JsonElement> Plan()=>StorageCleanup.ProtectControllerTasks(await Command("plan"),pendingControllerTasks);
    void DisplayPlan(JsonElement plan)
    {
        detail.Text="清理预览：可释放 "+Bytes(plan.GetProperty("reclaimable_bytes").GetInt64())+Environment.NewLine;
        foreach(var item in plan.GetProperty("items").EnumerateArray())
            detail.AppendText($"可清理 · {Protocol.Text(item,"kind")} · {Bytes(item.GetProperty("bytes").GetInt64())} · {Protocol.Text(item,"path")}\n");
        foreach(var item in plan.GetProperty("protected").EnumerateArray())
            detail.AppendText($"保留 · {Protocol.Text(item,"path")} · {Protocol.Text(item,"reason")}\n");
    }
    async Task Refresh()
    {
        if(busy)return;Busy(true);
        try
        {
            var state=await Command("status");rows.Clear();
            if(Protocol.Text(state,"mode")!="rescue")throw new InvalidOperationException("请先进入 Rescue。此窗口不会自动重启设备。");
            var space=state.GetProperty("shared");summary.Text="共享区：剩余 "+Bytes(space.GetProperty("free_bytes").GetInt64())+" / "+Bytes(space.GetProperty("total_bytes").GetInt64());
            foreach(var b in state.GetProperty("backups").EnumerateArray())rows.Add(new(){Id=Protocol.Text(b,"id"),Task=Protocol.Text(b,"task_id"),
                Kind=Protocol.Text(b,"kind")=="boot"?"BOOT":"工具维护",Size=Bytes(b.GetProperty("bytes").GetInt64()),
                Exported=b.GetProperty("exported").GetBoolean()?"是":"否",Retained=Protocol.Text(b,"reason")});
            try{DisplayPlan(await Plan());}catch(Exception error){detail.Text="当前不能清理："+error.Message;}
        }
        catch(Exception error){detail.Text="无法读取备份与空间状态：\n"+error.Message;}
        finally{Busy(false);}
    }
    async Task Export()
    {
        if(busy)return;
        var selected=rows.Where(r=>r.Selected).ToArray();
        if(selected.Length==0){MessageBox.Show(this,"请选择需要导出的备份。","备份与共享空间");return;}
        var picker=new OpenFolderDialog{Title="选择本机私有备份目录"};if(picker.ShowDialog(this)!=true)return;
        Busy(true);bool completed=false;
        try
        {
            foreach(var row in selected)
            {
                Progress("准备备份："+row.Task);
                var prepared=await Command("export","--backup-id",row.Id);
                var result=await router.DownloadBackup(Endpoint,credentials,device,prepared,picker.FolderName,Progress,cancellation.Token);
                // Acknowledgment follows local compression, full archive readback
                // and durable storage; an interrupted transfer never authorizes cleanup.
                await Command("acknowledge","--inventory-sha256",result.InventorySha256,"--archive-sha256",result.ArchiveSha256);
                Progress("压缩包已校验："+result.Archive+" · SHA256 "+result.ArchiveSha256);
            }
            var plan=await Plan();DisplayPlan(plan);
            if(plan.GetProperty("items").GetArrayLength()==0){Progress("备份导出完成；当前没有可清理的残留。");completed=true;return;}
            string message="所选备份已在本机压缩并完成逐文件校验。\n\n清理清单已显示在窗口中，可释放 "+Bytes(plan.GetProperty("reclaimable_bytes").GetInt64())+"。\n受保护文件和任务历史会保留。是否执行此清单？";
            if(MessageBox.Show(this,message,"确认共享区清理",MessageBoxButton.YesNo,MessageBoxImage.Question,MessageBoxResult.No)!=MessageBoxResult.Yes)
            {Progress("备份导出完成；共享区清理未执行。");completed=true;return;}
            var cleaned=await storage.Command(StorageCleanup.Arguments(plan),true,cancellation.Token);
            Progress("清理完成："+Bytes(cleaned.GetProperty("removed_bytes").GetInt64())+"；共享区剩余 "+Bytes(cleaned.GetProperty("shared_free_bytes").GetInt64()));
            completed=true;
        }
        catch(OperationCanceledException){Progress("操作已停止；未校验完成的备份不会被清理。");}
        catch(Exception error){MessageBox.Show(this,error.Message,"备份或清理未完成；请查看本机压缩包及设备状态");}
        finally
        {
            Busy(false);
            if(completed && !cancellation.IsCancellationRequested)
                try{var state=await Command("status");summary.Text="共享区剩余："+Bytes(state.GetProperty("shared").GetProperty("free_bytes").GetInt64());}
                catch(Exception error){Progress("请刷新空间状态："+error.Message);}
        }
    }
}

public partial class MainWindow
{
    private void BackupStorageClick(object sender,RoutedEventArgs e)
    {
        if(batching)return;
        try
        {
            var selected=SelectedTargets();
            if(selected.Count!=1 || !selected[0].Managed)throw new InvalidOperationException("请选择一台已认证的 Rescue 设备。");
            var d=selected[0];if(d.Mode!="rescue")throw new InvalidOperationException("请先进入 Rescue，再打开备份与共享空间。");
            batching=true;new BackupStorageWindow(ssh,d,CredentialsFor(d),Log,automaticTasks.Any(t=>t.DeviceId==d.DeviceId && !t.Terminal)){Owner=this}.ShowDialog();
        }
        catch(Exception error){MessageBox.Show(this,error.Message,"备份与共享空间");}
        finally{batching=false;}
    }
}
