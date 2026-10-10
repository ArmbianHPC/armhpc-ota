// SPDX-License-Identifier: GPL-3.0-only
using System.Text;
using System.Text.RegularExpressions;
namespace ArmHpc.Ota.Core;

public static class DeviceSelection
{
    public static bool Matches(Device device,string search,bool exact=false,string mode="all")
    {
        if(mode!="all" && device.Mode!=mode)return false;
        search=search.Trim();if(search.Length==0)return true;
        if(exact)return string.Equals(device.Hostname,search,StringComparison.OrdinalIgnoreCase);
        return new[]{device.Hostname,device.Name,device.Address,device.DeviceId}.Any(v=>v.Contains(search,StringComparison.OrdinalIgnoreCase));
    }
    public static IReadOnlyList<Device> Targets(IEnumerable<Device> visible,IEnumerable<Device> highlighted)
    {
        var items=visible.ToArray();var checkedItems=items.Where(d=>d.Selected).ToArray();
        if(checkedItems.Length>0)return checkedItems;
        var rows=highlighted.ToHashSet();return items.Where(rows.Contains).ToArray();
    }
}

public sealed record ArmHpcRequest(string Program,string[] Arguments,bool Writes,bool Interactive,bool Reboots)
{
    public bool VerifyReboot=>!Arguments.Contains("--help") && !Arguments.Contains("-h") &&
        (Arguments.FirstOrDefault()=="reboot" || Arguments.FirstOrDefault() is "rescue" or "boot" && Arguments.Contains("--reboot"));
    public string? ExpectedRebootMode=>Arguments.FirstOrDefault() is "rescue" or "boot" && !Arguments.Contains("--cancel")?"rescue":null;
    public string Label=>Program+" "+string.Join(" ",Arguments.Take(Program.EndsWith("kube")?1:Arguments.FirstOrDefault()=="ota"?2:1));
    public string Build(string mode,bool privileged)
    {
        if(mode is not ("system" or "rescue"))throw new ArgumentException("未知设备运行环境。");
        string program=Program;var args=Arguments.ToArray();
        if(program=="armhpc" && mode=="rescue")
        {
            program="armhpc-rescue";
            if(args.FirstOrDefault()=="rescue")args[0]="boot";
            else if(args.Length>0 && args[0] is not ("watchdog" or "ota" or "usb-console" or "led" or "configuration" or "reboot" or "--help" or "-h"))
                throw new ArgumentException("该命令仅适用于正常系统。");
        }
        if(program=="armhpc-rescue" && mode!="rescue")throw new ArgumentException("该命令需要设备先进入 Rescue。");
        if(program=="armhpc-kube" && mode!="system")throw new ArgumentException("K3s 命令需要在普通系统中运行。");
        if(Program=="armhpc" && args.FirstOrDefault()=="reboot")
        {
            // Normal ARMHPC has no reboot subcommand; use systemd on normal hosts.
            if(mode=="system")return (privileged?"sudo -n -- ":"")+"/usr/bin/systemctl reboot";
        }
        return (privileged?"sudo -n -- ":"")+"/usr/local/sbin/"+program+" "+string.Join(" ",args.Select(Commands.Quote));
    }
}

public sealed record CommandPreset(string Name,string Command);
public static class ArmHpcCommands
{
    public static IReadOnlyList<CommandPreset> Presets {get;} = [
        new("看门狗状态","armhpc watchdog status --json"),new("看门狗实验报告","armhpc watchdog report --json"),new("BOOT 维护状态","armhpc ota boot status --json"),
        new("ARMHPC 帮助","armhpc --help"),new("OTA 状态和版本","armhpc ota status --json"),
        new("OTA 任务日志","armhpc ota logs --json"),new("OTA 工具一致性","armhpc ota tools status --json"),
        new("OTA 诊断","armhpc ota doctor --json"),new("OTA 接入预览","armhpc ota bootstrap --json"),
        new("本地初始系统恢复计划","armhpc ota plan --release initial --target system --recovery --json"),
        new("OTG 串口状态","armhpc usb-console status --json"),new("当前内核启动日志","armhpc usb-console logs"),
        new("上次内核启动日志","armhpc usb-console logs --previous"),new("RGB 状态","armhpc led --status"),
        new("开启蓝色心跳","armhpc led --heartbeat on"),new("关闭蓝色心跳","armhpc led --heartbeat off"),
        new("请求下一次进入 Rescue","armhpc rescue"),new("进入 Rescue 并重启","armhpc rescue --reboot"),
        new("取消 Rescue 启动请求","armhpc rescue --cancel"),new("正常重启设备","armhpc reboot"),
        new("Rescue 综合状态","armhpc-rescue status"),new("Rescue SATA 安装预览","armhpc-rescue install --disk /dev/sda"),
        new("Rescue SATA 恢复预览","armhpc-rescue restore --disk /dev/sda"),new("K3s 检查","armhpc-kube check"),
        new("普通系统配置向导","armhpc configuration"),new("Rescue 配置向导","armhpc-rescue configuration"),
        new("K3s 配置向导","armhpc-kube configuration")];

    public static ArmHpcRequest Parse(string text)
    {
        if(text.Length>3000 || text.IndexOfAny(['\r','\n','\0'])>=0)throw new ArgumentException("请输入一条长度不超过 3000 的 ARMHPC 命令。");
        var tokens=new List<string>();var value=new StringBuilder();char quote='\0';bool started=false;
        foreach(char c in text)
        {
            if(quote!='\0'){if(c==quote)quote='\0';else value.Append(c);started=true;continue;}
            if(c is '\'' or '"'){quote=c;started=true;continue;}
            if(char.IsWhiteSpace(c)){if(started){tokens.Add(value.ToString());value.Clear();started=false;}continue;}
            if(c is ';' or '|' or '&' or '<' or '>' or '`' or '$')throw new ArgumentException("命令区只接受 ARMHPC 命令和参数，不接受 shell 运算符。");
            value.Append(c);started=true;
        }
        if(quote!='\0')throw new ArgumentException("引号未闭合。");if(started)tokens.Add(value.ToString());
        if(tokens.Count==0 || tokens[0] is not ("armhpc" or "armhpc-rescue" or "armhpc-kube"))throw new ArgumentException("命令必须以 armhpc、armhpc-rescue 或 armhpc-kube 开头。");
        string program=tokens[0];string[] args=tokens.Skip(1).ToArray();string first=args.FirstOrDefault()??"--help";
        if(args.Length==0)args=["--help"];
        string[] allowed=program=="armhpc"?["--help","-h","watchdog","ota","usb-console","led","rescue","reboot","configuration","firstrun"]:
            program=="armhpc-kube"?["--help","-h","configuration","check"]:
            ["--help","-h","watchdog","ota","usb-console","led","boot","status","install","restore","reboot","configuration","console","provision","firstrun"];
        if(!allowed.Contains(first))throw new ArgumentException("未知 ARMHPC 子命令。");
        if(args.Contains("--daemon") || args.Contains("--watch") || args.Contains("--simulate-root") || args.Contains("--config"))throw new ArgumentException("持续观察请使用任务面板；不允许服务内部或配置重定向参数。");
        bool help=args.Contains("--help") || args.Contains("-h");
        if(first=="ota" && !help)
        {
            string op=args.ElementAtOrDefault(1)??"";
            if(!new[]{"bootstrap","check","plan","download","apply","status","logs","cancel","recover","source","doctor","retry","tools","receive","boot"}.Contains(op))throw new ArgumentException("未知 OTA 子命令。");
        }
        bool writes=!help && (first=="watchdog" && (args.ElementAtOrDefault(1) is "prepare" or "test" || args.Contains("--confirm-recovered") || args.Contains("--manual-recovery") || args.Contains("--cancel-prepared")) || first is "configuration" or "firstrun" or "provision" or "reboot" or "rescue" or "boot" ||
            first=="led" && !args.Contains("--status") || first=="usb-console" && args.Skip(1).Any(x=>x is "start" or "stop") ||
            first is "install" or "restore" && args.Contains("--execute") ||
            first=="ota" && (args.ElementAtOrDefault(1)=="boot" && args.ElementAtOrDefault(2) is "apply" or "rollback" || args.ElementAtOrDefault(1) is "apply" or "recover" or "cancel" or "retry" or "receive" || args.ElementAtOrDefault(1)=="bootstrap" && args.Contains("--apply") || args.ElementAtOrDefault(1)=="source" && args.ElementAtOrDefault(2)=="set" || args.ElementAtOrDefault(1)=="tools" && args.ElementAtOrDefault(2)=="update"));
        bool interactive=!help && (first is "configuration" or "firstrun" or "provision" or "console" || first is "install" or "restore" && args.Contains("--execute"));
        if(first is "ota" or "watchdog" && writes && !args.Contains("--yes"))args=[..args,"--yes"];
        return new(program,args,writes,interactive,first=="reboot" || args.Contains("--reboot"));
    }
}

public sealed record CommandReply(int ExitCode,string Output,string Error,string Hostname,string Mode,string DeviceId,bool RebootConfirmed=false,string? BootIdBefore=null,string? BootIdAfter=null);
