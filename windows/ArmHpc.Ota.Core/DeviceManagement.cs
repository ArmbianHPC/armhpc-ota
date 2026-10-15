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
        return new[]{device.Hostname,device.Name,device.MacAddress,device.Address,device.DeviceId}.Any(v=>v.Contains(search,StringComparison.OrdinalIgnoreCase));
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
            else if(args.Length>0 && args[0] is not ("fan" or "watchdog" or "ota" or "usb-console" or "led" or "identify" or "configuration" or "reboot" or "--help" or "-h"))
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

public sealed record CommandPreset(string Name,string Command,bool Development=false);
public static class ArmHpcCommands
{
    public static IReadOnlyList<CommandPreset> Presets {get;} = [
        new("风扇状态","armhpc fan status --json"),new("风扇自动温控","armhpc fan set --mode auto --yes --json"),
        new("风扇开启","armhpc fan set --mode on --yes --json"),new("风扇关闭（保留高温保护）","armhpc fan set --mode off --yes --json"),
        new("看门狗状态","armhpc watchdog status --json",true),new("看门狗诊断报告","armhpc watchdog report --json",true),new("BOOT 维护状态","armhpc ota boot status --json",true),
        new("主机名","armhpc hostname show --json"),new("网络配置和事务","armhpc network show --json"),
        new("主机名向导","armhpc hostname configure"),new("网络配置向导","armhpc network configure"),
        new("ARMHPC 帮助","armhpc --help"),new("OTA 状态和版本","armhpc ota status --json"),
        new("OTA 任务日志","armhpc ota logs --json"),new("OTA 工具一致性","armhpc ota tools status --json"),
        new("OTA 诊断","armhpc ota doctor --json"),new("OTA 接入预览","armhpc ota bootstrap --json"),
        new("本地初始系统恢复计划","armhpc ota plan --release initial --target system --recovery --json"),
        new("OTG 串口状态","armhpc usb-console status --json"),new("当前内核启动日志","armhpc usb-console logs",true),
        new("上次内核启动日志","armhpc usb-console logs --previous",true),new("RGB 状态","armhpc led --status"),
        new("网口绿灯定位（30 秒）","armhpc identify --seconds 30 --json"),new("停止网口定位","armhpc identify --stop --json"),
        new("网口定位状态","armhpc identify --status --json"),
        new("开启蓝色心跳","armhpc led --heartbeat on",true),new("关闭蓝色心跳","armhpc led --heartbeat off",true),
        new("请求下一次进入 Rescue","armhpc rescue"),new("进入 Rescue 并重启","armhpc rescue --reboot"),
        new("取消 Rescue 启动请求","armhpc rescue --cancel"),new("正常重启设备","armhpc reboot"),
        new("Rescue 综合状态","armhpc-rescue status"),new("Rescue SATA 安装预览","armhpc-rescue install --disk /dev/sda"),
        new("Rescue SATA 恢复预览","armhpc-rescue restore --disk /dev/sda"),new("K3s 检查","armhpc-kube check"),
        new("普通系统配置向导","armhpc configuration"),new("Rescue 配置向导","armhpc-rescue configuration"),
        new("K3s 配置向导","armhpc-kube configuration")];

    public static IReadOnlyList<CommandPreset> ManagementPresets => Presets.Where(p=>!p.Development).ToArray();
    public static IReadOnlyList<CommandPreset> DevelopmentPresets => Presets.Where(p=>p.Development).ToArray();

    private static void ValidateHostSettings(string command,string[] args)
    {
        string action=args.ElementAtOrDefault(1) is { } value && !value.StartsWith("--")?value:"show";
        string[] operations=command=="hostname"?["show","set","configure"]:["show","set","configure","confirm","rollback"];
        if(!operations.Contains(action))throw new ArgumentException("未知主机名或网络配置操作。");
        int start=action==args.ElementAtOrDefault(1)?2:1;
        if(command=="hostname")
        {
            if(action=="set")
            {
                string name=args.ElementAtOrDefault(start++)??"";
                if(name.Length is <1 or >64 || name.Split('.').Any(label=>!Regex.IsMatch(label,@"\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z")) ||
                   new[]{"armbian","armhpc","localhost","localhost.localdomain"}.Contains(name.ToLowerInvariant()))throw new ArgumentException("主机名格式无效或为保留名称。");
            }
            if(args.Skip(start).Any(option=>option is not ("--json" or "--yes")))throw new ArgumentException("未知主机名配置参数。");
            return;
        }
        var seen=new HashSet<string>();
        for(int index=start;index<args.Length;index++)
        {
            string option=args[index];
            if(!seen.Add(option) && option!="--dns")throw new ArgumentException("网络配置参数不可重复。");
            if(option is "--json" or "--yes")continue;
            if(option is "--dhcp" or "--plan")
            {
                if(action!="set")throw new ArgumentException("此网络参数仅用于 set。");
                continue;
            }
            if(option is not ("--interface" or "--address" or "--gateway" or "--dns" or "--rollback-after" or "--transaction") || ++index>=args.Length || args[index].StartsWith("--"))
                throw new ArgumentException("未知网络配置参数或缺少值。");
            if(option=="--interface" && (!Regex.IsMatch(args[index],@"\A[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}\z") || args[index]=="lo"))throw new ArgumentException("网口名称无效。");
            if(option=="--transaction" && (action is not ("confirm" or "rollback") || !Guid.TryParse(args[index],out _)))throw new ArgumentException("确认或回滚需要有效事务 ID。");
            if(option=="--rollback-after" && (action is not ("set" or "configure") || !int.TryParse(args[index],out int seconds) || seconds<30 || seconds>600))throw new ArgumentException("回滚确认时间为 30–600 秒。");
            if(option is "--address" or "--gateway" or "--dns" && action!="set")throw new ArgumentException("地址参数仅用于 set。");
            if(option=="--interface" && action is "confirm" or "rollback")throw new ArgumentException("事务已绑定网口，无需另行指定。");
        }
        if(action=="set" && seen.Contains("--dhcp")==seen.Contains("--address"))throw new ArgumentException("请选择 DHCP 或静态 IPv4 地址。");
        if(seen.Contains("--gateway") && !seen.Contains("--address"))throw new ArgumentException("静态网关需要静态地址。");
    }

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
        string[] allowed=program=="armhpc"?["--help","-h","fan","watchdog","ota","usb-console","led","identify","hostname","network","rescue","reboot","configuration","firstrun"]:
            program=="armhpc-kube"?["--help","-h","configuration","check"]:
            ["--help","-h","fan","emmc","watchdog","ota","usb-console","led","identify","boot","status","install","restore","reboot","configuration","console","provision","firstrun"];
        if(!allowed.Contains(first))throw new ArgumentException("未知 ARMHPC 子命令。");
        if(args.Contains("--daemon") || args.Contains("--watch") || args.Contains("--simulate-root") || args.Contains("--config") || args.Contains("--worker"))throw new ArgumentException("持续观察请使用任务面板；不允许服务内部或配置重定向参数。");
        bool help=args.Contains("--help") || args.Contains("-h");
        if(first=="ota" && !help)
        {
            string op=args.ElementAtOrDefault(1)??"";
            if(!new[]{"bootstrap","check","plan","download","apply","status","logs","cancel","recover","source","doctor","retry","tools","receive","boot"}.Contains(op))throw new ArgumentException("未知 OTA 子命令。");
        }
        if(first=="identify" && !help)
        {
            var seen=new HashSet<string>();
            for(int i=1;i<args.Length;i++)
            {
                string option=args[i];
                if(!seen.Add(option))throw new ArgumentException("网口定位参数不可重复。");
                if(option is "--json" or "--status" or "--stop")continue;
                if(option is not ("--interface" or "--seconds" or "--period-ms") || ++i>=args.Length)throw new ArgumentException("未知网口定位参数或缺少值。");
                if(option=="--interface")
                {
                    if(!Regex.IsMatch(args[i],@"\A[A-Za-z0-9_.:-]{1,15}\z") || args[i] is "." or "..")throw new ArgumentException("网口名称无效。");
                }
                else if(!int.TryParse(args[i],out int number) || (option=="--seconds" ? number<1 || number>600 : number<200 || number>5000))
                    throw new ArgumentException("定位时间为 1–600 秒，亮灭周期为 200–5000 毫秒。");
            }
            if(seen.Contains("--stop") && seen.Contains("--status"))throw new ArgumentException("停止和查询不能同时使用。");
        }
        if(first is "hostname" or "network" && !help)ValidateHostSettings(first,args);
        if(first=="fan" && !help)
        {
            if(args.ElementAtOrDefault(1) is not ("status" or "set"))throw new ArgumentException("风扇操作为 status 或 set。");
            var seen=new HashSet<string>();
            for(int i=2;i<args.Length;i++)
            {
                if(!seen.Add(args[i]))throw new ArgumentException("风扇参数不可重复。");
                if(args[i] is "--json" or "--yes")continue;
                if(args[i]!="--mode" || ++i>=args.Length || args[i] is not ("auto" or "on" or "off"))throw new ArgumentException("风扇模式为 auto、on 或 off。");
            }
            if((args[1]=="set")!=seen.Contains("--mode"))throw new ArgumentException("仅 set 需要 --mode。");
        }
        bool writes=!help && (first=="fan" && args.ElementAtOrDefault(1)=="set" || first=="emmc" || first is "hostname" or "network" && args.ElementAtOrDefault(1) is "set" or "configure" or "confirm" or "rollback" && !args.Contains("--plan") || first=="watchdog" && (args.ElementAtOrDefault(1) is "prepare" or "test" || args.Contains("--confirm-recovered") || args.Contains("--manual-recovery") || args.Contains("--cancel-prepared")) || first is "configuration" or "firstrun" or "provision" or "reboot" or "rescue" or "boot" ||
            first is "led" or "identify" && !args.Contains("--status") || first=="usb-console" && args.Skip(1).Any(x=>x is "start" or "stop") ||
            first is "install" or "restore" && args.Contains("--execute") ||
            first=="ota" && (args.ElementAtOrDefault(1)=="boot" && args.ElementAtOrDefault(2) is "apply" or "rollback" || args.ElementAtOrDefault(1) is "apply" or "recover" or "cancel" or "retry" or "receive" || args.ElementAtOrDefault(1)=="bootstrap" && args.Contains("--apply") || args.ElementAtOrDefault(1)=="source" && args.ElementAtOrDefault(2)=="set" || args.ElementAtOrDefault(1)=="tools" && args.ElementAtOrDefault(2)=="update"));
        bool interactive=!help && (first is "hostname" or "network" && args.ElementAtOrDefault(1)=="configure" || first is "configuration" or "firstrun" or "provision" or "console" || first is "install" or "restore" && args.Contains("--execute"));
        if(first is "fan" or "emmc" or "ota" or "watchdog" or "hostname" or "network" && writes && !interactive && !args.Contains("--yes"))args=[..args,"--yes"];
        return new(program,args,writes,interactive,first=="reboot" || args.Contains("--reboot"));
    }
}

public sealed record CommandReply(int ExitCode,string Output,string Error,string Hostname,string Mode,string DeviceId,bool RebootConfirmed=false,string? BootIdBefore=null,string? BootIdAfter=null);
