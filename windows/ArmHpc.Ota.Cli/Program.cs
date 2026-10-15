// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
using ArmHpc.Ota.Core;

static string Password()
{
    if(Console.IsInputRedirected)throw new ArgumentException("重定向输入时请使用 --password-env 环境变量或已保存的凭据。");
    Console.Error.Write("密码：");var value=new System.Text.StringBuilder();
    while(true){var key=Console.ReadKey(true);if(key.Key==ConsoleKey.Enter)break;if(key.Key==ConsoleKey.Backspace){if(value.Length>0)value.Length--;}else if(!char.IsControl(key.KeyChar))value.Append(key.KeyChar);}
    Console.Error.WriteLine();return value.ToString();
}
const string Help="""
ARMHPC OTA controller 1.1.4 — SSH / USB serial automation

  ARMHPC-OTA-CLI command --ssh <IPv4> [--ssh <IPv4> ...] --command "armhpc ..."
      [--devices-csv <inventory.csv> | --all-managed] [--hostname <name>] [--exact-hostname]
      [--concurrency 1..8] [--ignore-unknown] [--ignore-fingerprint] [--pilot]
      [--scan-range <approved-cidr>] [--reboot-timeout 180] [--yes] [--json]
  ARMHPC-OTA-CLI boot-export (--ssh <IPv4> | --serial COM8) --output-directory <private-folder>
  ARMHPC-OTA-CLI usb-rescue --usb-tool-directory <folder> --export <BOOT-export.json> [--prepare | --yes] [--json]
  ARMHPC-OTA-CLI ports [--json]
  ARMHPC-OTA-CLI status --ssh <IPv4> [--port 22]
  ARMHPC-OTA-CLI status --serial COM8 [--baud-rate 115200]
  ARMHPC-OTA-CLI tools-update (--ssh <IPv4> | --serial COM8) --bundle <signed-maintenance.tar.xz>
  ARMHPC-OTA-CLI upgrade (--ssh <IPv4> | --serial COM8) --package <signed-local-package.tar.xz> [--bundle maintenance.tar.xz]
  ARMHPC-OTA-CLI upgrade (--ssh <IPv4> | --serial COM8) --source <signed-index-url>
      [--allow-http] [--release <id>] [--target all|system|rescue]
      [--bundle <signed-maintenance.tar.xz>] [--ca <public-ca.pem>]
      [--scan-range <approved-cidr>] [--serial-reconnect COM9]
      [--minimum-agent 1.1.4] [--yes] [--json]
  ARMHPC-OTA-CLI resume --task <local-automation-id> [--bundle <same-hash-relocated-package>]

Authentication: --username root; password is entered locally or read from --password-env <name>.
SSH keys: --key <private-key-path> [--passphrase-env <name>]. --remember uses Windows DPAPI; Linux uses SSH keys or interactive credentials.
Trust: --hostkey-system SHA256:... --hostkey-rescue SHA256:... ; --ignore-fingerprint is an explicit per-operation override.
Local package push uses SSH/SFTP or streaming USB COM, with the same signed receive/task engine.
Full serial push needs agent 0.3.4; old agents accept the small signed maintenance first.
Linux serial ports use /dev/ttyACM0 or /dev/ttyUSB0.
Register --serial-reconnect COM8 or /dev/ttyACM1 to allow SSH -> COM takeover by persistent device ID.
Watchdog/BOOT commands use "command"; destructive diagnostics require one device and concurrency 1.
Reboot / connection loss is observed by persistent device, maintenance and OTA job IDs.
""";
if(args.Length==0 || args.Contains("--help") || args.Contains("-h")){Console.WriteLine(Help);return 0;}
if(args[0]=="--version"){Console.WriteLine("1.1.4");return 0;}
if(args[0]=="command")return await ArmHpc.Ota.Cli.CommandCli.Run(args.Skip(1).ToArray());
var flags=new HashSet<string>{"--yes","--json","--remember","--allow-http","--ignore-fingerprint","--prepare"};
var valued=new HashSet<string>{"--ssh","--serial","--port","--baud-rate","--source","--release","--target","--bundle","--ca","--scan-range","--serial-reconnect","--minimum-agent","--username","--password-env","--key","--passphrase-env","--hostkey-system","--hostkey-rescue","--device-id","--task","--package","--output-directory","--usb-tool-directory","--export"};
var values=new Dictionary<string,List<string>>();bool json=args.Contains("--json");
string? One(string name)=>values.GetValueOrDefault(name)?.LastOrDefault();
bool Has(string name)=>values.ContainsKey(name);
void Emit(object data)=>Console.WriteLine(JsonSerializer.Serialize(new{protocol=1,ok=true,data},new JsonSerializerOptions{WriteIndented=!json,PropertyNamingPolicy=JsonNamingPolicy.SnakeCaseLower}));
try
{
    for(int i=1;i<args.Length;i++)
    {
        string option=args[i];if(!flags.Contains(option) && !valued.Contains(option))throw new ArgumentException("未知参数："+option);
        string value=flags.Contains(option)?"true":++i<args.Length?args[i]:throw new ArgumentException("参数缺少值："+option);
        if(!values.TryGetValue(option,out var list))values[option]=list=[];list.Add(value);
    }
    if(args[0]=="usb-rescue")
    {
        if(!Has("--prepare") && !Has("--yes"))throw new ArgumentException("先用 --prepare 校验；执行内存启动需 --yes。");
        using var cancelled=new CancellationTokenSource();Console.CancelKeyPress+=(_,e)=>{e.Cancel=true;cancelled.Cancel();};
        var usbResult=await UsbRescue.Run(One("--usb-tool-directory")??throw new ArgumentException("提供 --usb-tool-directory。"),
            One("--export")??throw new ArgumentException("提供 --export BOOT-export.json。"),Has("--prepare"),
            line=>Console.Error.WriteLine(line),cancelled.Token);
        Emit(usbResult);return 0;
    }
    if(Has("--remember") && !OperatingSystem.IsWindows())throw new ArgumentException("Linux 不保存登录密码；使用 SSH 私钥或每次输入凭据。");
    if(args[0]=="ports"){Emit(new{ports=SerialRunner.Ports()});return 0;}
    if(args[0] is not ("status" or "upgrade" or "tools-update" or "resume" or "boot-export"))throw new ArgumentException("未知操作；使用 --help。");
    var vault=new Vault();var devices=vault.LoadDevices().ToList();var tasks=vault.LoadAutomatic().ToList();
    AutomaticTask? task=args[0]=="resume"?tasks.SingleOrDefault(t=>t.TaskId==One("--task"))??throw new ArgumentException("未找到已批准的自动升级任务。"):null;
    Device device;
    if(task is not null)device=devices.Single(d=>d.DeviceId==task.DeviceId);
    else
    {
        if(Has("--ssh")==Has("--serial"))throw new ArgumentException("请选择一种连接：--ssh 或 --serial。");
        string transport=Has("--serial")?"serial":"ssh",address=One("--serial")??One("--ssh")!;
        device=devices.FirstOrDefault(d=>d.Transport==transport && d.Address==address)??new Device{Address=address,Transport=transport};
    }
    device.IgnoreFingerprint=Has("--ignore-fingerprint");
    if(device.IgnoreFingerprint)Console.Error.WriteLine("本次操作临时忽略 SSH 指纹，设备 ID 仍将核对。");
    if(One("--device-id") is {} expected)device.DeviceId=expected;
    if(One("--ssh") is {} ssh){device.Address=ssh;device.Transport="ssh";}
    if(One("--serial") is {} serial){device.Address=serial;device.Transport="serial";}
    if(device.Transport=="ssh" && (!System.Net.IPAddress.TryParse(device.Address,out var ip) || ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork))throw new ArgumentException("SSH 地址必须为 IPv4。");
    device.Port=int.Parse(One("--port")??device.Port.ToString());if(device.Port is <1 or >65535)throw new ArgumentException("SSH 端口无效。");
    device.BaudRate=int.Parse(One("--baud-rate")??device.BaudRate.ToString());
    if(values.TryGetValue("--serial-reconnect",out var ports))device.SerialPorts=ports.ToArray();
    foreach(string mode in new[]{"system","rescue"})if(One("--hostkey-"+mode) is {} pin)
    {if(!System.Text.RegularExpressions.Regex.IsMatch(pin,"^SHA256:[A-Za-z0-9+/]{43}$"))throw new ArgumentException("SSH 指纹格式无效。");device.HostKeys[mode]=pin;}
    var credentials=device.Managed?vault.LoadConnection(device):null;
    if(credentials is null && !Has("--username") && !Has("--password-env") && !Has("--key"))credentials=vault.LoadDefault();
    if(credentials is null || Has("--username") || Has("--password-env") || Has("--key"))
    {
        string password=Has("--key")?"":One("--password-env") is {} env?Environment.GetEnvironmentVariable(env)??throw new ArgumentException("密码环境变量未设置。"):Password();
        string? passphrase=One("--passphrase-env") is {} penv?Environment.GetEnvironmentVariable(penv)??throw new ArgumentException("私钥口令环境变量未设置。"):null;
        credentials=new(One("--username")??"root",password,One("--key"),passphrase);
    }
    using var cancellation=new CancellationTokenSource();Console.CancelKeyPress+=(_,e)=>{e.Cancel=true;cancellation.Cancel();};using var router=new ConnectionRouter();
    bool Trust(string address,string fingerprint)
    {
        if(json || Console.IsInputRedirected)return false;
        Console.Error.Write($"SSH {address} 指纹 {fingerprint}\n核对后信任？[y/N]: ");return Console.ReadLine()?.Trim().ToLowerInvariant() is "y" or "yes";
    }
    if(task is null)
    {
        var response=await router.Authenticate(new(device.Address,device.Port),credentials,device,Trust,phase=>Console.Error.WriteLine(device.Address+" · "+phase),cancellation.Token);
        string id=Protocol.Text(response.Data,"device_id");var previous=devices.FirstOrDefault(d=>d.DeviceId==id);
        if(previous is not null && previous!=device)foreach(var pin in previous.HostKeys)device.HostKeys.TryAdd(pin.Key,pin.Value);
        device.DeviceId=id;device.Mode=response.Mode;device.Board=Protocol.Text(response.Data,"board");device.Hostname=response.Hostname;
        if(response.Hostname.Length>0)device.HostnameSource=device.Transport=="serial"?"串口":"SSH";
        if(response.Network is not null){device.MacAddress=response.Network.MacAddress;device.NetworkDetail=response.Network.Detail;}
        if(device.Transport=="ssh")device.HostKeys[response.Mode]=response.Fingerprint;
        if(args[0]=="status"){devices.RemoveAll(d=>d.DeviceId==device.DeviceId);devices.Add(device);vault.SaveDevices(devices);if(Has("--remember"))vault.SaveConnection(device,credentials);Emit(response.Data);return 0;}
        if(args[0]=="boot-export")
        {
            var state=await router.Execute(new(device.Address,device.Port),credentials,device,"boot",["status"],cancellation:cancellation.Token);
            var bootTask=state.Data.GetProperty("task");
            string directory=One("--output-directory")??throw new ArgumentException("提供 --output-directory 私有备份目录。");
            await router.DownloadBoot(new(device.Address,device.Port),credentials,device,bootTask,directory,
                line=>Console.Error.WriteLine(line),cancellation.Token);
            Emit(new{task_id=Protocol.Text(bootTask,"task_id"),directory=Path.GetFullPath(directory),
                exported_backup_sha256=Protocol.Text(bootTask.GetProperty("backups").GetProperty("BOOT-rescue.img.xz"),"sha256")});
            return 0;
        }
        var options=new UpgradeOptions(One("--source")??(args[0]=="tools-update" || Has("--package")?"":throw new ArgumentException("需要 --package 本地 OTA 包。")),One("--release"),One("--target")??"all",Has("--allow-http"),(One("--bundle")??(File.Exists(Path.Combine(AppContext.BaseDirectory,"maintenance/maintenance.tar.xz"))?Path.Combine(AppContext.BaseDirectory,"maintenance/maintenance.tar.xz"):null)),Ca:One("--ca"),MinimumAgent:One("--minimum-agent")??"1.1.4",Ranges:values.GetValueOrDefault("--scan-range")?.ToArray(),ToolsOnly:args[0]=="tools-update",Package:One("--package"));
        task=AutomaticTask.Create(id,options);
        if(!Has("--yes"))
        {
            if(json || Console.IsInputRedirected)throw new ArgumentException("审核自动升级参数后使用 --yes。");
            string summary=options.ToolsOnly
                ? $"设备 {id}，连接 {device.Transport}:{device.Address}。自动上传并验证签名维护包，更新普通系统和 Rescue A/B 的 OTA 工具；必要时重启。"
                : $"设备 {id}，连接 {device.Transport}:{device.Address}，目标 {options.Target}，升级包／源 {options.Package??options.Source}。按需维护工具并提交系统升级，必要时重启。";
            Console.Error.Write(summary+"\n开始？[y/N]: ");
            if(Console.ReadLine()?.Trim().ToLowerInvariant() is not ("y" or "yes"))throw new OperationCanceledException("已取消。");
        }
        tasks.Add(task);
    }
    if(device.Transport=="ssh" && !device.IgnoreFingerprint && (!device.HostKeys.ContainsKey("system") || !device.HostKeys.ContainsKey("rescue")))throw new ArgumentException("自动重启前需登记两种环境的 SSH 指纹。");
    devices.RemoveAll(d=>d.DeviceId==device.DeviceId);devices.Add(device);vault.SaveDevices(devices);
    if(Has("--remember"))vault.SaveConnection(device,credentials);
    void Save(AutomaticTask value){int i=tasks.FindIndex(t=>t.TaskId==value.TaskId);if(i>=0)tasks[i]=value;else tasks.Add(value);vault.SaveAutomatic(tasks);vault.SaveDevices(devices);}
    if(args[0]=="resume" && One("--bundle") is {} relocated)
        task=TaskFiles.RelocateBundle(task,relocated);
    Save(task);Console.Error.WriteLine("自动升级任务："+task.TaskId);
    var result=await AutomaticUpgrade.Run(task,new UpgradeConnection(router,device,credentials,task.Options.Ranges??[]),Save,stage=>Console.Error.WriteLine(stage),cancellation.Token);
    Emit(result);return result.Stage=="succeeded"?0:2;
}
catch(OperationCanceledException){Console.Error.WriteLine("观察已停止，已提交的设备服务任务继续；用原自动任务 ID resume。");return 130;}
catch(Exception error)
{
    if(json)Console.WriteLine(JsonSerializer.Serialize(new{protocol=1,ok=false,error=new{code=error is RemoteRejectedException r?r.Code:"controller",message=error.Message}}));
    else Console.Error.WriteLine(error.Message);
    return 2;
}
