// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
using System.Text.Json;
using System.Net;
namespace ArmHpc.Ota.Cli;

public static class CommandCli
{
    public static async Task<int> Run(string[] args,Vault? testVault=null)
    {
        var flags=new HashSet<string>{"--json","--yes","--ignore-unknown","--pilot","--all-managed","--exact-hostname","--remember","--ignore-fingerprint"};
        var valued=new HashSet<string>{"--command","--ssh","--serial","--devices-csv","--hostname","--concurrency","--port","--username","--password-env","--key","--passphrase-env","--reboot-timeout","--scan-range","--serial-reconnect"};
        var values=new Dictionary<string,List<string>>();bool json=args.Contains("--json");
        string? One(string name)=>values.GetValueOrDefault(name)?.LastOrDefault();bool Has(string name)=>values.ContainsKey(name);
        try
        {
            for(int i=0;i<args.Length;i++)
            {
                string option=args[i];if(!flags.Contains(option) && !valued.Contains(option))throw new ArgumentException("未知 command 参数："+option);
                string value=flags.Contains(option)?"true":++i<args.Length?args[i]:throw new ArgumentException("参数缺少值："+option);
                if(!values.TryGetValue(option,out var list))values[option]=list=[];list.Add(value);
            }
            var request=ArmHpcCommands.Parse(One("--command")??throw new ArgumentException("需要 --command，例如 \"armhpc ota status --json\"。"));
            if(request.Interactive)throw new ArgumentException("交互命令使用 GUI 的单台 SSH 终端。");
            int concurrency=int.Parse(One("--concurrency")??"1");BatchQueue.ValidateConcurrency(concurrency);
            var vault=testVault??new Vault();var saved=vault.LoadDevices();var targets=new List<Device>();
            void Add(Device device){if(!targets.Any(d=>d.DeviceId==device.DeviceId))targets.Add(device);}
            Device Known(string address,string transport,int? port=null)=>saved.FirstOrDefault(d=>d.Transport==transport && d.Address==address && (port is null || d.Port==port))??throw new ArgumentException("设备未登记："+address+"。先用 GUI 或 CLI status 登记并核对 SSH 身份。");
            if(Has("--all-managed"))foreach(var d in saved)Add(d);
            foreach(string address in values.GetValueOrDefault("--ssh")??[])
            {
                if(!IPAddress.TryParse(address,out var ip) || ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork)throw new ArgumentException("SSH 地址需要 IPv4。");
                Add(Known(ip.ToString(),"ssh",One("--port") is {} p?int.Parse(p):null));
            }
            foreach(string port in values.GetValueOrDefault("--serial")??[])Add(Known(port.ToUpperInvariant(),"serial"));
            foreach(string file in values.GetValueOrDefault("--devices-csv")??[])foreach(var d in Csv.Import(File.ReadAllText(file)))Add(Known(d.Address,d.Transport,d.Port));
            if(One("--hostname") is {} name)targets=targets.Where(d=>DeviceSelection.Matches(d,name,Has("--exact-hostname"))).ToList();
            if(targets.Count==0)throw new ArgumentException("没有命令目标。使用重复 --ssh、--serial、--devices-csv 或显式 --all-managed。");
            int rebootSeconds=int.Parse(One("--reboot-timeout")??"180");if(rebootSeconds<10 || rebootSeconds>900)throw new ArgumentException("重启确认超时必须为 10–900 秒。");
            var ranges=values.GetValueOrDefault("--scan-range")?.ToArray()??[];foreach(string range in ranges)Scanner.Expand(range);
            if(values.TryGetValue("--serial-reconnect",out var ports))foreach(var d in targets)d.SerialPorts=ports.ToArray();
            foreach(var d in targets)d.IgnoreFingerprint=Has("--ignore-fingerprint");
            if(Has("--ignore-fingerprint"))Console.Error.WriteLine("当前命令临时忽略 SSH 指纹；设备 ID 仍将核对。");
            if(Has("--remember") && !OperatingSystem.IsWindows())throw new ArgumentException("Linux 不保存登录密码；使用 SSH 私钥或每次输入凭据。");
            Credentials? supplied=null;
            if(Has("--username") || Has("--password-env") || Has("--key"))
            {
                string password=Has("--key")?"":One("--password-env") is {} env?Environment.GetEnvironmentVariable(env)??throw new ArgumentException("密码环境变量未设置。"):ReadPassword();
                string? phrase=One("--passphrase-env") is {} pe?Environment.GetEnvironmentVariable(pe)??throw new ArgumentException("私钥口令环境变量未设置。"):null;
                supplied=new(One("--username")??"root",password,One("--key"),phrase);
            }
            var credentials=new Dictionary<Device,Credentials>();
            foreach(var d in targets)
            {
                var c=supplied??vault.LoadConnection(d)??vault.LoadDefault();
                if(c is null){supplied=new("root",ReadPassword());c=supplied;}
                credentials[d]=c;
            }
            bool ignore=Has("--ignore-unknown");
            if(request.Writes && !Has("--yes"))
            {
                if(json || Console.IsInputRedirected)throw new ArgumentException("审核命令和目标后使用 --yes。");
                Console.Error.Write($"命令：{request.Label}\n目标：{string.Join(", ",targets.Select(d=>d.Hostname.Length>0?d.Hostname:d.Address))}\n并发：{concurrency}，未知结果继续：{ignore}\n开始？[y/N]: ");
                if(Console.ReadLine()?.Trim().ToLowerInvariant() is not ("y" or "yes"))return 130;
            }
            using var stopping=new CancellationTokenSource();var queue=new BatchQueue();
            Console.CancelKeyPress+=(_,e)=>{e.Cancel=true;queue.Stop();stopping.Cancel();};using var router=new ConnectionRouter();
            var report=await CommandBatch.Run(targets,request,new(concurrency,ignore,Has("--pilot")),
                async device=>
                {
                    var result=await router.ExecuteArmHpc(new(device.Address,device.Port),credentials[device],device,request,stopping.Token,new(rebootSeconds,ranges),stage=>Console.Error.WriteLine(device.Address+" · "+stage));
                    if(result.Hostname.Length>0)device.Hostname=result.Hostname;device.Mode=result.Mode;return result;
                },result=>Console.Error.WriteLine(result.Address+" · "+result.Status),queue,stopping.Token);
            vault.SaveDevices(saved);if(Has("--remember"))foreach(var d in targets)vault.SaveConnection(d,credentials[d]);
            Console.WriteLine(JsonSerializer.Serialize(new{protocol=1,ok=true,data=report},new JsonSerializerOptions{WriteIndented=!json,PropertyNamingPolicy=JsonNamingPolicy.SnakeCaseLower}));
            if(stopping.IsCancellationRequested)return 130;if(report.Failed>0 || report.Skipped>0)return 2;
            return report.Unknown>0 && !ignore?3:0;
        }
        catch(Exception error)
        {
            if(json)Console.WriteLine(JsonSerializer.Serialize(new{protocol=1,ok=false,error=new{code="command_controller",message=error.Message}}));
            else Console.Error.WriteLine(error.Message);return 2;
        }
    }
    static string ReadPassword()
    {
        if(Console.IsInputRedirected)throw new ArgumentException("请使用已保存凭据、默认登录或 --password-env。");
        Console.Error.Write("密码：");var value=new System.Text.StringBuilder();
        while(true){var key=Console.ReadKey(true);if(key.Key==ConsoleKey.Enter)break;if(key.Key==ConsoleKey.Backspace){if(value.Length>0)value.Length--;}else if(!char.IsControl(key.KeyChar))value.Append(key.KeyChar);}
        Console.Error.WriteLine();return value.ToString();
    }
}
