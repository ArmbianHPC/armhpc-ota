// SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;
using System.IO.Ports;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArmHpc.Ota.Core;

public sealed record ConsoleReply(int ExitCode,string Output,string Error);

public static class ConsoleProtocol
{
    public static string Wrap(string command,string nonce)
    {
        if(!Regex.IsMatch(nonce,"^[a-f0-9]{32}$"))throw new ArgumentException("Invalid frame ID.");
        string encoded=Convert.ToBase64String(Encoding.UTF8.GetBytes(command));
        string code="import subprocess,json,base64; r=subprocess.run(['/bin/sh','-c',base64.b64decode('"+encoded+"').decode('utf-8')],text=True,capture_output=True); print('\\n__ARMHPC_"+nonce+"__:'+base64.b64encode(json.dumps({'rc':r.returncode,'out':r.stdout,'err':r.stderr}).encode()).decode()+':__END__',flush=True)";
        string line="python3 -c "+Commands.Quote(code);
        if(Encoding.UTF8.GetByteCount(line)>3500)throw new ArgumentException("Console command is too long; upload a script instead.");
        return line;
    }
    public static ConsoleReply? Decode(string text,string nonce)
    {
        var match=Regex.Match(CleanTerminal(text),@"(?:^|[\r\n])__ARMHPC_"+Regex.Escape(nonce)+@"__:([A-Za-z0-9+/=]+):__END__(?:\r*\n|$)");
        if(!match.Success)return null;
        if(match.Groups[1].Length>12*1024*1024)throw new InvalidOperationException("Console response is oversized.");
        using var document=JsonDocument.Parse(Convert.FromBase64String(match.Groups[1].Value));var value=document.RootElement;
        return new(value.GetProperty("rc").GetInt32(),value.GetProperty("out").GetString()!,value.GetProperty("err").GetString()!);
    }
    public static string CleanTerminal(string text)
    {
        // OSC window titles/hyperlinks and CSI colours/bracketed paste are not prompts.
        text=Regex.Replace(text,@"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)","");
        text=Regex.Replace(text,@"\x1b\[[0-?]*[ -/]*[@-~]","");
        return text.Replace("\0","");
    }
    public static string Prompt(string text)
    {
        text=CleanTerminal(text);
        if(Regex.IsMatch(text,@"password[：:]\s*$",RegexOptions.IgnoreCase))return "password";
        if(Regex.IsMatch(text,@"login[：:]\s*$",RegexOptions.IgnoreCase))return "login";
        if(Regex.IsMatch(text,@"(?:选择|select|choice)[^\r\n]*[\[［]0[\]］]\s*[：:]?\s*$",RegexOptions.IgnoreCase))return "menu";
        // Several real consoles omit the trailing space, or use CR without LF.
        if(Regex.IsMatch(text,@"(?:^|[\r\n])[^\r\n]*[#$]\s*$"))return "shell";
        if(Regex.IsMatch(text,@"(?:login incorrect|authentication failure|access denied)",RegexOptions.IgnoreCase))return "rejected";
        return "waiting";
    }
    public static void VerifyIdentity(Device device,JsonElement data)
    {
        string id=Protocol.Text(data,"device_id"),mode=Protocol.Text(data,"mode");
        if(id.Length==0 || mode is not ("system" or "rescue") || (device.Managed && id!=device.DeviceId))
            throw new InvalidOperationException("串口设备身份不匹配，拒绝执行设备操作。");
    }
}

public interface IConsoleWire:IDisposable
{
    string Read();
    void Write(string value);
}

public sealed class ConsoleDisconnectedException(string message,Exception? inner=null):IOException(message,inner);

/// <summary>Normalize only wire I/O failures, never CLI rejection or identity errors.</summary>
public sealed class SafeConsoleWire(IConsoleWire inner):IConsoleWire
{
    public string Read()
    {
        try{return inner.Read();}
        catch(Exception e) when(e is IOException or InvalidOperationException or TimeoutException)
        {throw new ConsoleDisconnectedException("串口暂时断开或未打开，等待设备重连。",e);}
    }
    public void Write(string value)
    {
        try{inner.Write(value);}
        catch(Exception e) when(e is IOException or InvalidOperationException or TimeoutException)
        {throw new ConsoleDisconnectedException("串口写入回应未知，重连后核对原任务。",e);}
    }
    public void Dispose()
    {
        try{inner.Dispose();}
        catch(Exception e) when(e is IOException or InvalidOperationException or TimeoutException){}
    }
}

public sealed class SerialWire:IConsoleWire
{
    private readonly SerialPort port;
    public SerialWire(string name,int baud)
    {
        bool valid=OperatingSystem.IsWindows()
            ? Regex.IsMatch(name,"^COM[1-9][0-9]*$",RegexOptions.IgnoreCase)
            : Regex.IsMatch(name,@"^/dev/(?:tty[A-Za-z][A-Za-z0-9]*|serial/by-(?:id|path)/[^/\s]+|pts/[0-9]+)$") && !name.Contains("..");
        if(!valid || baud<1200 || baud>3000000)
            throw new ArgumentException("请输入 COM 或 /dev/ttyACM0、/dev/ttyUSB0 等串口和有效波特率。");
        bool modemLines=!name.StartsWith("/dev/pts/",StringComparison.Ordinal);
        port=new SerialPort(name,baud,Parity.None,8,StopBits.One){Encoding=Encoding.UTF8,Handshake=Handshake.None,DtrEnable=modemLines,RtsEnable=modemLines,ReadTimeout=200,WriteTimeout=30000};
        port.Open();
    }
    public string Read()=>port.ReadExisting();
    public void Write(string value)=>port.Write(value);
    public void Dispose()=>port.Dispose();
}

/// <summary>One framed command at a time. Terminal output and passwords never enter logs.</summary>
public sealed partial class ConsoleSession(IConsoleWire rawWire):IDisposable
{
    private readonly IConsoleWire wire=new SafeConsoleWire(rawWire);
    private readonly SemaphoreSlim gate=new(1,1);
    private int disposed;
    public async Task Login(Credentials credentials,CancellationToken token,Action<string>? progress=null,
        TimeSpan? timeout=null,TimeSpan? probeTimeout=null)
    {
        if(credentials.PrivateKeyPath is {Length:>0})throw new ArgumentException("串口登录需要用户名和密码，不能使用 SSH 私钥。");
        if(credentials.Username.Length==0 || credentials.Username.Any(char.IsControl) || credentials.Password.Any(char.IsControl))
            throw new ArgumentException("用户名不能为空，登录内容不能包含控制字符。");
        var buffer=new StringBuilder();var deadline=Stopwatch.StartNew();
        var limit=timeout??TimeSpan.FromSeconds(20);int users=0,passwords=0,menus=0;
        string phase="等待 Linux 登录提示";progress?.Invoke(phase);
        // Clear an unfinished shell/getty input line without interrupting a running command.
        token.ThrowIfCancellationRequested();wire.Write("\u0015\r");
        while(deadline.Elapsed<limit)
        {
            token.ThrowIfCancellationRequested();buffer.Append(wire.Read());
            if(buffer.Length>65536)buffer.Remove(0,buffer.Length-32768);
            string prompt=ConsoleProtocol.Prompt(buffer.ToString());
            switch(prompt)
            {
                case "rejected":throw new InvalidOperationException("串口登录被设备拒绝，请核对用户名和密码。");
                case "login":
                    if(++users>1)throw new InvalidOperationException("串口登录被设备拒绝（再次请求登录）；本次凭据不会自动重复提交。");
                    phase="已发送用户名，等待密码提示";progress?.Invoke(phase);
                    wire.Write(credentials.Username+"\r");buffer.Clear();break;
                case "password":
                    if(++passwords>1)throw new InvalidOperationException("设备再次请求密码；本次凭据不会自动重复提交。");
                    phase="已发送密码，等待命令行或配置菜单";progress?.Invoke(phase);
                    wire.Write(credentials.Password+"\r");buffer.Clear();break;
                case "menu":
                    if(++menus>3)throw new InvalidOperationException("无法退出 ARMHPC 登录配置菜单，请在终端选择 0 后重试。");
                    phase="退出首次登录配置菜单";progress?.Invoke(phase);
                    wire.Write("0\r");buffer.Clear();break;
                case "shell":
                    phase="验证命令行回应";progress?.Invoke(phase);
                    // A fresh framed response proves this is a live shell; an old banner cannot authenticate it.
                    var probe=await Run("true",probeTimeout??TimeSpan.FromSeconds(5),token).ConfigureAwait(false);
                    if(probe.ExitCode!=0)throw new InvalidOperationException("串口命令行探针失败；请确认 python3 可用。");
                    progress?.Invoke("命令行已就绪");return;
            }
            await Task.Delay(30,token).ConfigureAwait(false);
        }
        throw new TimeoutException("串口登录等待超时（"+phase+"）。请关闭其他串口终端，检查端口和设备控制台状态。");
    }
    public async Task<ConsoleReply> Run(string command,TimeSpan timeout,CancellationToken token)
    {
        await gate.WaitAsync(token);
        try
        {
            string nonce=Guid.NewGuid().ToString("N");wire.Read();wire.Write(ConsoleProtocol.Wrap(command,nonce)+"\r");
            var buffer=new StringBuilder();var deadline=Stopwatch.StartNew();
            while(deadline.Elapsed<timeout)
            {
                token.ThrowIfCancellationRequested();buffer.Append(wire.Read());
                if(buffer.Length>16*1024*1024)throw new InvalidOperationException("Console output exceeds the response bound.");
                var result=ConsoleProtocol.Decode(buffer.ToString(),nonce);if(result is not null)return result;
                if(ConsoleProtocol.Prompt(buffer.ToString()) is "login" or "password" or "menu")
                    throw new ConsoleDisconnectedException("串口返回登录提示，设备可能已重启；重连后查询原任务。");
                await Task.Delay(25,token);
            }
            throw new TimeoutException("串口命令结果未知；重连后按原任务 ID 查询。");
        }
        finally{gate.Release();}
    }
    public void Dispose(){if(Interlocked.Exchange(ref disposed,1)==0)wire.Dispose();}
    // Do not dispose the managed semaphore while a cancelled operation is releasing it.
}

public sealed partial class SerialRunner(Func<Device,IConsoleWire>? wireFactory=null):IDisposable
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string,ConsoleSession> sessions=new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string,SemaphoreSlim> portGates=new(StringComparer.OrdinalIgnoreCase);
    public static string[] Ports()=>SerialPort.GetPortNames().Order(StringComparer.OrdinalIgnoreCase).ToArray();
    private async Task<ConsoleSession> Session(Device device,Credentials credentials,CancellationToken token,
        bool fresh=false,Action<string>? progress=null)
    {
        if(fresh && sessions.TryRemove(device.Address,out var previous))previous.Dispose();
        if(sessions.TryGetValue(device.Address,out var current))return current;
        progress?.Invoke("打开串口 "+device.Address);
        token.ThrowIfCancellationRequested();
        IConsoleWire wire;
        try{wire=wireFactory?.Invoke(device)??new SerialWire(device.Address,device.BaudRate);}
        catch(UnauthorizedAccessException error){throw new ConsoleDisconnectedException("串口 "+device.Address+" 被其他程序占用或暂时不可用，请关闭其他终端或等待重启枚举。",error);}
        var session=new ConsoleSession(wire);
        try
        {
            using var cancelled=token.Register(session.Dispose);
            token.ThrowIfCancellationRequested();
            await session.Login(credentials,token,progress).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();sessions[device.Address]=session;return session;
        }
        catch{session.Dispose();throw;}
    }
    private static string Privileged(Credentials c,string command)=>(c.Username!="root"?"sudo -n -- ":"")+command;
    private async Task<JsonElement> Query(ConsoleSession session,string command,CancellationToken token,TimeSpan? timeout=null)
    {
        var result=await session.Run(command,timeout??TimeSpan.FromMinutes(30),token);
        if(string.IsNullOrWhiteSpace(result.Output))throw new InvalidOperationException("设备未返回 CLI JSON；退出码："+result.ExitCode);
        return Protocol.Decode(result.Output);
    }
    private Task<T> Use<T>(Device device,Credentials credentials,Func<ConsoleSession,Task<T>> action,CancellationToken token,
        bool fresh=false,Action<string>? progress=null)
        =>Task.Run(async()=>
        {
            // Native COM open/read/write can block; never perform them on the WPF dispatcher.
            string port=device.Address;var portGate=portGates.GetOrAdd(port,_=>new SemaphoreSlim(1,1));
            await portGate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                var session=await Session(device,credentials,token,fresh,progress).ConfigureAwait(false);
                using var cancelled=token.Register(session.Dispose);
                token.ThrowIfCancellationRequested();return await action(session).ConfigureAwait(false);
            }
            catch(Exception error)
            {
                if(sessions.TryRemove(port,out var session))session.Dispose();
                if(token.IsCancellationRequested)throw new OperationCanceledException("串口结果观察已取消；设备任务不会被重新提交。",error,token);
                if(error is IOException or TimeoutException)
                    throw new TransientConnectionException("串口断开或结果未知："+error.Message+" 设备服务任务可按原 ID 查询。",error);
                throw;
            }
            finally{portGate.Release();}
        },token);
    public Task<RemoteResult> Execute(Device device,Credentials credentials,string operation,IReadOnlyList<string> arguments,bool yes,CancellationToken token)
        =>Use(device,credentials,async session=>
        {
            var identity=await Query(session,Commands.Build("status",[],credentials.Username!="root"),token,TimeSpan.FromSeconds(30));ConsoleProtocol.VerifyIdentity(device,identity);
            var host=await session.Run(SshRunner.HostnameCommand,TimeSpan.FromSeconds(8),token);
            var result=operation=="status" && arguments.Count==0?identity:await Query(session,Commands.Build(operation,arguments,credentials.Username!="root",yes),token,operation is "status" or "logs"?TimeSpan.FromSeconds(30):TimeSpan.FromMinutes(30));
            return new RemoteResult(result,"",Protocol.Text(identity,"mode"),host.ExitCode==0?host.Output.Trim():"");
        },token);
    public Task<JsonElement> MaintenanceStatus(Device device,Credentials credentials,CancellationToken token,bool rollback=false)
        =>Use(device,credentials,async session=>
        {
            var identity=await Query(session,Privileged(credentials,"python3 -c "+Commands.Quote(SshRunner.MaintenanceIdentityCode)),token,TimeSpan.FromSeconds(30));ConsoleProtocol.VerifyIdentity(device,identity);
            return rollback?await Query(session,Privileged(credentials,"python3 /var/lib/armhpc/ota/maintenance/runner.py --rollback"),token):identity;
        },token);
    private async Task<string> Transfer(ConsoleSession session,byte[] content,string name,CancellationToken token)
    {
        if(content.Length>256*1024*1024)throw new ArgumentException("上传文件超过维护包大小限制。");
        string directory="/tmp/armhpc-ota-upload-"+Guid.NewGuid().ToString("N"),file=directory+"/"+name;
        async Task Check(string command){var r=await session.Run(command,TimeSpan.FromSeconds(30),token);if(r.ExitCode!=0)throw new InvalidOperationException("串口上传步骤失败；退出码："+r.ExitCode);}
        await Check("umask 077; mkdir "+Commands.Quote(directory));
        string encoded=Convert.ToBase64String(content);
        for(int offset=0;offset<encoded.Length;offset+=768)
            await Check("printf %s "+Commands.Quote(encoded.Substring(offset,Math.Min(768,encoded.Length-offset)))+" >> "+Commands.Quote(file+".b64"));
        if(encoded.Length==0)await Check("touch "+Commands.Quote(file+".b64"));
        await Check("base64 -d "+Commands.Quote(file+".b64")+" > "+Commands.Quote(file)+" && chmod 600 "+Commands.Quote(file)+" && rm "+Commands.Quote(file+".b64"));
        var hash=await session.Run("sha256sum "+Commands.Quote(file),TimeSpan.FromSeconds(30),token);
        if(hash.ExitCode!=0 || hash.Output.Split(' ',StringSplitOptions.RemoveEmptyEntries)[0]!=Convert.ToHexStringLower(SHA256.HashData(content)))throw new InvalidOperationException("串口上传 SHA256 不匹配。");
        return file;
    }
    public async Task<string> Upload(Device device,Credentials credentials,string file,CancellationToken token,bool maintenance)
    {
        if(maintenance)await MaintenanceStatus(device,credentials,token);else await Execute(device,credentials,"status",[],false,token);
        if(new FileInfo(file).Length>1024*1024)
        {
            return await Use(device,credentials,async session=>
            {
                var identity=await Query(session,Commands.Build("status",[],credentials.Username!="root"),token,TimeSpan.FromSeconds(30));
                ConsoleProtocol.VerifyIdentity(device,identity);
                if(!Version.TryParse(Protocol.Text(identity,"agent_version"),out var version) || version<new Version(0,3,4))
                    throw new ArgumentException("大型串口上传需要 agent 0.3.4；先安装小型维护包。");
                using var input=File.OpenRead(file);string hash=Convert.ToHexStringLower(SHA256.HashData(input));
                byte[] idBytes=SHA256.HashData(Encoding.UTF8.GetBytes(device.DeviceId+":"+hash));string id=new Guid(idBytes.AsSpan(0,16)).ToString("D");
                string command=Privileged(credentials,"env PYTHONPATH=/usr/lib/armhpc-ota python3 -m armhpc_ota.serial_stream --upload-id "+Commands.Quote(id)+" --sha256 "+Commands.Quote(hash)+" --size "+input.Length);
                await session.StreamFile(command,file,input.Length,hash,_=>{},token);
                var path=await session.Run(Privileged(credentials,"env PYTHONPATH=/usr/lib/armhpc-ota python3 -c "+Commands.Quote("from armhpc_ota.config import Config; print(Config.load().cache / 'uploads' / '"+id+"' / 'bundle')")),TimeSpan.FromSeconds(15),token);
                if(path.ExitCode!=0 || !path.Output.Trim().StartsWith('/'))throw new IOException("无法读取已上传包路径。");
                return path.Output.Trim();
            },token);
        }
        return await Use(device,credentials,s=>Transfer(s,File.ReadAllBytes(file),"payload",token),token);
    }
    public async Task<JsonElement> InstallTools(Device device,Credentials credentials,string bundle,string requestId,CancellationToken token)
    {
        string remote=await Upload(device,credentials,bundle,token,true);
        return await Use(device,credentials,async session=>
        {
            var identity=await Query(session,Privileged(credentials,"python3 -c "+Commands.Quote(SshRunner.MaintenanceIdentityCode)),token,TimeSpan.FromSeconds(30));ConsoleProtocol.VerifyIdentity(device,identity);
            string script=await Transfer(session,Encoding.UTF8.GetBytes(SshRunner.MaintenanceVerifier),"verify.py",token);
            return await Query(session,Privileged(credentials,"python3 "+Commands.Quote(script)+" "+Commands.Quote(remote)+" "+Commands.Quote(requestId)),token);
        },token);
    }
    public void Reset(string port){if(sessions.TryRemove(port,out var session))session.Dispose();}
    public void Dispose(){foreach(var session in sessions.Values)session.Dispose();sessions.Clear();portGates.Clear();}
}
