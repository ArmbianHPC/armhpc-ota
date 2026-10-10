// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

public static class SerialAuthenticationChecks
{
    static Device Device()=>new(){Address="COM7",Transport="serial",DeviceId="serial-fixture"};
    static Credentials Login()=>new("root","fixture-password");
    public static async Task Run(Action<bool,string> check)
    {
        check(ConsoleProtocol.Prompt("\x1b]0;fixture\a\x1b[32mroot@armhpc:~#\x1b[0m")=="shell","serial accepts OSC title, colour and prompt without a trailing space");
        check(ConsoleProtocol.Prompt("stale output\rroot@armhpc:~$")=="shell","serial accepts carriage-return-only prompts");
        check(ConsoleProtocol.Prompt("选择节点用途 ［0］： ")=="menu" && ConsoleProtocol.Prompt("Select [0] : ")=="menu","serial accepts both ARMHPC menu formats and full-width punctuation");
        check(ConsoleProtocol.Prompt("root#\x1b]0;title\x1b\\")=="shell","serial accepts an OSC title terminated by ESC-backslash");
        check(ConsoleProtocol.Prompt("Login incorrect\r\nroot@armhpc:~#")=="shell" && ConsoleProtocol.Prompt("Login incorrect\r\narmhpc login: ")=="login","historic rejection cannot mask the current prompt; submitted credentials remain single attempt");
        string id=Guid.NewGuid().ToString("N");
        string frame=Frame(id,"fixture");
        check(ConsoleProtocol.Decode("\x1b[?2004l\r"+frame.Replace("\r\n","\r\r\n"),id)?.Output=="fixture","serial decodes ANSI and repeated CR around a complete frame");
        using(var wire=new Wire{Menu=true,Fragment=true})using(var runner=new SerialRunner(_=>wire))
        {
            var phases=new List<string>();var result=await runner.Authenticate(Device(),Login(),phases.Add);
            check(result.Hostname=="serial-host" && wire.PasswordWrites==1 && wire.MenuWrites==1,"serial authentication exits a real-format first-login menu and reads identity");
            check(wire.Probes==1 && wire.StatusQueries==1,"authentication requires a live framed shell probe before identity");
            check(phases.Contains("验证命令行回应") && phases.Contains("读取 ARMHPC 设备身份") && phases.Last()=="认证成功","authentication reports login, shell, identity and success phases");
            check(!string.Join(" ",phases).Contains(Login().Password),"authentication progress never includes credentials or raw console text");
        }
        using(var occupied=new SerialRunner(_=>throw new UnauthorizedAccessException()))
        {
            var error=await Failure(()=>occupied.Authenticate(Device(),Login()));
            check(error.Contains("打开串口 COM7") && error.Contains("被其他程序占用"),"occupied COM reports port and the failing phase immediately");
        }
        using(var wire=new Wire{Reject=true})using(var runner=new SerialRunner(_=>wire))
        {
            var error=await Failure(()=>runner.Authenticate(Device(),Login()));
            check(error.Contains("登录被设备拒绝") && wire.PasswordWrites==1 && !error.Contains(Login().Password),"wrong credentials fail once without password retries or disclosure");
        }
        using(var wire=new Wire{RepeatPassword=true})using(var runner=new SerialRunner(_=>wire))
        {
            var error=await Failure(()=>runner.Authenticate(Device(),Login()));
            check(error.Contains("再次请求密码") && wire.PasswordWrites==1,"repeated password prompts cannot create an authentication loop");
        }
        using(var wire=new Wire{Silent=true})using(var runner=new SerialRunner(_=>wire))
        {
            var timer=Stopwatch.StartNew();var error=await Failure(()=>runner.Authenticate(Device(),Login(),timeout:TimeSpan.FromMilliseconds(140)));
            check(error.Contains("等待 Linux 登录提示") && timer.Elapsed<TimeSpan.FromSeconds(2) && wire.Disposed,"silent console timeout is bounded, identifies phase and releases the port");
        }
        using(var wire=new Wire{AlreadyShell=true,NoProbe=true})using(var runner=new SerialRunner(_=>wire))
        {
            var error=await Failure(()=>runner.Authenticate(Device(),Login(),timeout:TimeSpan.FromMilliseconds(160)));
            check(error.Contains("验证命令行回应") && wire.StatusQueries==0 && wire.Disposed,"a stale shell prompt cannot authenticate without a fresh reply");
        }
        using(var wire=new Wire{NoIdentity=true})using(var runner=new SerialRunner(_=>wire))
        {
            var error=await Failure(()=>runner.Authenticate(Device(),Login(),timeout:TimeSpan.FromMilliseconds(350)));
            check(error.Contains("读取 ARMHPC 设备身份") && wire.Disposed,"identity query timeout is distinct from login timeout");
        }
        using(var wire=new Wire{WrongIdentity=true})using(var runner=new SerialRunner(_=>wire))
        {
            var error=await Failure(()=>runner.Authenticate(Device(),Login()));
            check(error.Contains("身份不匹配") && wire.Disposed,"serial identity mismatch releases the session and cannot register another device");
        }
        using(var wire=new Wire{Silent=true})using(var runner=new SerialRunner(_=>wire))using(var cancel=new CancellationTokenSource(120))
        {
            bool cancelled=false;try{await runner.Authenticate(Device(),Login(),token:cancel.Token);}catch(OperationCanceledException){cancelled=true;}
            check(cancelled && wire.Disposed,"user cancellation releases the console and does not become unknown OTA success");
        }
        using(var wire=new Wire{NoIdentity=true})using(var runner=new SerialRunner(_=>wire))using(var cancel=new CancellationTokenSource())
        {
            var first=runner.Authenticate(Device(),Login(),token:cancel.Token);
            var timer=Stopwatch.StartNew();
            while(wire.StatusQueries==0 && timer.Elapsed<TimeSpan.FromSeconds(2))await Task.Delay(10);
            var waiting=await Failure(()=>runner.Authenticate(Device(),Login(),timeout:TimeSpan.FromMilliseconds(90)));
            bool ownerPreserved=wire.StatusQueries==1 && !wire.Disposed && waiting.Contains("等待串口操作完成");
            await cancel.CancelAsync();try{await first;}catch(OperationCanceledException){}
            check(ownerPreserved && wire.Disposed,"cancelled port waiter never closes the existing operation's console");
        }
        var opened=new List<Wire>();
        using(var runner=new SerialRunner(_=>{var w=new Wire{AlreadyShell=true};opened.Add(w);return w;}))
        {
            await runner.Authenticate(Device(),Login());await runner.Authenticate(Device(),Login());
            check(opened.Count==2 && opened[0].Disposed && opened[1].Probes==1,"explicit reauthentication never reuses a stale cached console");
        }
        using(var started=new ManualResetEventSlim())
        {
            int caller=Environment.CurrentManagedThreadId,openedThread=0;
            using var wire=new Wire{AlreadyShell=true};
            using var runner=new SerialRunner(_=>{openedThread=Environment.CurrentManagedThreadId;started.Set();Thread.Sleep(150);return wire;});
            var task=runner.Authenticate(Device(),Login());
            bool asynchronous=!task.IsCompleted && started.Wait(TimeSpan.FromSeconds(3));await task;
            check(asynchronous && openedThread!=caller,"native port open and console I/O run off the caller/UI thread");
        }
        if(Environment.GetEnvironmentVariable("ARMHPC_SERIAL_PTY_SCRIPT") is {} script)
        {
            using var wire=new PtyWire(script);using var console=new ConsoleSession(wire);
            await console.Login(new("fixture","fixture"),CancellationToken.None);
            var reply=await console.Run("printf %s "+Commands.Quote("实际 Linux PTY · 中文 🙂"),TimeSpan.FromSeconds(5),CancellationToken.None);
            check(reply.ExitCode==0 && reply.Output=="实际 Linux PTY · 中文 🙂","actual Linux bash PTY authenticates coloured no-space prompt and returns Unicode framed output");
        }
    }
    static async Task<string> Failure(Func<Task<RemoteResult>> action)
    {
        try{await action();throw new Exception("Expected authentication failure");}
        catch(InvalidOperationException e){return e.Message;}
        catch(TimeoutException e){return e.Message;}
    }
    static string Frame(string id,string output,int rc=0)=>"\r\n__ARMHPC_"+id+"__:"+
        Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new{rc,@out=output,err=""}))+":__END__\r\n";
    sealed class Wire:IConsoleWire
    {
        readonly ConcurrentQueue<string> pending=new();int login;
        public bool Menu,Fragment,AlreadyShell,Reject,RepeatPassword,Silent,NoProbe,NoIdentity,WrongIdentity,Disposed;
        public int PasswordWrites,MenuWrites,Probes,StatusQueries;
        void Send(string text)
        {
            if(Fragment)for(int i=0;i<text.Length;i+=11)pending.Enqueue(text.Substring(i,Math.Min(11,text.Length-i)));
            else pending.Enqueue(text);
        }
        const string Shell="\r\n\x1b]0;fixture\a\x1b[32mroot@serial-host:~#\x1b[0m";
        public void Write(string value)
        {
            if(Disposed)throw new IOException("Fixture wire closed");if(Silent)return;
            if(value=="\r" || value=="\u0015\r")
            {
                if(AlreadyShell){login=3;Send(Shell);}else{login=1;Send("Debian GNU/Linux 12\r\narmhpc login: ");}return;
            }
            if(login==1){login=2;Send("Password: ");return;}
            if(login==2)
            {
                PasswordWrites++;login=3;
                if(Reject)Send("\r\nLogin incorrect\r\narmhpc login: ");
                else if(RepeatPassword)Send("Password: ");
                else if(Menu){login=4;Send("\r\nARMHPC Rescue\r\n选择 ［0］： ");}
                else Send(Shell);return;
            }
            if(login==4){if(value=="0\r")MenuWrites++;login=3;Send(Shell);return;}
            string nonce=Regex.Match(value,"__ARMHPC_([a-f0-9]{32})__").Groups[1].Value;
            if(value.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes("true")))){Probes++;if(NoProbe)return;Send(Frame(nonce,""));}
            else if(value.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes(Commands.Build("status",[],false)))))
            {
                StatusQueries++;if(NoIdentity)return;
                Send(Frame(nonce,JsonSerializer.Serialize(new{protocol=1,ok=true,data=new{device_id=WrongIdentity?"wrong":"serial-fixture",mode="rescue",agent_version="0.3.4"}})));
            }
            else Send(Frame(nonce,"serial-host\n"));
        }
        public string Read(){if(Disposed)throw new IOException("Fixture wire closed");return pending.TryDequeue(out var value)?value:"";}
        public void Dispose()=>Disposed=true;
    }
    sealed class PtyWire:IConsoleWire
    {
        readonly Process process;readonly ConcurrentQueue<string> pending=new();readonly Task reading;bool disposed;
        public PtyWire(string script)
        {
            var info=new ProcessStartInfo("wsl.exe"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(string argument in new[]{"-d","Armbian-HPC-Ubuntu-24.04","--","python3","-u",script})info.ArgumentList.Add(argument);
            process=Process.Start(info)!;
            reading=Task.Run(async()=>{while(await process.StandardOutput.ReadLineAsync() is {} line){using var d=JsonDocument.Parse(line);pending.Enqueue(d.RootElement.GetProperty("data").GetString()!);}});
        }
        public string Read(){if(process.HasExited)throw new IOException("PTY fixture exited");return pending.TryDequeue(out var value)?value:"";}
        public void Write(string value){process.StandardInput.WriteLine(JsonSerializer.Serialize(new{write=value}));process.StandardInput.Flush();}
        public void Dispose()
        {
            if(disposed)return;disposed=true;
            try{process.StandardInput.WriteLine("{\"close\":true}");process.StandardInput.Flush();if(!process.WaitForExit(3000))process.Kill();}
            finally{process.Dispose();}
        }
    }
}
