// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
using ArmHpc.Ota.Core;

public static class EnvironmentLoginChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        var key=new Credentials("root","","system-key-fixture", "private-passphrase-fixture");
        var password=new Credentials("root","rescue-password-fixture");
        var login=key with { Ssh=new SshLoginContext { PrimaryEnvironment="system",DefaultLogin=password } };
        check(LoginProfiles.Choices(login,"system").First().Credentials==key,"legacy System key remains the System login");
        check(LoginProfiles.Choices(login,"rescue").Single().Credentials==password,"Rescue uses configured default password instead of the System key");
        check(LoginProfiles.Choices(login).Select(c=>c.Credentials).SequenceEqual(new[]{key,password}),"ambiguous environment considers only explicitly configured distinct logins");
        var savedRescue=new Credentials("recovery-admin","separate-rescue-fixture");
        login=login with { Ssh=new SshLoginContext { PrimaryEnvironment="system",DefaultLogin=password,
            Environments=new Dictionary<string,Credentials>{{"system",key},{"rescue",savedRescue}} } };
        check(LoginProfiles.Choices(login,"rescue").First().Credentials==savedRescue,"explicit Rescue login takes priority over the global default");
        var reverse=savedRescue with { Ssh=login.Ssh };
        check(LoginProfiles.Choices(reverse,"system").First().Credentials==key,"returning to System selects its original key");
        var forced=password with { Ssh=new SshLoginContext { PrimaryOnly=true,PrimaryEnvironment="system",
            Environments=new Dictionary<string,Credentials>{{"system",key}},DefaultLogin=savedRescue } };
        check(LoginProfiles.Choices(forced,"system").Single().Credentials==password,"explicit default reauthentication is not overridden by a saved environment login");
        check(LoginProfiles.Same(key,login) && LoginProfiles.Plain(login).Ssh is null,"runtime login context is stripped before persistence and comparison");
        string serialized=JsonSerializer.Serialize(login);
        check(!serialized.Contains("rescue-password-fixture") && !serialized.Contains("separate-rescue-fixture") && !serialized.Contains("Environments"),"runtime alternate secrets and callbacks do not enter serialized credentials");
        check(LoginProfiles.SessionKey("node","ssh","system")!=LoginProfiles.SessionKey("node","ssh","rescue") &&
            LoginProfiles.SessionKey("node","serial","rescue")=="node/serial","environment keys separate SSH modes while retaining serial compatibility");
        check(NetworkReconnect.FailureReason(new SshHostIdentityException("declined")).Contains("指纹") &&
            NetworkReconnect.FailureReason(new SshLoginRejectedException("rescue 默认登录（密码）")).Contains("rescue 默认登录（密码）"),"fingerprint rejection and environment-specific account rejection have distinct diagnostics");
        if(OperatingSystem.IsWindows())
        {
            string folder=Path.Combine(Path.GetTempPath(),"armhpc-login-profiles-"+Guid.NewGuid().ToString("N"));
            try
            {
                var vault=new Vault(folder);var device=new Device{DeviceId="login-fixture",Mode="system",Transport="ssh"};
                vault.Save(device.DeviceId+"/ssh",key);vault.SaveDefault(password);
                check(vault.LoadConnection(device)==key,"old device-wide key is readable without migration");
                vault.SaveEnvironmentConnection(device.DeviceId,"system",key);
                vault.SaveEnvironmentConnection(device.DeviceId,"rescue",password);
                device.Mode="rescue";
                check(vault.LoadConnection(device)==password,"encrypted Rescue profile is selected after an environment switch");
                device.Mode="system";
                check(vault.LoadConnection(device)==key && vault.LoadDefault()==password,"System key and global default survive saving the Rescue profile");
                check(Directory.GetFiles(folder).All(f=>!File.ReadAllText(f).Contains("rescue-password-fixture")),"environment credentials are never persisted as plaintext");
                vault.ForgetConnection(device,true);
                check(vault.LoadConnection(device) is null && vault.LoadEnvironmentConnection(device.DeviceId,"rescue") is null && vault.LoadDefault()==password,
                    "forgetting one device removes its environment logins while preserving global defaults");
            }
            finally{Directory.Delete(folder,true);}
        }
        foreach (Exception failure in new Exception[]{new SshHostIdentityException("old address changed"),new SshLoginRejectedException("rescue 默认登录（密码）")})
        {
            bool reconnect=false;
            try { await NetworkReconnect.ReadBound<object>(()=>Task.FromException<object>(failure)); }
            catch(TransientConnectionException error){reconnect=ReferenceEquals(error.InnerException,failure);}
            check(reconnect,"read-only status rediscovery retains the specific "+failure.GetType().Name+" without bypassing identity checks");
        }
    }
}
