// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;

public static class DualAuthenticationChecks
{
    public static void Run(Action<bool,string> check)
    {
        var both=new Credentials("system-admin","account-password-fixture","key-fixture","key-passphrase-fixture");
        var choices=LoginProfiles.Choices(both);
        check(choices.Count==2 && choices[0].Authentication==SshAuthenticationKind.PrivateKey && choices[1].Authentication==SshAuthenticationKind.Password,
            "one configured profile offers private-key then password authentication");
        check(choices.All(choice=>choice.Credentials==both),"each authentication choice retains the complete configured profile for persistence and sudo");
        check(choices[0].Label.Contains("私钥") && choices[1].Label.Contains("密码") && LoginProfiles.Method(both)=="私钥 / 密码",
            "combined profiles have explicit authentication labels without exposing secrets");
        check(!LoginProfiles.SameAttempt(choices[0],choices[1]),"trying a private key does not suppress password fallback for the same account");
        var otherPassword=LoginProfiles.Choices(both with {Password="other-password-fixture"});
        check(LoginProfiles.SameAttempt(choices[0],otherPassword[0]) && !LoginProfiles.SameAttempt(choices[1],otherPassword[1]),
            "attempt deduplication uses the selected method's key or password rather than unrelated fields");
        check(LoginProfiles.Choices(both with {Password=""}).Count==1 && LoginProfiles.Choices(new Credentials("root","password-only")).Count==1,
            "single-method profiles do not introduce an unconfigured alternative");
        var rescue=new Credentials("rescue-admin","rescue-password-fixture");
        var context=new SshLoginContext{PrimaryEnvironment="system",DefaultLogin=both,
            EnvironmentDefaults=new Dictionary<string,Credentials>{{"system",both},{"rescue",rescue}}};
        var wrapped=both with {Ssh=context};
        check(LoginProfiles.Choices(wrapped,"rescue").First().Credentials==rescue && LoginProfiles.Choices(wrapped,"system").First().Credentials.Username=="system-admin",
            "different default usernames and passwords are selected by the trusted environment");
        var explicitRescue=new Credentials("per-node-rescue","per-node-password");
        var saved=wrapped with {Ssh=new SshLoginContext{PrimaryEnvironment="system",DefaultLogin=both,
            EnvironmentDefaults=context.EnvironmentDefaults,Environments=new Dictionary<string,Credentials>{{"rescue",explicitRescue}}}};
        var rescueChoices=LoginProfiles.Choices(saved,"rescue");
        check(rescueChoices[0].Credentials==explicitRescue && rescueChoices[1].Credentials==rescue && rescueChoices.Count==4,
            "per-device environment settings precede environment defaults and generic method fallback");
        var strict=wrapped with {Ssh=new SshLoginContext{PrimaryEnvironment="system",EnvironmentDefaults=context.EnvironmentDefaults}};
        check(LoginProfiles.Choices(strict,"rescue").Single().Credentials==rescue,
            "a known environment does not try the other environment's account without a generic default");
        var forced=wrapped with {Ssh=new SshLoginContext{PrimaryOnly=true,PrimaryEnvironment="system",DefaultLogin=both,
            EnvironmentDefaults=context.EnvironmentDefaults,Environments=new Dictionary<string,Credentials>{{"rescue",explicitRescue}}}};
        check(LoginProfiles.Choices(forced,"rescue").Single().Credentials==rescue,
            "default reauthentication honors the environment default while ignoring a per-device override");
        check(LoginProfiles.Choices(wrapped).Count==3 && choices.All(choice=>!choice.Label.Contains(both.Password) && !choice.Label.Contains(both.PrivateKeyPath!)),
            "ambiguous environments deduplicate method attempts and labels contain no credential material");
        if(OperatingSystem.IsWindows())
        {
            string folder=Path.Combine(Path.GetTempPath(),"armhpc-dual-login-"+Guid.NewGuid().ToString("N"));
            try
            {
                var vault=new Vault(folder);vault.SaveDefault(both);
                vault.SaveDefaultEnvironment("system",both);vault.SaveDefaultEnvironment("rescue",rescue);
                var loaded=new Vault(folder);
                check(loaded.LoadDefault()==both && loaded.LoadDefaultEnvironment("system")==both && loaded.LoadDefaultEnvironment("rescue")==rescue,
                    "DPAPI storage retains both authentication methods and independent default environment accounts across reload");
                check(Directory.GetFiles(folder).All(file=>!File.ReadAllText(file).Contains(both.Password) && !File.ReadAllText(file).Contains(rescue.Password)),
                    "default environment secrets are encrypted rather than persisted in plaintext");
                loaded.SaveEnvironmentConnection("device","system",both);loaded.SaveEnvironmentConnection("device","rescue",explicitRescue);
                loaded.ClearDefault();
                check(loaded.LoadDefault() is null && loaded.LoadDefaultEnvironment("system") is null && loaded.LoadDefaultEnvironment("rescue") is null &&
                      loaded.LoadEnvironmentConnection("device","system")==both && loaded.LoadEnvironmentConnection("device","rescue")==explicitRescue,
                    "clearing global defaults retains independent per-device environment accounts");
            }
            finally{Directory.Delete(folder,true);}
        }
    }
}
