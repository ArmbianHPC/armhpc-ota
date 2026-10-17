// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
namespace ArmHpc.Ota.Core;

public sealed class SshLoginContext
{
    public string PrimaryEnvironment { get; init; } = "";
    public IReadOnlyDictionary<string, Credentials> Environments { get; init; } = new Dictionary<string, Credentials>();
    public IReadOnlyDictionary<string, Credentials> EnvironmentDefaults { get; init; } = new Dictionary<string, Credentials>();
    public Credentials? DefaultLogin { get; init; }
    public bool PrimaryOnly { get; init; }
    public Action<string, string, Credentials>? Verified { get; init; }
    public Action<string>? Progress { get; init; }
}

public enum SshAuthenticationKind { PrivateKey, Password }
public sealed record LoginChoice(Credentials Credentials, string Label, SshAuthenticationKind Authentication = SshAuthenticationKind.Password);

public static class LoginProfiles
{
    public static Credentials Plain(Credentials value) => new(value.Username, value.Password, value.PrivateKeyPath, value.Passphrase);
    public static bool Same(Credentials left, Credentials right) => Plain(left) == Plain(right);
    public static bool SameAttempt(LoginChoice left, LoginChoice right) =>
        left.Authentication == right.Authentication && left.Credentials.Username == right.Credentials.Username &&
        (left.Authentication == SshAuthenticationKind.PrivateKey
            ? left.Credentials.PrivateKeyPath == right.Credentials.PrivateKeyPath && left.Credentials.Passphrase == right.Credentials.Passphrase
            : left.Credentials.Password == right.Credentials.Password);
    public static string Method(Credentials value) => string.IsNullOrEmpty(value.PrivateKeyPath) ? "密码" :
        value.Password.Length > 0 ? "私钥 / 密码" : "私钥";
    public static string SessionKey(string id, string transport, string mode = "") =>
        id + "/" + transport + (transport == "ssh" && mode is "system" or "rescue" ? "/" + mode : "");

    public static IReadOnlyList<LoginChoice> Choices(Credentials primary, string? environment = null)
    {
        var context = primary.Ssh;
        var result = new List<LoginChoice>();
        void Add(Credentials? value, string label)
        {
            if (value is null) return;
            void MethodChoice(SshAuthenticationKind method, string name)
            {
                var choice = new LoginChoice(Plain(value), label + "（" + name + "）", method);
                if (!result.Any(item => SameAttempt(item, choice))) result.Add(choice);
            }
            if (!string.IsNullOrEmpty(value.PrivateKeyPath)) MethodChoice(SshAuthenticationKind.PrivateKey, "私钥");
            if (string.IsNullOrEmpty(value.PrivateKeyPath) || value.Password.Length > 0) MethodChoice(SshAuthenticationKind.Password, "密码");
        }
        if (context is null) { Add(primary, "所选登录"); return result; }
        if (context.PrimaryOnly)
        {
            if (environment is "system" or "rescue" && context.EnvironmentDefaults.TryGetValue(environment, out var forced))
                Add(forced, environment + " 默认登录");
            else Add(primary, "所选登录");
            if (environment is not ("system" or "rescue"))
                foreach (var value in context.EnvironmentDefaults) Add(value.Value, value.Key + " 默认登录");
            return result;
        }
        if (environment is "system" or "rescue")
        {
            if (context.Environments.TryGetValue(environment, out var saved)) Add(saved, environment + " 已保存登录");
            else if (context.PrimaryEnvironment == environment) Add(primary, environment + " 已保存登录");
            Add(context.EnvironmentDefaults.GetValueOrDefault(environment), environment + " 默认登录");
            Add(context.DefaultLogin, environment + " 默认登录");
            if (result.Count == 0 && context.PrimaryEnvironment is not ("system" or "rescue")) Add(primary, "所选登录");
            return result;
        }
        Add(primary, context.PrimaryEnvironment is "system" or "rescue" ? context.PrimaryEnvironment + " 已保存登录" : "所选登录");
        Add(context.DefaultLogin, "默认登录");
        foreach (string mode in new[] { "system", "rescue" })
            if (context.Environments.TryGetValue(mode, out var saved)) Add(saved, mode + " 已保存登录");
        foreach (string mode in new[] { "system", "rescue" })
            if (context.EnvironmentDefaults.TryGetValue(mode, out var saved)) Add(saved, mode + " 默认登录");
        return result;
    }
}
