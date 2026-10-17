// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Collections.Concurrent;
using ArmHpc.Ota.Core;

namespace ArmHpc.Ota.Windows;

public partial class MainWindow
{
    Credentials? ResolveCredentials(Device device) =>
        sessionCredentials.GetValueOrDefault(LoginProfiles.SessionKey(device.DeviceId, device.Transport, device.Mode)) ??
        (device.Managed && device.Transport == "ssh" ? vault.LoadEnvironmentConnection(device.DeviceId, device.Mode) : null) ??
        sessionCredentials.GetValueOrDefault(LoginProfiles.SessionKey(device.DeviceId, device.Transport)) ??
        (device.Managed ? vault.LoadConnection(device) : null) ?? DefaultCredentialsFor(device.Mode);

    void RememberLogin(Device device, string mode, Credentials credentials, bool persist)
    {
        string key = LoginProfiles.SessionKey(device.DeviceId, device.Transport, mode);
        bool changed = !sessionCredentials.TryGetValue(key, out var previous) || !LoginProfiles.Same(previous, credentials);
        sessionCredentials[key] = LoginProfiles.Plain(credentials);
        if (persist)
        {
            if (device.Transport == "ssh") vault.SaveEnvironmentConnection(device.DeviceId, mode, credentials);
            else vault.SaveConnection(device, credentials);
        }
        if (changed) Log($"已记录 {mode} 登录方式：{LoginProfiles.Method(credentials)}");
    }

    void PreserveLoginForSwitch(Device device)
    {
        if (!device.Managed || device.Transport != "ssh" || device.Mode is not ("system" or "rescue")) return;
        var previous = ResolveCredentials(device);
        if (previous is null) return;
        bool persisted = new[] { vault.LoadConnection(device), vault.LoadDefault(), vault.LoadDefaultEnvironment(device.Mode) }
            .Any(saved => saved is not null && LoginProfiles.Same(saved, previous));
        RememberLogin(device, device.Mode, previous, persisted);
    }

    Credentials ConnectionCredentialsFor(Device device, Credentials primary, bool primaryOnly = false,
        Action<string, string, Credentials>? verified = null)
    {
        if (device.Transport != "ssh") return LoginProfiles.Plain(primary);
        var environments = new ConcurrentDictionary<string, Credentials>();
        var persisted = new List<Credentials>();
        foreach (string mode in new[] { "system", "rescue" })
        {
            var saved = device.Managed ? vault.LoadEnvironmentConnection(device.DeviceId, mode) : null;
            if (saved is not null) persisted.Add(saved);
            var value = sessionCredentials.GetValueOrDefault(LoginProfiles.SessionKey(device.DeviceId, "ssh", mode)) ?? saved;
            if (value is not null) environments[mode] = LoginProfiles.Plain(value);
        }
        var old = device.Managed ? vault.LoadConnection(device) : null;
        if (old is not null) persisted.Add(old);
        string originalMode = device.Mode;
        if (device.Managed && originalMode is "system" or "rescue" && !environments.ContainsKey(originalMode))
            environments[originalMode] = LoginProfiles.Plain(primary);
        var savedDefault = vault.LoadDefault();
        if (savedDefault is not null) persisted.Add(savedDefault);
        foreach(string mode in new[]{"system","rescue"})
            if(vault.LoadDefaultEnvironment(mode) is {} saved)persisted.Add(saved);
        return LoginProfiles.Plain(primary) with
        {
            Ssh = new SshLoginContext
            {
                PrimaryEnvironment = PrimaryLoginEnvironment(device,primary), Environments = environments, DefaultLogin = defaultLogin,
                EnvironmentDefaults = new Dictionary<string,Credentials>(defaultEnvironmentLogins),
                PrimaryOnly = primaryOnly, Progress = Log,
                Verified = verified ?? ((id, mode, actual) => Dispatcher.Invoke(() =>
                {
                    if (!device.Managed || device.DeviceId != id || mode is not ("system" or "rescue")) return;
                    foreach (var prior in environments)
                        if (vault.LoadEnvironmentConnection(id, prior.Key) is null && persisted.Any(c => LoginProfiles.Same(c, prior.Value)))
                            vault.SaveEnvironmentConnection(id, prior.Key, prior.Value);
                    environments[mode] = LoginProfiles.Plain(actual);
                    RememberLogin(device, mode, actual, persisted.Any(c => LoginProfiles.Same(c, actual)));
                }))
            }
        };
    }
}
