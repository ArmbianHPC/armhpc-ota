// SPDX-License-Identifier: GPL-3.0-only
using System.Windows;
using ArmHpc.Ota.Core;

namespace ArmHpc.Ota.Windows;

public partial class MainWindow
{
    private readonly Dictionary<string, Credentials> defaultEnvironmentLogins = [];
    private Credentials? DefaultCredentialsFor(string mode) =>
        defaultEnvironmentLogins.GetValueOrDefault(mode) ?? defaultLogin ??
        (mode is "system" or "rescue" ? null : defaultEnvironmentLogins.Values.FirstOrDefault());

    private string PrimaryLoginEnvironment(Device device, Credentials primary)
    {
        if (device.Mode is "system" or "rescue") return device.Mode;
        if (defaultLogin is not null && LoginProfiles.Same(defaultLogin, primary)) return "";
        var modes = defaultEnvironmentLogins.Where(pair => LoginProfiles.Same(pair.Value, primary)).Select(pair => pair.Key).ToArray();
        return modes.Length == 1 ? modes[0] : "";
    }

    private void SaveDefaultEnvironmentLogins(IReadOnlyDictionary<string, Credentials> profiles)
    {
        ValidateEnvironmentLogins(profiles);
        foreach (var pair in profiles)
        {
            vault.SaveDefaultEnvironment(pair.Key, LoginProfiles.Plain(pair.Value));
            defaultEnvironmentLogins[pair.Key] = LoginProfiles.Plain(pair.Value);
        }
        RefreshDefaultLabel();
        Log("已保存分环境默认登录设置：" + string.Join("、", profiles.Keys));
    }

    private void SaveDeviceEnvironmentLogins(Device device, IReadOnlyDictionary<string, Credentials> profiles)
    {
        if (!device.Managed || device.Transport != "ssh") throw new InvalidOperationException("请选择已登记的 SSH 设备。");
        ValidateEnvironmentLogins(profiles);
        foreach (var pair in profiles) RememberLogin(device, pair.Key, pair.Value, true);
        Log("已更新所选设备的分环境登录设置：" + string.Join("、", profiles.Keys));
    }

    private static void ValidateEnvironmentLogins(IReadOnlyDictionary<string, Credentials> profiles)
    {
        if (profiles.Count == 0 || profiles.Any(pair => pair.Key is not ("system" or "rescue") || string.IsNullOrWhiteSpace(pair.Value.Username)))
            throw new ArgumentException("需要有效的 System 或 Rescue 环境及非空用户名。");
    }

    private void DefaultEnvironmentCredentialsClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new EnvironmentLoginDialog(this, "System / Rescue 默认登录", defaultEnvironmentLogins, _ => defaultLogin);
            if (dialog.ShowDialog() == true) SaveDefaultEnvironmentLogins(dialog.Read());
        }
        catch (Exception error) { MessageBox.Show(this, error.Message, "默认登录未保存"); }
    }

    private void EditDeviceEnvironmentLogins(Device device)
    {
        if (!device.Managed || device.Transport != "ssh") throw new InvalidOperationException("请选择已登记的 SSH 设备。");
        var profiles = new Dictionary<string, Credentials>();
        foreach (string mode in new[] { "system", "rescue" })
        {
            var value = sessionCredentials.GetValueOrDefault(LoginProfiles.SessionKey(device.DeviceId, "ssh", mode)) ??
                        vault.LoadEnvironmentConnection(device.DeviceId, mode);
            if (value is not null) profiles[mode] = value;
        }
        if (device.Mode is "system" or "rescue" && !profiles.ContainsKey(device.Mode))
        {
            var legacy = vault.Load(device.DeviceId + "/ssh") ?? vault.Load(device.DeviceId);
            if (legacy is not null) profiles[device.Mode] = legacy;
        }
        var dialog = new EnvironmentLoginDialog(this, device.Name + " · System / Rescue 登录设置", profiles, DefaultCredentialsFor);
        if (dialog.ShowDialog() == true) SaveDeviceEnvironmentLogins(device, dialog.Read());
    }

    private string DefaultLoginSummary()
    {
        var descriptions = new List<string>();
        if (defaultLogin is not null) descriptions.Add("通用 " + defaultLogin.Username + " · " + LoginProfiles.Method(defaultLogin));
        foreach (var pair in defaultEnvironmentLogins)
            descriptions.Add(pair.Key + " " + pair.Value.Username + " · " + LoginProfiles.Method(pair.Value));
        return descriptions.Count == 0 ? "默认登录：未设置" : "默认登录：" + string.Join("；", descriptions);
    }
}
