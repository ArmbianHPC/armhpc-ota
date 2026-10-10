// SPDX-License-Identifier: GPL-3.0-only
using System.Windows;
using System.Windows.Controls;
using ArmHpc.Ota.Core;

namespace ArmHpc.Ota.Windows;

public static class Dialogs
{
    public static Credentials? Credentials(Window owner, string address, out bool remember, Credentials? initial=null, bool defaults=false)
    {
        var window = new Window { Owner = owner, Title = (defaults?"默认登录 · ":"认证 · ") + address, Width = 520, Height = 470, ResizeMode = ResizeMode.NoResize, WindowStartupLocation = WindowStartupLocation.CenterOwner };
        var panel = new StackPanel { Margin = new Thickness(20) };
        var user = new TextBox { Text = initial?.Username??"root" }; var password = new PasswordBox { Padding = new Thickness(7), Password=initial?.Password??"" };
        var key = new TextBox{Text=initial?.PrivateKeyPath??""}; var passphrase = new PasswordBox { Padding = new Thickness(7),Password=initial?.Passphrase??"" };
        var save = new CheckBox { Content = defaults?"保存默认登录到本机（Windows DPAPI）":"为此设备保存凭据（Windows DPAPI）",IsChecked=defaults, Margin = new Thickness(0, 10, 0, 12) };
        panel.Children.Add(new TextBlock { Text = "用户名" }); panel.Children.Add(user);
        panel.Children.Add(new TextBlock { Text = "密码", Margin = new Thickness(0, 8, 0, 0) }); panel.Children.Add(password);
        panel.Children.Add(new TextBlock { Text = "或 OpenSSH 私钥文件路径", Margin = new Thickness(0, 8, 0, 0) }); panel.Children.Add(key);
        panel.Children.Add(new TextBlock { Text = "私钥口令（如需要）", Margin = new Thickness(0, 8, 0, 0) }); panel.Children.Add(passphrase);
        panel.Children.Add(save);
        var submit = new Button { Content = defaults?"保存默认设置":"确认", IsDefault = true };
        submit.Click += (_, _) => window.DialogResult = true;
        panel.Children.Add(submit); window.Content = panel;
        bool accepted = window.ShowDialog() == true; remember = save.IsChecked == true;
        return accepted ? new(user.Text.Trim(), password.Password, string.IsNullOrWhiteSpace(key.Text) ? null : key.Text.Trim(), passphrase.Password) : null;
    }

    public static string? Input(Window owner, string title, string label, string initial = "")
    {
        var window = new Window { Owner = owner, Title = title, Width = 630, Height = 190, ResizeMode = ResizeMode.NoResize, WindowStartupLocation = WindowStartupLocation.CenterOwner };
        var panel = new StackPanel { Margin = new Thickness(20) }; var entry = new TextBox { Text = initial, Margin = new Thickness(0, 10, 0, 12) };
        panel.Children.Add(new TextBlock { Text = label, TextWrapping = TextWrapping.Wrap }); panel.Children.Add(entry);
        var submit = new Button { Content = "确定", IsDefault = true }; submit.Click += (_, _) => window.DialogResult = true;
        panel.Children.Add(submit); window.Content = panel;
        return window.ShowDialog() == true ? entry.Text.Trim() : null;
    }
}
