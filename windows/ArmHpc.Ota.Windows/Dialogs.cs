// SPDX-License-Identifier: GPL-3.0-only
using System.Windows;
using System.Windows.Controls;
using ArmHpc.Ota.Core;

namespace ArmHpc.Ota.Windows;

public static class Dialogs
{
    public static Credentials? Credentials(Window owner, string address, out bool remember, Credentials? initial=null, bool defaults=false)
    {
        var window = new Window { Owner = owner, Title = (defaults?"默认登录 · ":"认证 · ") + address, Width = 520, Height = 530, ResizeMode = ResizeMode.NoResize, WindowStartupLocation = WindowStartupLocation.CenterOwner };
        var panel = new StackPanel { Margin = new Thickness(20) };
        var fields = new LoginCredentialFields(initial);
        var save = new CheckBox { Content = defaults?"保存默认登录到本机（Windows DPAPI）":"为此设备保存凭据（Windows DPAPI）",IsChecked=defaults, Margin = new Thickness(0, 10, 0, 12) };
        panel.Children.Add(fields);
        panel.Children.Add(save);
        var submit = new Button { Content = defaults?"保存默认设置":"确认", IsDefault = true };
        submit.Click += (_, _) =>
        {
            try { fields.Read(); window.DialogResult = true; }
            catch(ArgumentException error) { MessageBox.Show(window,error.Message,"登录设置未保存"); }
        };
        panel.Children.Add(submit); window.Content = panel;
        bool accepted = window.ShowDialog() == true; remember = save.IsChecked == true;
        return accepted ? fields.Read() : null;
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
