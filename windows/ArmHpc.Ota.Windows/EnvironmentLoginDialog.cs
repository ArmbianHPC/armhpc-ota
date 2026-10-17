// SPDX-License-Identifier: GPL-3.0-only
using System.Windows;
using System.Windows.Controls;
using ArmHpc.Ota.Core;
using Microsoft.Win32;

namespace ArmHpc.Ota.Windows;

public sealed class LoginCredentialFields : StackPanel
{
    public TextBox UsernameBox { get; } = new();
    public PasswordBox PasswordBox { get; } = new() { Padding = new Thickness(7) };
    public TextBox PrivateKeyBox { get; } = new();
    public PasswordBox PassphraseBox { get; } = new() { Padding = new Thickness(7) };
    public LoginCredentialFields(Credentials? initial = null)
    {
        UsernameBox.Text = initial?.Username ?? "root";
        PasswordBox.Password = initial?.Password ?? "";
        PrivateKeyBox.Text = initial?.PrivateKeyPath ?? "";
        PassphraseBox.Password = initial?.Passphrase ?? "";
        void Field(string label, UIElement control)
        {
            Children.Add(new TextBlock { Text = label, Margin = new Thickness(0, 8, 0, 2) });
            Children.Add(control);
        }
        Field("用户名", UsernameBox);
        Field("密码", PasswordBox);
        var keyRow = new Grid();
        keyRow.ColumnDefinitions.Add(new());
        keyRow.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        keyRow.Children.Add(PrivateKeyBox);
        var browse = new Button { Content = "选择文件", Margin = new Thickness(8, 0, 0, 0) };
        Grid.SetColumn(browse, 1); keyRow.Children.Add(browse);
        browse.Click += (_, _) => { var picker = new OpenFileDialog { Title = "选择 SSH 私钥", CheckFileExists = true }; if (picker.ShowDialog(Window.GetWindow(this)) == true) PrivateKeyBox.Text = picker.FileName; };
        Field("OpenSSH 私钥文件路径（可选）", keyRow);
        Field("私钥口令（如需要）", PassphraseBox);
        Children.Add(new TextBlock { Text = "同时配置私钥和密码时，先尝试私钥，认证失败后尝试密码。", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 4) });
    }
    public Credentials Read()
    {
        string username = UsernameBox.Text.Trim();
        if (username.Length == 0) throw new ArgumentException("用户名不能为空。");
        return new(username, PasswordBox.Password, string.IsNullOrWhiteSpace(PrivateKeyBox.Text) ? null : PrivateKeyBox.Text.Trim(), PassphraseBox.Password);
    }
}

public sealed class EnvironmentLoginDialog : Window
{
    public IReadOnlyDictionary<string, LoginCredentialFields> Editors { get; }
    public IReadOnlyDictionary<string, CheckBox> EnabledEnvironments { get; }
    public EnvironmentLoginDialog(Window owner, string title, IReadOnlyDictionary<string, Credentials> existing,
                                 Func<string, Credentials?> fallback)
    {
        Owner = owner; Title = title; Width = 610; Height = 580; MinWidth = 550; MinHeight = 510;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var layout = new DockPanel { Margin = new Thickness(18) };
        var introduction = new TextBlock { Text = "分别配置 System 和 Rescue 的登录账户。仅保存勾选的环境，其余环境保留原设置；登录设置使用 Windows DPAPI 加密保存在本机。", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) };
        DockPanel.SetDock(introduction, Dock.Top); layout.Children.Add(introduction);
        var save = new Button { Content = "保存所勾选环境的登录设置", IsDefault = true, Margin = new Thickness(0, 12, 0, 0) };
        DockPanel.SetDock(save, Dock.Bottom); layout.Children.Add(save);
        var tabs = new TabControl(); layout.Children.Add(tabs);
        var editors = new Dictionary<string, LoginCredentialFields>();
        var enabled = new Dictionary<string, CheckBox>();
        foreach (string mode in new[] { "system", "rescue" })
        {
            var panel = new StackPanel { Margin = new Thickness(12) };
            var use = new CheckBox { Content = "保存此环境的独立登录设置", IsChecked = existing.ContainsKey(mode), Margin = new Thickness(0, 0, 0, 8) };
            var editor = new LoginCredentialFields(existing.GetValueOrDefault(mode) ?? fallback(mode)) { IsEnabled = use.IsChecked == true };
            use.Checked += (_, _) => editor.IsEnabled = true;
            use.Unchecked += (_, _) => editor.IsEnabled = false;
            panel.Children.Add(use); panel.Children.Add(editor);
            tabs.Items.Add(new TabItem { Header = mode == "system" ? "System（普通系统）" : "Rescue（救援系统）", Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto } });
            editors[mode] = editor; enabled[mode] = use;
        }
        Editors = editors; EnabledEnvironments = enabled;
        save.Click += (_, _) =>
        {
            try { Read(); DialogResult = true; }
            catch (ArgumentException error) { MessageBox.Show(this, error.Message, "登录设置未保存"); }
        };
        Content = layout;
    }
    public IReadOnlyDictionary<string, Credentials> Read()
    {
        var profiles = EnabledEnvironments.Where(pair => pair.Value.IsChecked == true).ToDictionary(pair => pair.Key, pair => Editors[pair.Key].Read());
        if (profiles.Count == 0) throw new ArgumentException("请勾选至少一个要保存的环境。");
        return profiles;
    }
}
