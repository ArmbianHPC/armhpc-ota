// SPDX-License-Identifier: GPL-3.0-only
using System.Windows;
namespace ArmHpc.Ota.Windows;
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        MainWindow = new MainWindow();
        MainWindow.Show();
    }
}
