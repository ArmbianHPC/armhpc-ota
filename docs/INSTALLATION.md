# Windows installation

[简体中文](INSTALLATION.zh-CN.md)

Download `armhpc-ota-1.0.0-windows-x64.msi` and open it to start the Setup Wizard.

1. Continue from the welcome page and read the GPLv3 license.
2. Choose the installation folder, or use **Change** to browse for another folder.
3. Select whether to create a desktop shortcut and add the CLI to your user PATH.
4. Review the options, click **Install**, and finish the wizard.

The default folder is `%LocalAppData%\Programs\ARMHPC\OTA`. Installation applies to the current Windows user.
Start ARMHPC OTA from the Start menu or the optional desktop shortcut. Open a new terminal after changing PATH.

Running the MSI again offers repair or removal. This installer revision can upgrade the original v1.0.0 MSI,
including moving the installation to a different folder. Device records and saved login settings remain in AppData on uninstall.

## Unattended installation

```powershell
msiexec /i "armhpc-ota-1.0.0-windows-x64.msi" /qn INSTALLFOLDER="D:\ARMHPC\OTA" INSTALLDESKTOPSHORTCUT=1 ADDCLIPATH=1
```

Use `INSTALLDESKTOPSHORTCUT=0` or `ADDCLIPATH=0` to disable the corresponding integration.
