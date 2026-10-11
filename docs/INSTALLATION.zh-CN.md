# Windows 安装

[English](INSTALLATION.md)

下载 `armhpc-ota-1.0.0-windows-x64.msi`，双击打开安装向导。

1. 从欢迎页继续，并阅读 GPLv3 许可协议。
2. 选择安装路径，或点击 **Change** 浏览其他文件夹。
3. 勾选是否添加桌面快捷方式、是否将 CLI 加入当前用户的 PATH。
4. 确认选项，点击 **Install**，等待完成。

默认安装到 `%LocalAppData%\Programs\ARMHPC\OTA`，仅针对当前 Windows 用户。
安装后从开始菜单或桌面快捷方式打开 ARMHPC OTA。PATH 更改后需要重新打开终端。

再次运行 MSI 可以修复或卸载。本次安装包修订支持从原 v1.0.0 MSI 升级，并可迁移安装路径。
卸载保留 AppData 中的设备记录和已保存登录配置。

## 静默安装

```powershell
msiexec /i "armhpc-ota-1.0.0-windows-x64.msi" /qn INSTALLFOLDER="D:\ARMHPC\OTA" INSTALLDESKTOPSHORTCUT=1 ADDCLIPATH=1
```

将 `INSTALLDESKTOPSHORTCUT` 或 `ADDCLIPATH` 设为 `0` 可关闭对应选项。
