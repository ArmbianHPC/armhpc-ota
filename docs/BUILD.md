# 软件构建

使用两仓库的同一版本 tag。设备代码兼容 Python 3.11；Windows 构建使用 global.json 指定的 .NET 10 SDK。发行依赖固定于 DEPENDENCIES.lock.json 与 NuGet packages.lock.json。

```powershell
python tools/build-release.py --framework-source F:\armhpc\armbian-hpc --work F:\armhpc\output\build\1.0.0\software --output F:\armhpc\output\releases\1.0.0 --helpers F:\armhpc\output\build\1.0.0\helpers --cache F:\armhpc\output\downloads\release-1.0.0-wheels --signing-key PATH_TO_PRIVATE_KEY --key-id KEY_ID
```

ARM64/ARMhf 辅助程序在 Debian Bookworm 兼容工具链上由 `tools/build-helpers.py --output PATH` 生成，构建检查 ELF 架构与 glibc ABI。

私钥位于发布目录之外。已存在的发行附件不覆盖。二进制、维护包和源码记录两个仓库的 commit；许可与共享源码随附。

自动化检查：`python -m unittest discover -s tests -v`、Windows ArmHpc.Ota.Tests 与 ArmHpc.Ota.UiTests。检查输出存放于独立工作目录。

发行附件使用 MSI / Linux CLI tar.gz / 签名 maintenance 三项。Windows MSI 使用固定 WiX 4.0.6，将已发布且验证过的程序目录装入当前用户 Programs/ARMHPC/OTA，注册启动菜单和 CLI PATH，卸载不删除 AppData 中的用户配置。
Linux CLI 使用与 Windows 相同的 Core 和 Cli 工程，选择 net10.0、linux-x64 或 linux-arm64。Windows GUI 仍选择 net10.0-windows。Linux 包中的本地签名包解析助手需要系统 Python 3.11+ 与 cryptography。

MSI 安装向导使用固定的 `WixToolset.UI.wixext/4.0.6`。通过 `wix extension add WixToolset.UI.wixext/4.0.6` 获取后，构建时将扩展 DLL 路径传给 `--ui-extension`。
安装向导包括许可、安装路径、桌面／PATH 选项、确认、进度和完成页。界面及命令行用法见 [Windows installation](INSTALLATION.md)。
