# 软件构建

使用两仓库的同一版本 tag。设备代码兼容 Python 3.11；Windows 构建使用 global.json 指定的 .NET 10 SDK。发行依赖固定于 DEPENDENCIES.lock.json 与 NuGet packages.lock.json。

```powershell
python tools/build-release.py --framework-source F:\armhpc\armbian-hpc --work F:\armhpc\output\build\1.0.0\software --output F:\armhpc\output\releases\1.0.0 --helpers F:\armhpc\output\build\1.0.0\helpers --cache F:\armhpc\output\downloads\release-1.0.0-wheels --signing-key PATH_TO_PRIVATE_KEY --key-id KEY_ID
```

ARM64/ARMhf 辅助程序在 Debian Bookworm 兼容工具链上由 `tools/build-helpers.py --output PATH` 生成，构建检查 ELF 架构与 glibc ABI。

私钥位于发布目录之外。已存在的发行附件不覆盖。二进制、维护包和源码记录两个仓库的 commit；许可与共享源码随附。

自动化检查：`python -m unittest discover -s tests -v`、Windows ArmHpc.Ota.Tests 与 ArmHpc.Ota.UiTests。检查输出存放于独立工作目录。
