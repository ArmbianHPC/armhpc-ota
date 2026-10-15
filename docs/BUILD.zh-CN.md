# 软件构建

使用两个仓库的配套、干净提交。设备代码支持 Python 3.11+；.NET SDK、运行时及发行依赖由 global.json、DEPENDENCIES.lock.json 和 NuGet 锁文件固定。

先安装 `requirements-test.txt`，使用 `PYTHONPATH=src python3 -m pytest tests` 运行全部 Python 回归，再运行 Windows 的 ArmHpc.Ota.Tests 和 ArmHpc.Ota.UiTests。pytest 同时收集函数测试与 unittest 用例。

使用框架的 `tools/build/prepare-firmware-inputs.py --project FRAMEWORK` 准备有固定哈希和许可的板卡固件。`tools/build-release.py` 也会执行此步骤，不依赖构建机预先放好的缓存。通过 `tools/build-helpers.py` 生成 ARM64/ARMhf 辅助程序，校验架构与 Bookworm glibc 兼容性。

`tools/build-release.py` 从配套提交生成运行时、维护包及 Windows 便携输入。然后使用固定 WiX 4.0.6 与同版本 UI 扩展运行 `tools/build-msi.py`；安装向导包含许可、路径、桌面快捷方式、PATH、确认、进度和完成页。`tools/build-linux-cli.py` 生成 Linux x86_64/ARM64 上位机 CLI。

公开附件仅三项：MSI、Linux CLI tar.gz、签名 maintenance tar.xz。必要源码和许可放入包内；中间文件、私钥留在仓库及公开包之外。已有版本附件不可覆盖。

草稿发布使用 `tools/release-policy.py --release-id ID`，核对全部附件 SHA256 后才执行 `--apply --publish`，标题仅使用版本号。
