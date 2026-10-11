# ARMHPC OTA

ARMHPC 双系统 OTA 引擎与 Windows 设备管理程序，版本 **1.0.0**。原创代码采用 GPL-3.0-only；第三方组件保留原许可证。

## 功能

- Windows GUI／CLI 和 Linux 上位机 CLI 经 SSH/SFTP 或 USB 串口推送本地签名包，不要求电脑固定 IP。
- 多选设备、主机名筛选、DPAPI 登录保存、SSH 身份管理、命令返回概况，并发 1–8。
- 普通系统在 Rescue 中离线更新；Rescue 更新写入备用 A/B 槽，启动确认后提交。
- 签名、SHA256、设备／架构／布局匹配、活动根保护、单写锁及写盘前取消。
- 持久任务、传输续传、重启重连、原请求继续、维护资源备份与回滚。
- 共享时间恢复、NTP 校准、估计时间及事件序号，普通系统与 Rescue A/B 一致。
- 可选签名索引拉取、内网 HTTP/HTTPS 文件服务和版本签名工具。

设备端使用 Python 3.11+；Windows 包包含 .NET 10 和独立 Python 发布助手。OECT 使用 SATA 64 GiB ext4 系统、其余 DATA，eMMC SquashFS Rescue A/B 与 ext4 共享区。ARM32 使用相同引擎接口及对应辅助程序，写盘操作由板卡适配限制。

## 使用

Windows 使用 MSI 安装，启动菜单中的 ARMHPC OTA；CLI 为 `ARMHPC-OTA-CLI.exe --help`。Linux 解压 tar.gz 后运行 `./armhpc-ota-cli --help`，包含 x86_64 与 ARM64 运行时。
正常系统使用 `armhpc ota`；Rescue 使用 `armhpc-rescue ota`。设备命令支持 `--json`，写入确认支持 `--yes`。

```sh
armhpc ota status --json
armhpc-rescue ota tools status --json
armhpc-rescue ota tools update --bundle /path/maintenance.tar.xz --yes --json
armhpc-rescue ota recover --release current --target system --yes --json
```

本地系统推送需另行选择兼容的系统 OTA 包，源码或工具维护包不能代替系统载荷。

## 文档

- [Windows GUI／CLI](docs/WINDOWS.md)
- [设备与批量命令](docs/DEVICE-MANAGEMENT.md)
- [自动升级与重连](docs/AUTOMATIC-UPGRADE.md)
- [签名发布](docs/RELEASES.md)
- [软件构建](docs/BUILD.md)
- [许可及对应源码](THIRD-PARTY-NOTICES.md)
- [已知问题](docs/KNOWN-ISSUES.md)

框架源码为独立的 `armbian-hpc` 仓库。升级核心仅在本仓库维护。
