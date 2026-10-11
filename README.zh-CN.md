# ARMHPC OTA

[English](README.md)

ARMHPC OTA **1.0.0** 是面向 ARM Linux 系统的通用升级与设备管理平台，包含共享设备端引擎、Windows GUI 和 Windows／Linux 上位机 CLI。

升级流程与板卡的存储、引导接入分开维护。WXY OEC Turbo（OECT）是首个接入设备，新增设备使用各自的板卡配置及兼容固件包。

## 功能

- 通过 SSH/SFTP 或 USB 串口推送本地签名包，不要求电脑使用固定 IP。
- 多选设备、主机名筛选、命令返回概况，以及 1–8 并发操作。
- 在 Rescue 中离线替换配置指定的普通系统分区；Rescue 写入备用 A/B 槽，启动确认后提交。
- 部署前校验 Ed25519 签名、SHA256、板卡、架构、存储布局和容量。
- 传输续传、持久任务、重启重连、维护备份和回滚。
- 普通系统和 Rescue A/B 共用时间恢复记录，支持 NTP 校准及有序事件。
- 可选签名更新源、HTTP/HTTPS 文件发布，以及版本包和维护包签名。

设备端需要 Python 3.11 或更高版本，包含 ARM64／ARM32 运行时支持。Windows 包含 .NET 10 和独立 Python 发布助手；Linux 上位机包包含 x86_64 与 ARM64 运行时。Windows 使用 DPAPI 保存登录凭据；Linux 使用 SSH 密钥或本地输入密码。设备兼容性由板卡配置和包清单确定。

## 项目组成

| 部分 | 职责 |
| --- | --- |
| 设备引擎 | 签名验证、下载、持久任务、部署、恢复和工具维护。 |
| 上位机 | 设备发现、认证、SSH／串口传输、批量命令和重连。 |
| 发布工具 | 包签名与可选的本地文件服务。 |
| 固件接入 | [armbian-hpc](https://github.com/ArmbianHPC/armbian-hpc) 负责板卡配置、引导处理、存储布局及系统载荷生成。 |

## 开始使用

从 [Releases](https://github.com/ArmbianHPC/armhpc-ota/releases) 下载软件。

| 文件 | 用途 |
| --- | --- |
| `armhpc-ota-<版本>-windows-x64.msi` | 安装 Windows GUI、CLI、发布服务及维护包。 |
| `armhpc-ota-<版本>-linux-cli.tar.gz` | 在 Linux 上解压后执行 `./armhpc-ota-cli --help`。 |
| `armhpc-ota-<版本>-maintenance.tar.xz` | 更新现有设备的 OTA 工具。 |

Windows 从开始菜单打开 **ARMHPC OTA**，或执行 `ARMHPC-OTA-CLI.exe --help`。
设备普通系统使用 `armhpc ota`，Rescue 使用 `armhpc-rescue ota`。

```sh
armhpc ota status --json
armhpc-rescue ota tools status --json
armhpc-rescue ota tools update --bundle /path/maintenance.tar.xz --yes --json
armhpc-rescue ota recover --release current --target system --yes --json
```

从 [armbian-hpc](https://github.com/ArmbianHPC/armbian-hpc) 选择与设备板卡配置匹配的系统 OTA 包。维护包更新工具，不替换系统镜像。

## 文档

- [Windows 安装](docs/INSTALLATION.zh-CN.md)
- [Windows GUI／CLI](docs/WINDOWS.md)
- [设备与批量命令](docs/DEVICE-MANAGEMENT.md)
- [自动升级与重连](docs/AUTOMATIC-UPGRADE.md)
- [签名与发行](docs/RELEASES.zh-CN.md)
- [软件构建](docs/BUILD.md)
- [v1.0.0 更新说明](docs/releases/v1.0.0.zh-CN.md)
- [已知问题](docs/KNOWN-ISSUES.md)

## 许可证

原创代码采用 **GPL-3.0-only**；第三方组件保留原许可证。详见 [LICENSE](LICENSE)、[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) 和各软件包中的许可材料。
