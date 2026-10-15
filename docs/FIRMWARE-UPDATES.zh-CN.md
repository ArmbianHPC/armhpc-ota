<!-- SPDX-License-Identifier: GPL-3.0-only -->
# 配套固件更新

[English](FIRMWARE-UPDATES.md)

1.3.0 支持包含 `firmware/boot-update.tar.xz` 的签名固件包，导入时选择 **all**。嵌套签名用途为 firmware-update、最低设备 agent 为 1.3.0；普通的同 BOOT system/Rescue 包沿用原流程。

先安装随附 maintenance。上位机核验持久设备 ID、签名、板型、布局、BOOT ABI 和载荷配套，进入已确认 Rescue，准备本机私有恢复备份；所有备份文件下载到电脑并通过容量/SHA256 校验后才切换 BOOT。验收完成前保留显示的备份目录。

设备保留原包和请求 ID。新 Rescue 确认启动后，经原引擎部署配套普通系统，检查持久资源和服务再提交。关闭软件或 SSH/COM 断开不创建新任务；重新打开保存的任务继续查询原请求。未知结果和超时保持待核对。

```sh
armhpc ota boot status --json
armhpc-rescue ota boot status --json
armhpc-rescue ota boot rollback --request-id ORIGINAL_TASK_ID --yes --json
```

应用/回滚受设备当前环境、原任务绑定和签名资源限制。请将 BOOT 恢复说明与私有备份保存在一起。包只支持所声明的原 kernel/DTB 配套，其他基线需要对应迁移包或完整镜像。正常固件确认不改变看门狗、kexec 或完整硬件验收结果；早期内核失效仍可能需要现场 BOOT 恢复。

设备提供新字段时，上位机显示管理网络、内核能力和状态恢复；旧 agent 缺少字段显示“未提供”。认证、防火墙、资源和 swap 的新修改要求命令中显式提供 `--yes`；预览不会应用。改密仍为交互操作。

节点配置、只读检查及实机矩阵见配套框架的 `docs/BASE-IMAGE-1.3.0.zh-CN.md` 和 `tools/verify-node-1.3.py`。源码 commit、最终内核配置/模块清单、许可材料和 SHA256 清单用于核对交付内容；凭据、本机备份和签名私钥保持私有。
