<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Rescue 部署中断后的恢复

[English](INTERRUPTED-RECOVERY.md)

OESP 的 MBR 发现按磁盘签名、分区编号和精确范围定位。正常 Rescue 槽还必须通过签名尾部及完整 SquashFS 内容哈希校验。备用槽写入中断后可能没有已提交尾部；已批准的写入记录保留其物理身份，并绑定持久设备、原任务和受信任的原始清单。

设备先核对正在运行的 Overlay 根和持久身份，再解释中断目标。只有经过核验的写入记录可以补充该目标的逻辑文件系统身份。未知槽、伪造标记、GUID／范围／磁盘变化、无效签名及正在运行的根分区仍会被拒绝。

硬中断后按同一设备身份重连，查询原任务：

```sh
armhpc-rescue ota status --json
armhpc-rescue ota logs --job <原任务ID> --json
```

尚未完成的 worker 沿用原持久任务。已经记录为 `failed-recoverable` 的任务进入既有恢复流程；`retry` 仍仅用于写盘前的可恢复故障。

BOOT 候选回滚沿用原请求 ID：

```sh
armhpc-rescue ota boot status --json
armhpc-rescue ota boot rollback --request-id <原请求ID> --yes --json
```

回滚恢复原确认启动选择，并保留未完成备用槽的写入绑定。不可改写的回滚日志使其在创建新 BOOT 任务后仍可核对；只有替换部署完成后才清除绑定。该记录不会将半写入槽变成可启动槽，启动仍核验完整签名 SquashFS 内容。部分写入的普通系统仍保持阻断。

## SATA 磁盘身份

中断写入保存原磁盘序列号与 WWN。旧记录从原持久任务计划恢复已登记的 WWN；更换磁盘、原身份缺失或计划冲突时，在接纳目标前拒绝。无法证明原序列号或 WWN 的 OESP 记录不能授权替换写入。
