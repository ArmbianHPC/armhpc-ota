# Rescue 备份与共享空间

[English](BACKUPS-AND-STORAGE.md)

选择一台已经认证的 Rescue 设备，在“批量 OTA”中打开“备份与共享空间”。
勾选 BOOT、工具维护备份，选择上位机上的私有目录。

流程为：传输原始文件 → 逐文件校验 SHA256 → 上位机生成 ZIP → 打开 ZIP，
重新校验清单和每个解压后的文件 → 向设备登记导出完成。Rescue 不执行压缩，
也不生成额外的大型导出归档。传输中断时保留本机临时文件，不进入清理。
ZIP 包含 `backup-inventory.json` 和 `files/` 下的原始文件。压缩包及相邻的 JSON
校验回执可能涉及设备身份、访问设置，请妥善保存；恢复时从 `files/` 提取原文件。

所选备份全部导出成功后，窗口显示清理清单、可释放空间和保留项，确认后才执行。
允许清理共享区内不再使用的下载缓存、无当前任务引用的 BOOT 解包目录、
超过一小时的上传残留，以及已完成 BOOT 任务且已导出并校验的备份。
当前工具维护的回退备份、当前 BOOT 任务的载荷、活动或待恢复任务、工厂恢复资料、
已确认版本基线、Overlay、身份、配置、时间记录和任务历史继续保留。
无法确认用途的历史备份可以导出，但不清理。SATA DATA 文件不在共享区清理范围内。
流程不扩容、不格式化、不重新分区。

执行前会重新核对任务、文件身份及清单哈希；状态变化后需要重新预览。
已经导出后从设备移除的 BOOT 备份保存在上位机 ZIP 中，原设备路径不能继续直接用于
回滚，需先恢复原文件。若删除过程中发生 I/O 错误，部分项目可能已删除，请刷新清单。

## 命令行

Linux、Windows 上位机使用同一套命令：

```sh
ARMHPC-OTA-CLI storage-status --ssh 192.168.1.20 --username root --json
ARMHPC-OTA-CLI backup-export --ssh 192.168.1.20 --username root --output-directory /private/armhpc
ARMHPC-OTA-CLI backup-export --ssh 192.168.1.20 --username root --output-directory /private/armhpc --cleanup-after-export --yes
```

第三条命令只有在所选备份全部完成压缩包回读校验后，才打印并执行当前清理清单。
认证和 SSH 指纹验证沿用分环境登录设置。

设备端入口为 `armhpc-rescue ota storage status`、`export --backup-id ID`、
`acknowledge --inventory-sha256 HASH --archive-sha256 HASH`、`plan`、
`cleanup --plan-id HASH --yes`，均支持 `--json`。请通过上位机完成压缩包校验后登记导出，
不要手工伪造回执。`stage --bytes N` 为上传检查空间，并准备经过核验的 SATA DATA 缓存。

即使设备显示 1.2.3，也需要手动安装本次重编附带的 maintenance 包。
`storage_management` 能力字段用于识别本次实现。SSH 上传优先使用核验后的 DATA，
空间不足会在传输前拒绝。导出和清理能释放被占用的共享空间，但不能增加 eMMC 容量。

本次可见版本和交付文件为 **1.2.3-r8**。MSI 内部版本及 `agent_version` 保持 `1.2.3`，`agent_display_version`、维护包签名中的 `display_version` 与 `revision` 区分修订版。

上位机保留该设备的未完成自动任务时，上传文件和缓存会保留，供原任务继续；已完成并核验导出的备份仍可进入清理清单。取消或完成上位机任务后，刷新清单可查看其他残留。

## 共享区已满或设备只有旧工具

r8 的 SSH 备份入口可直接使用 MSI 附带的签名维护包。设备先核对签名、板型和设备身份，
仅在内存中载入备份辅助代码；少量导出清单和回执暂存于 `/run` 的私有 tmpfs 会话目录。
不需要先更新设备工具，也不向已满的共享区写入导出清单或压缩包。备份字节仍直接传到上位机。
清理后会尝试将回执保存到共享区，任务历史保持不变。

上位机或设备重启后，可以重新导出并核验已有 ZIP，再重新预览。Linux CLI 使用
`--bundle /path/armhpc-ota-1.2.3-r8-maintenance.tar.xz` 指定配套包；串口仍需设备已有备份接口。
共享区满时先执行备份与清理，释放空间后再更新 OTA 工具或进行系统升级。
