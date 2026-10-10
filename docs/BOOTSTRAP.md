# 接入与恢复

已预分区的 OECT SquashFS A/B 在首次启动绑定设备身份，无需重复分区迁移。旧 ext4 Rescue 使用 ota bootstrap 先预览，--apply --yes 执行追加 B 与共享区，不移动现有 BOOT/A，不改 SATA 分区表。

接入备份分区表、启动入口及身份，持久记录各步骤，完整校验载荷与空间后推进。大缓存优先使用已验证 DATA，缺少 SATA 时 Rescue 使用共享空间。

恢复命令只在 Rescue 中执行：`armhpc-rescue ota recover --release initial --target system --yes --json`。恢复 SATA 根保留 DATA 和指定配置；整盘首次安装由 armhpc-rescue configuration 提供交互操作。
