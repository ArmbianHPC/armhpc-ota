# v1.2.1

- Add signed paired kernel/BOOT firmware updates with private recovery export and persistent controller reconnection.
- Integrate management network, node resource recovery, authentication, firewall, swap and health status.
- Preserve existing JSON protocol and task bindings across firmware and tool updates.

# v1.2.0


- Add OESP board, storage, paired BOOT maintenance and recovery support.
- Preserve disk identity when resuming interrupted deployment and reconnect SSH or serial sessions to the original task.
- Include board firmware, fan and performance resources in maintenance packages.
- Update the Windows installer, Linux controller CLI and release packaging.

# v1.1.4

Bind interrupted SATA writes to their original WWN and serial number, including compatible legacy task records.

# v1.1.3

Retain and authenticate interrupted OESP Rescue write targets during discovery and BOOT rollback.

# v1.1.2

Bind private BOOT exports to the original device and task. Add OESP USB RAM recovery, BOOT-only restoration and controller recovery actions.

# v1.1.1

- Add OESP FAT32 BOOT maintenance with paired system deployment through the existing OTA engine.
- Select signed hardware resources by board and retain performance services during baseline recovery.
- Extend dual-port diagnostics and the controller's BOOT confirmation flow.

# v1.1.0

- Add DNS/mDNS hostname discovery, authenticated MAC inventory and local host removal.
- Streamline device management, group diagnostics and retain concurrent SSH/serial operations.
- Improve maintenance submission recovery and bind Linux controller builds to their included source archive.
- Preserve normal-system host settings and include the current shared management resources in signed maintenance.


# 1.0.0

首次正式发布：双系统 OTA、SSH/USB 串口、批量管理、持久任务、时间恢复、签名工具维护和许可材料。
