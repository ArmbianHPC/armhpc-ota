# 看门狗与 BOOT 诊断

公开接口：普通系统 `armhpc watchdog status/report`；Rescue `armhpc-rescue watchdog status/prepare/test/report`。BOOT 管理使用 `armhpc[-rescue] ota boot plan/apply/status/rollback`。

一次诊断使用唯一 ID，准备后仅提交一次。结果未知时重连并查询原 ID。执行前确认设备可恢复、SATA 数据及供电条件正确、没有活动升级或挂载中的 SATA 根／DATA。

Guardian 复用唯一看门狗持有者。expire 真正停止喂狗；reboot、direct-restart 和 panic 分别提供不同复位路径。返回状态与触发证据不能替代操作者确认；人工恢复使用 --manual-recovery，自行恢复使用 --confirm-recovered。

BOOT 维护限定在 Rescue，先备份并导出恢复文件，再切换版本化入口。永久引导链、MiniLoader、DATA 和分区前部不在维护写入范围。回滚恢复相关入口与选择，不回滚身份或共享时间。

USB 虚拟 COM 依赖 Linux。完全无 Linux/COM 时，按设备方法进入 Loader，仅按导出元数据恢复 BOOT；BOOT 分区镜像不得写到地址 0。
