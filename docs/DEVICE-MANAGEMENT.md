# 设备与批量操作

表格显示主机名、连接、环境、系统版本、Rescue 版本／槽位、时间状态、最近命令和返回概况；详细行与横向滚动查看完整结果。

可勾选、全选可见、反选和清空选择；主机名支持精确与包含筛选。默认登录与单台登录保存在本机加密存储，CSV 不导出密码。

命令、工具接入和 OTA 队列支持并发 1–8。OTA 和接入默认先完成一台，再推进后续设备；失败暂停后续队列。写盘开始后停止批量仅停止尚未开始的设备。

命令栏支持 armhpc、armhpc-rescue、armhpc-kube 的单条命令。交互配置使用 SSH／串口终端。返回状态为 succeeded、failed、unknown 或 skipped；忽略 unknown 只影响队列推进，不把未知结果改为成功。

旧请求使用原 ID、包哈希和目标继续。串口重启或认证中断后重新认证，释放占用；不同时用多个终端占用同一 COM。

## 网口定位

命令栏提供“网口绿灯定位（30 秒）”“停止网口定位”和“网口定位状态”。支持多选设备及 1–8 并发；在 Rescue 中自动使用对应命令入口。设备需要安装包含该命令的框架运行时。

```sh
armhpc identify --seconds 30 --json
armhpc identify --stop --json
armhpc identify --status --json
```

可用 `--interface eth0` 指定网口，`--period-ms 1000` 设置亮灭周期。后台任务在连接断开后继续，到时或停止时恢复原来的硬件 LED 规则。此方式要求网口有链路，以及关联绿色 PHY LED 的 netdev 硬件卸载支持。

设备端的三个 ARMHPC 命令入口支持 Bash Tab 补全。安装相应维护资源后，SSH／串口新登录会话自动加载；现有终端执行 `source /usr/lib/armhpc/completion.bash` 即可启用。

## 主机名和网络配置

命令栏提供“主机名”和“网络配置和事务”查询，支持以下普通系统命令：

```sh
armhpc hostname set compute-07 --yes --json
armhpc network show --interface eth0 --json
armhpc network set --interface eth0 --dhcp --plan --json
armhpc network set --interface eth0 --dhcp --yes --json
armhpc network confirm --transaction <事务ID> --yes --json
armhpc network rollback --transaction <事务ID> --yes --json
```

网络设置由 systemd-networkd 应用，默认 90 秒内需通过新地址或 USB 串口确认，否则自动回滚。
重新交互式 SSH 登录会先提示确认、回滚或稍后处理；非交互命令和 SFTP 不弹提示，登录本身不算确认。
先确认网络事务，再执行 OTA。升级和 OTA 恢复会保留普通系统主机名、hosts 和网络配置；
Rescue 主机名继续自动生成。交互向导使用 `armhpc hostname configure` 或 `armhpc network configure`，
需要 SSH／串口终端；命令栏不会向 Rescue 自动转换这些普通系统配置命令。
设备需先安装包含新命令和保留策略的维护运行时。
