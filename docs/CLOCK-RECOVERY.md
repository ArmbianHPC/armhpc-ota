# 时间恢复

普通系统及 Rescue A/B 使用 OTA_SHARED 上的 confirmed-time.json 与 resume-time.json，并保留本地副本。共享目录必须确认为实际挂载的 ext4；保存使用锁、原子替换和 fsync。

启动按记录恢复时间下限，之后由 chrony 校准。NTP 可用时记录 synchronised；有有效恢复锚点时使用 estimated；无有效锚点为 invalid，拒绝新的 OTA 写入。

开机首次检测与周期检查、重启和关机保存覆盖普通系统及 Rescue A/B。保留用户 chrony 配置，可配置内网 NTP。NTP 能纠正过高的旧记录；历史事件原始时间不改写，事件顺序使用 sequence 和 boot_id。

状态：`python3 /usr/lib/armhpc/clock_floor.py --status`。主动保存：`python3 /usr/lib/armhpc/clock_floor.py --flush --reason manual`。
