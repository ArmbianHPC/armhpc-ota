# SquashFS A/B

OECT 布局 oect-squashfs-ab-v2：BOOT 512 MiB ext4，Rescue A/B 各 512 MiB SquashFS，剩余共享 ext4。运行 Rescue 使用下层只读镜像与分槽、分版本可写层；普通 SATA 系统为 64 GiB ext4，DATA 为其余 ext4。

更新备用 Rescue 后校验镜像与槽位提交记录，再进行一次启动确认。共享区保存身份、时间、控制、内核配套和恢复基线。初始基线不被当前版本替换。
