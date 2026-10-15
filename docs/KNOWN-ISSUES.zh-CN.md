# 已知问题

[English](KNOWN-ISSUES.md)

OECT 的硬件看门狗自然超时后可能停在白灯状态，网络和 USB 虚拟串口不恢复。需要完全断开设备电源及 USB，再重新上电恢复；普通软件重启可正常恢复。

OESP 的 NET1 当前通过 USB 2.0 以 480 Mbit/s 枚举。以太网协商为 1000 Mbit/s，不代表这条 USB 连接能够达到千兆吞吐量。

虚拟串口在 Linux USB gadget 启动后提供登录和日志，不能采集 DDR、SPL 或 U-Boot 输出。硬件状态字段保留实际验收结果。
