# Known issues

[简体中文](KNOWN-ISSUES.zh-CN.md)

On OECT, a natural hardware-watchdog timeout can leave the device at a white light with no network or USB console. Disconnect both power and USB completely, then power it on again to recover. Ordinary software reboot recovers normally.

OESP NET1 currently enumerates over USB 2.0 at 480 Mbit/s. A 1000 Mbit/s Ethernet negotiation does not imply gigabit throughput through that USB connection.

The USB console starts with the Linux gadget; it cannot capture DDR, SPL or U-Boot output. Hardware status fields report their actual acceptance state.
