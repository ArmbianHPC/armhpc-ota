# Device management

[简体中文](DEVICE-MANAGEMENT.zh-CN.md)

The device table shows hostname, MAC address, address/COM, board, environment,
system and Rescue versions, status, recent command and result summary. Selecting
a row highlights it without expanding a details panel. Full command output is
shown in the separate results panel.
Notes, transport and clock-quality columns are no longer displayed; existing
connection settings and clock records remain compatible.

## Discover without logging in

Specify an IPv4 CIDR and select **Scan SSH / hostname**. The scan first finds SSH
candidates, then queries reverse DNS and local-link mDNS PTR records. It never
sends usernames, passwords or SSH authentication messages. Name queries have a
bounded deadline and can be cancelled with the scan.

DNS/mDNS names are discovery hints, not verified device identity. Devices and
routers must publish appropriate records; otherwise the hostname remains empty.
The SSH banner is not used as a hostname. A later authenticated query replaces
the discovered name with the actual OS hostname. Rediscovery never overwrites an
already verified managed hostname.

## MAC addresses

Authentication and status refresh read the current MAC addresses of physical
interfaces through the existing SSH or serial connection. The interface carrying
the SSH connection is preferred for the table; all available interface names,
MACs and addresses are available in the host CLI status `network_interfaces`
field. Loopback and virtual interfaces are excluded. The probe is read-only and
does not require a new device agent.

MAC values are inventory information; upgrade authorization continues to use
the persistent device ID and trusted SSH identity. Existing protocol-1 status
fields are retained. The host CLI status response adds `mac_address`,
`network_interfaces` and `hostname` when these are available.

## Select, filter and remove

Use checkboxes, Ctrl/Shift row selection, select-visible, invert or clear-selection.
Filtering supports hostname, MAC, address and device ID; exact mode matches only
the hostname. Operations use the visible selected devices.

**Delete selected hosts**, or Delete while the table has focus, removes candidates
or registered hosts from the local list. Local connection credentials for removed
connections are cleared; default login settings are retained. Device tasks and
their original local task records remain intact. Re-add and authenticate a host
to continue observing its task. Rescanning can discover a removed host again.
Deletion is refused during an active local scan, authentication or batch.

## Operations

- **Device management:** everyday ARMHPC commands, hostname/network management,
  port identification, reboot and single-device terminal access.
- **Batch OTA:** local push, tool maintenance, original-task continuation,
  status/logs, pre-write cancel/retry and Rescue recovery.
- **Initial setup:** bootstrap preview and initial OTA layout setup.
- **Development and diagnostics:** watchdog fault injection, BOOT candidates and
  backups, legacy source-based updates, publishing, fingerprint override and
  detailed clock diagnostics.

The everyday preset picker excludes development presets. Their CLI commands,
confirmation rules and identity checks are unchanged. Watchdog and BOOT writes
still require one device, concurrency one and observation of the original ID.

Commands, setup and OTA use concurrency 1–8. OTA/setup default to a pilot device;
failure pauses followers. Stopping a batch stops later devices and does not cancel
an already submitted device task. Unknown command outcomes remain unknown even
when the user elects to continue the queue; commands are not automatically resent.

Default and per-device credentials use local encrypted storage on Windows and are
not exported to CSV. Interactive wizards use the SSH/serial terminal. Do not open
the same COM port simultaneously in multiple terminal programs.
