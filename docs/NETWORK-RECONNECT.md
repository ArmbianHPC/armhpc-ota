# Network reconnection and retained settings

[简体中文](NETWORK-RECONNECT.zh-CN.md)

## Static System, DHCP Rescue

System and Rescue can keep different network configurations. The controller records
addresses separately for authenticated System and Rescue sessions, including the
SSH port, and remembers the MACs of all physical interfaces. These observations
remain in the local device inventory across controller restarts.

After a restart or connection loss, Windows and Linux controllers use the same
reconnection sequence:

1. Try the current address and previously authenticated environment addresses.
2. Read the host's IPv4 neighbor cache and prioritize addresses matching a known
   device MAC within the selected scope.
3. Scan the configured `--scan-range` / GUI range, refresh neighbor information,
   then verify candidates. The discovery scan reads SSH banners without sending
   login credentials.
4. If no range is configured and an authenticated MAC is known, search the host's
   directly connected private IPv4 subnets with prefixes `/22` through `/30`,
   limited to 1,024 host addresses in total. Larger or routed networks require an
   explicit range. Without known MAC information, automatic subnet scanning is
   disabled; explicit ranges remain available.

MACs locate candidates. A rediscovered address must still present a previously
registered SSH host key and return the original persistent device ID. A temporary
fingerprint override for the selected address is never extended to rediscovery.
Register the System and Rescue SSH identities before an unattended switch.
Existing jobs and request IDs continue after reconnecting; discovery does not
submit a second deployment.

A reboot closes the old SSH session. Reconnection restores task observation after
the new environment obtains a reachable address and starts SSH. MAC discovery
does not change either environment's IP configuration, DHCP server, routes or
firewall. Across a router, the neighbor table may contain the router's MAC rather
than the device's; use reachable known addresses or an explicit scan range.

## OTA and system recovery

Before replacing the SATA System root, the device captures that System root's
selected configuration. It restores it into the new root before starting System.
Rescue configuration is captured independently and is not used as the System
network profile.

Retained network resources include:

- systemd-networkd `.network`, `.netdev`, `.link` files and drop-ins under
  `/etc/systemd/network`;
- NetworkManager connection profiles under
  `/etc/NetworkManager/system-connections`;
- `/etc/netplan`, `/etc/network/interfaces` and `/etc/network/interfaces.d`;
- `/etc/resolv.conf`, `/etc/systemd/resolved.conf` and its drop-ins;
- ARMHPC management-interface, route policy and confirmed network transaction
  settings, plus physical interface identities and MAC records.

When a complete network configuration directory was captured, restoration replaces
that directory's image defaults with the saved directory. This prevents a newly
introduced DHCP profile from taking precedence over a retained static profile.
When no old directory was captured, the new image's defaults remain available.

The same preservation path is used for system OTA, Rescue-initiated system
recovery and continuation after an interrupted write. An unconfirmed network
change blocks OTA until it is confirmed or rolled back.

Runtime-only `ip address` / `ip route` commands, active DHCP leases and custom
configuration stored outside the preservation policy are not saved as static
configuration. A full eMMC flash or a fresh SATA installation has different
semantics from preserving an existing System root through OTA/recovery.

## Reconnect diagnostics

Reboot confirmation and OTA observation report registered MACs, trusted environments, scan ranges, matching addresses and connection outcomes. A found address with rejected SSH credentials or an unregistered environment key is reported separately from an empty discovery result. Trust checks remain enabled for discovered addresses.

Known offline addresses first receive a bounded SSH banner check. If SSH becomes ready during scanning, that address can be tried again in the same round. The timeout result retains the original pre-reboot boot ID and last discovery reason; it never re-sends the reboot command.

## Manually find the current IP

In the Windows GUI, select registered SSH devices, set the scan range if needed,
then click **按 MAC 查找 IP** in **发现与登录**. The active scan refreshes neighbor
information and shows matching IPs together with SSH readiness. Cached neighbor
entries without an SSH response are displayed as unready.

The controller updates a managed address only after SSH authentication and the
original persistent device ID are verified. A previously unregistered environment
key can be explicitly approved in this manual action; a changed registered key
is rejected. Login failure or cancellation preserves the old managed address and
the discovered IP list. **停止扫描** cancels the scan and its identity queries.
The action sends status queries only and preserves existing deployment tasks.

## Separate System and Rescue login methods

Windows stores SSH login settings separately for System and Rescue, encrypted with
DPAPI. Existing device-wide entries remain readable. A trusted environment host
key selects that environment's saved login before credentials are sent. If the
environment has no saved login or rejects it, the configured default login is available; for
example, System can use a private key while Rescue uses the saved default password.
When a host key cannot distinguish the environments, only explicitly configured
logins can be tried, and only during SSH authentication. Commands and deployments
are never retried because of an authentication fallback.

Successful login choices are remembered only after host trust, environment and
persistent device ID checks. Changing the current environment's login settings
does not replace the other environment's settings. Fingerprint rejection is shown
separately from account authentication failure. MAC matches still require SSH
trust and the original device ID.

## Key/password fallback and environment accounts

**默认登录设置** (Default login) can retain an SSH private key, its passphrase and the account password together. Each profile tries its key first, then its password after authentication rejection or an unusable key. Host-key rejection, network failures and command execution failures do not trigger an authentication-method retry. Commands are never resubmitted by this fallback.

**System / Rescue 默认登录** stores independent default usernames, passwords and keys for both environments. **单台登录设置** provides separate System and Rescue tabs; either can be edited before switching the device. Select the environments to save; other profiles remain unchanged. Per-device profiles take priority, followed by environment defaults and the generic default.

Windows DPAPI encrypts these local settings. Editing controller login settings does not change a device account. Successful authentication retains the complete configured profile, including the alternative method.
