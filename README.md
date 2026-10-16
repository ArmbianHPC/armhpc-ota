# ARMHPC OTA

[简体中文](README.zh-CN.md)

ARMHPC OTA **1.2.1** is a general update and device-management platform for ARM Linux systems. It combines a shared device engine with a Windows GUI and Windows/Linux controller CLIs.

The update workflow is separated from board-specific storage and boot integration. WXY OEC Turbo (OECT) is the first integrated device; OESP uses a separate board profile, storage policy and compatible firmware packages.

## Features

- Upload local signed packages through SSH/SFTP or USB serial, without requiring a fixed controller IP address.
- Discover SSH candidates and DNS/mDNS hostnames without logging in; read hostname and MAC information through authenticated SSH or serial sessions.
- Select, filter and remove hosts, inspect command results, and run operations with concurrency from 1 to 8. Inspect management actions and diagnostic results from the same device inventory.
- Replace the configured normal-system partition offline from Rescue. Update Rescue through its inactive A/B slot and confirm it after boot.
- Verify Ed25519 signatures, SHA256 hashes, board, architecture, storage layout, and capacity before deployment.
- Resume transfers and persistent tasks after connection loss or reboot, with maintenance backups and rollback.
- Share clock recovery records across the normal system and Rescue A/B, with NTP synchronisation and ordered events.
- Publish optional signed update feeds and HTTP/HTTPS files, and prepare signed release and maintenance packages.

The device engine requires Python 3.11 or later and includes ARM64 and ARM32 runtime support. Windows includes .NET 10 and an isolated Python publishing helper. The Linux controller archive includes x86_64 and ARM64 runtimes. Windows can store login credentials with DPAPI; Linux uses SSH keys or passwords entered locally. Device compatibility is determined by its board profile and package manifest.

## Project structure

| Part | Responsibility |
| --- | --- |
| Device engine | Signature verification, downloads, persistent tasks, deployment, recovery, and tool maintenance. |
| Controller tools | Device discovery, authentication, SSH/serial transport, batch commands, and reconnection. |
| Publisher | Package signing and optional local file service. |
| Firmware integration | Board profiles, boot handling, storage layout, and system payload generation in [armbian-hpc](https://github.com/ArmbianHPC/armbian-hpc). |

## Get started

Download the software from [Releases](https://github.com/ArmbianHPC/armhpc-ota/releases).

| Package | Purpose |
| --- | --- |
| `armhpc-ota-<version>-windows-x64.msi` | Install the Windows GUI, CLI, publisher, and maintenance package. |
| `armhpc-ota-<version>-linux-cli.tar.gz` | Extract and run `./armhpc-ota-cli --help` on a Linux controller. |
| `armhpc-ota-<version>-maintenance.tar.xz` | Update OTA tools on existing devices. |

On Windows, launch **ARMHPC OTA** from the Start menu or use `ARMHPC-OTA-CLI.exe --help`.
On devices, use `armhpc ota` in the normal system and `armhpc-rescue ota` in Rescue.

```sh
armhpc ota status --json
armhpc-rescue ota tools status --json
armhpc-rescue ota tools update --bundle /path/maintenance.tar.xz --yes --json
armhpc-rescue ota recover --release current --target system --yes --json
```

Choose a system OTA package that matches the device's board profile from [armbian-hpc](https://github.com/ArmbianHPC/armbian-hpc). A maintenance package updates tools; it does not replace the system image.

## Documentation

- [Contributing](CONTRIBUTING.md)
- [Maintenance](docs/MAINTENANCE.md)
- [Questions and ideas](https://github.com/ArmbianHPC/armbian-hpc/discussions)

- [Windows installation](docs/INSTALLATION.md)
- [Windows GUI and CLI](docs/WINDOWS.md)
- [Device and batch commands](docs/DEVICE-MANAGEMENT.md)
- [Automatic upgrades and reconnection](docs/AUTOMATIC-UPGRADE.md)
- [Signing and releases](docs/RELEASES.md)
- [Building the software](docs/BUILD.md)
- [v1.2.1 release notes](docs/releases/v1.2.1.md) / [简体中文](docs/releases/v1.2.1.zh-CN.md)
- [Known issues](docs/KNOWN-ISSUES.md)

## License

Original code is licensed under **GPL-3.0-only**. Third-party components retain their licenses; see [LICENSE](LICENSE), [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), and the license materials included in each package.
