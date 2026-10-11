# ARMHPC OTA

[简体中文](README.zh-CN.md)

ARMHPC OTA **1.0.0** provides a dual-system update engine and desktop tools for managing ARMHPC devices.

## Features

- Windows GUI and CLI, plus a Linux controller CLI, upload local signed packages over SSH/SFTP or USB serial. The controller does not need a fixed IP address.
- Select multiple devices, filter by hostname, inspect command results, and run operations with concurrency from 1 to 8.
- Update the SATA system offline from Rescue. Update Rescue through the inactive A/B slot and confirm it after boot.
- Verify Ed25519 signatures, SHA256 hashes, board, architecture, layout, and capacity before deployment.
- Resume transfers and persistent tasks after a connection loss or reboot, with maintenance backups and rollback.
- Share clock recovery records across the normal system and Rescue A/B, with NTP synchronisation and ordered events.
- Optional signed update feeds, HTTP/HTTPS file publishing, and package signing tools.

The device engine requires Python 3.11 or later. Windows includes .NET 10 and an isolated Python publishing helper. The Linux controller archive includes x86_64 and ARM64 runtimes. Windows can store login credentials with DPAPI; Linux uses SSH keys or passwords entered locally.

## Get started

Download the packages from [Releases](https://github.com/ArmbianHPC/armhpc-ota/releases).

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

System upgrades require a compatible system OTA package from [armbian-hpc](https://github.com/ArmbianHPC/armbian-hpc). A maintenance package updates tools; it does not replace the system image.

## Documentation

- [Windows installation](docs/INSTALLATION.md)
- [Windows GUI and CLI](docs/WINDOWS.md)
- [Device and batch commands](docs/DEVICE-MANAGEMENT.md)
- [Automatic upgrades and reconnection](docs/AUTOMATIC-UPGRADE.md)
- [Signing and releases](docs/RELEASES.md)
- [Building the software](docs/BUILD.md)
- [v1.0.0 release notes](docs/releases/v1.0.0.md) / [简体中文](docs/releases/v1.0.0.zh-CN.md)
- [Known issues](docs/KNOWN-ISSUES.md)

## License

Original code is licensed under **GPL-3.0-only**. Third-party components retain their licenses; see [LICENSE](LICENSE), [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), and the license materials included in each package.

The OTA engine is maintained in this repository. Board integration and firmware builds are maintained separately in [armbian-hpc](https://github.com/ArmbianHPC/armbian-hpc).
