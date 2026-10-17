# Rescue backups and shared storage

[简体中文](BACKUPS-AND-STORAGE.zh-CN.md)

Select one authenticated Rescue device, then open **Backups and shared storage**
(`备份与共享空间`) in the OTA tab. Select the BOOT and tool-maintenance backup
groups and choose a private folder on the controller.

The workflow transfers original files over authenticated SSH/SFTP or serial,
checks every SHA256, then creates a ZIP on the controller. It opens the ZIP again
and verifies its inventory and every decompressed file before acknowledging the
export to the device. Rescue does not compress files or stage an export archive.
Interrupted transfers retain local partial files and do not authorize deletion.
The ZIP contains `backup-inventory.json` and the original files under `files/`.
Keep the ZIP and its adjacent JSON receipt private; BOOT backups can contain
device identities and access settings. Extract `files/` when original recovery
files are needed.

After every selected export succeeds, the window displays a cleanup plan and
asks whether to execute it. The plan can reclaim obsolete download caches,
unreferenced BOOT staging, upload staging older than one hour, and verified
exports of completed BOOT backup groups on OTA_SHARED. The current tool rollback
backup, current BOOT payload, active or recoverable tasks, factory and confirmed
baselines, overlays, identity, configuration, time records, and task history are
retained. Unknown backups can be exported but are retained locally. Files on SATA
DATA are not included in shared-storage cleanup. No partition or filesystem is
resized or reformatted.

Cleanup rechecks tasks, file identities and the exact plan before deleting any
entry. A changed plan must be reviewed again. A completed BOOT backup removed
after export is thereafter available from the verified controller ZIP; it cannot
be used through its former device-local path until restored there. A cleanup I/O
failure may leave a partially executed plan; refresh the inventory before retrying.

## CLI

On the controller (Linux or Windows):

```sh
ARMHPC-OTA-CLI storage-status --ssh 192.168.1.20 --username root --json
ARMHPC-OTA-CLI backup-export --ssh 192.168.1.20 --username root --output-directory /private/armhpc
ARMHPC-OTA-CLI backup-export --ssh 192.168.1.20 --username root --output-directory /private/armhpc --cleanup-after-export --yes
```

The last command prints the current cleanup plan and executes it only after all
selected archives have passed readback verification. Authentication and host-key
verification use the same per-environment settings as other OTA operations.

Device commands are `armhpc-rescue ota storage status`, `export --backup-id ID`,
`acknowledge --inventory-sha256 HASH --archive-sha256 HASH`, `plan`, and
`cleanup --plan-id HASH --yes`, with `--json` available. The controller's verified
archive workflow should be used to acknowledge exports. `stage --bytes N` reserves
an upload directory after checking space and preparing validated SATA DATA.

Install the maintenance archive shipped with this rebuild even if the displayed
agent version is already 1.2.3. The `storage_management` capability identifies this
implementation. SSH uploads prefer the validated DATA cache and are rejected
before transfer when there is insufficient staging space. Export and cleanup can
recover occupied shared space but cannot increase physical eMMC capacity.

This rebuild is displayed and delivered as **1.2.3-r8**. MSI and numeric agent compatibility remain `1.2.3`; `agent_display_version` and signed maintenance `display_version`/`revision` identify the rebuild.

If the controller retains an unfinished automatic task for this device, uploaded files and caches are protected so that the original task can continue. Completed and verified exported backups remain eligible. Cancel or finish the controller task, then refresh the plan to review other remnants.

## Full shared storage or older device tools

The r8 SSH backup entry uses the signed maintenance bundle shipped with the MSI. The device verifies
its signature, adapter and identity, then loads the backup helper into memory. Small inventories and
receipts live in a private `/run` tmpfs session. No tool installation, shared-storage export metadata,
or on-device compression is needed before transfer. Cleanup attempts to persist receipts after space
has been freed and retains task history.

After controller or device restart, export and verify the existing ZIP again before reviewing a fresh
plan. Linux CLI users provide `--bundle /path/armhpc-ota-1.2.3-r8-maintenance.tar.xz`.
Serial connections still require an installed backup interface. When shared storage is full, export
and review cleanup first, then install device tools or resume system updates.
