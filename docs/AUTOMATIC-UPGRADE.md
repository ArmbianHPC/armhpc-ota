# Automatic upgrades

[简体中文](AUTOMATIC-UPGRADE.zh-CN.md)

Select a signed local system package and its maintenance package. Authenticate each device and check its identity, versions, tasks and available space. Complete any required tool maintenance before continuing the system upgrade.

Resources are transferred and resumed over SSH/SFTP or serial, verified, and submitted under the original persistent request ID. A normal system enters the confirmed Rescue environment before writing the SATA system. Rescue updates write the inactive slot and then confirm the new boot. DATA and the device identity are retained.

After a connection loss, query the original task. Reauthentication, address changes and COM takeover must verify the persistent device ID. Submitted device services run independently of the controller window.

## Cancel a paused controller task

In **Batch OTA**, select the devices and click **取消暂停任务** (Cancel paused tasks). Review the task IDs and confirm. Only paused controller automation is cancelled; submitted device operations continue. Cancellation does not roll back an update, stop a device service or cancel a device-side job.

The original automation, maintenance and deployment IDs, package bindings, paused phase, last error and cancellation time remain in local storage. Click **自动流程历史** (Automatic task history) to view the selected devices' records, including cancelled tasks. History remains available after restarting the application. Cancelled flows are excluded from resume and no longer occupy the controller's active automation slot. A new operation still checks the device's actual task and maintenance state before submitting work.

To request cancellation of a device-side OTA job before disk writing, use **写盘前取消** with the appropriate device task. This is a separate operation.

Device events retain sequence, boot ID, monotonic time and clock quality. The controller reception time is displayed separately. System OTA does not automatically upgrade K3s.

A firmware package may sign recovery for the original kernel/DTB and its candidate pair. The device selects only an exact confirmed Rescue pair, validates the matching initramfs, and binds that selection to the private recovery export. Unknown pairs remain rejected before BOOT writes. Older archives without the signed alternative cannot acquire it from a tool update; select the rebuilt package.
