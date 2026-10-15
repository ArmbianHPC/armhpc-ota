<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Paired firmware updates

[简体中文](FIRMWARE-UPDATES.zh-CN.md)

Version 1.3.0 recognizes a signed firmware transport containing `firmware/boot-update.tar.xz`. Select **all** when importing this package. The nested signed purpose is `firmware-update` and its minimum device agent is 1.3.0. A standard same-BOOT system/Rescue transport keeps its existing behavior.

Install the supplied maintenance package before a firmware update. The controller checks the persistent device ID, signature, board, layout, BOOT ABI and payload pairing. It enters confirmed Rescue, prepares a private recovery backup and downloads every backup file with size/SHA256 verification before switching BOOT. Keep the displayed local backup directory until the node has passed acceptance.

The device retains the original bundle and request ID. After the candidate Rescue confirms its boot, it deploys the paired normal system through the existing engine and checks persistent resources and services before committing. Closing the controller or losing SSH/COM does not create a new job. Reopen the saved task to observe its original request. Unknown or timed-out results remain pending verification.

```sh
armhpc ota boot status --json
armhpc-rescue ota boot status --json
armhpc-rescue ota boot rollback --request-id ORIGINAL_TASK_ID --yes --json
```

Apply/rollback is restricted by the device's current environment, original task binding and signed resources. Retain the exported BOOT recovery instructions with the private backup. The supplied package supports only its declared old kernel/DTB pairing; other baselines require a matching migration bundle or full image. Normal firmware confirmation does not update watchdog, kexec or full hardware acceptance fields. An early kernel failure may still require local BOOT recovery.

The controller shows management network, kernel capabilities and state recovery when supplied by the device. Older agents display **not provided** for optional fields. New authentication, firewall, resource and swap changes require an explicitly supplied `--yes`; profile/import previews do not apply them. Interactive password change remains an interactive command.

For node configuration, local verification and physical acceptance, use the matching framework's `docs/BASE-IMAGE-1.3.0.md` and `tools/verify-node-1.3.py`. Source commits, final kernel configuration/module receipts, license materials and SHA256 lists identify the delivered files. Keep credentials, device backups and signing keys private.
