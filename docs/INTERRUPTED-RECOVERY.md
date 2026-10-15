<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Interrupted Rescue deployment

[简体中文](INTERRUPTED-RECOVERY.zh-CN.md)

OESP MBR discovery uses the exact disk signature, partition numbers and ranges. A Rescue slot normally also needs a valid signed SquashFS trailer and content hash. An interrupted inactive-slot write may have no committed trailer. The admitted write intent retains that target's physical identity, bound to the persistent device, original job and exact trusted manifest.

The runtime verifies the running Overlay root and persistent identity before interpreting an interrupted target. Only an authenticated write intent can supply the target's logical filesystem identity. Unknown slots, forged markers, changed GUID/ranges/disks, invalid signatures and the running root remain refused.

After a hard interruption, reconnect to the same device and query the existing job:

```sh
armhpc-rescue ota status --json
armhpc-rescue ota logs --job <original-job-id> --json
```

An unfinished worker continues its original durable job. A job that has recorded `failed-recoverable` is handled through the existing recovery flow; `retry` is reserved for recoverable failures before disk writing.

For a BOOT candidate rollback, use the original request ID:

```sh
armhpc-rescue ota boot status --json
armhpc-rescue ota boot rollback --request-id <original-id> --yes --json
```

Rollback restores the original confirmed boot choice and preserves an unfinished inactive target's write intent. An immutable rollback journal keeps this identity usable even after another BOOT task is created. The binding is removed only after a replacement deployment completes; it does not make the unfinished slot bootable. Boot still verifies the complete signed SquashFS content. A partially written normal system remains blocked.

## SATA disk identity

Interrupted writes retain the original disk serial number and WWN. Legacy intents use the original durable task plan to recover a recorded WWN. A replaced disk, a missing recorded identity or a conflicting plan is refused before target admission. An OESP record without a provable original serial number or WWN cannot authorise a replacement write.
