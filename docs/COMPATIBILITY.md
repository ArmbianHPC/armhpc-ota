# Independent versions and compatibility

[简体中文](COMPATIBILITY.zh-CN.md)

`armbian-hpc` and `armhpc-ota` use independent MAJOR.MINOR.PATCH versions. Change the version of the repository being released; a companion repository does not need an empty release or version bump. The framework version names firmware images and system OTA packages. The OTA version names the agent, controllers and maintenance package.

## Build inputs

Each repository declares its requirements in `COMPATIBILITY.json`. Builds compare numeric versions against `minimum_companion_version`, check the source interface and OTA protocol, and validate the framework's explicit `minimum_agent`. They do not compare the two release versions for equality. For example, framework 1.2.1 with OTA 1.2.2, or framework 1.2.2 with OTA 1.2.1, is supported when those declared requirements remain satisfied.

The current baseline requires companion source 1.2.1 or later. It reflects the shared recovery and firmware-update resources used by this source tree; it is not a minimum firmware version for every connected device. Published source through 1.2.1 predates the contract and is recognised as legacy source interface 1 / OTA protocol 1. Later source must supply an explicit contract. New incompatible interfaces are rejected, even if their version number is higher.

Pin the exact companion commit used for CI in `.github/companion-source.json` and the workflows. This is a tested source selection, not a requirement to synchronise release numbers. Public builds still require clean, committed inputs. Build records keep both `source_versions` and `source_commits`; each corresponding-source archive uses its own repository version or exact commit.

## Device and package compatibility

- Preserve JSON `protocol: 1`, existing command arguments, task identifiers, reconnect behaviour and optional-field defaults. Add compatible optional fields without requiring an old device to provide them.
- New agents continue to read supported older signed packages and task records. Older installed firmware can receive a newer maintenance package when its board, layout and runtime requirements are satisfied.
- A package's `minimum_agent` specifies the oldest agent that implements its required features. Increase it only when a feature needs a newer agent, not merely because the builder or framework version increased. The framework contract currently specifies 1.2.1; paired BOOT firmware updates also retain their existing 1.2.1 floor.
- A firmware package can have a newer version than its compatible agent. An old agent that lacks a required feature must receive maintenance before deployment.
- Keep signatures, hashes, architecture, board, layout, boot ABI, paired kernel/DTB/initramfs/modules, capacity and active-root protection. Independent versions do not permit incompatible firmware or bypass anti-rollback sequence checks.
- The signed maintenance manifest and the runtime it contains must still agree on the OTA version. Compatibility does not imply downgrading K3s/etcd data or restoring an older device identity.

Backwards compatibility is a release requirement: retain older supported behaviour in regression checks, and raise the relevant minimum or interface explicitly when an incompatible change is unavoidable. It cannot guarantee compatibility with arbitrary future packages or unsupported hardware.
