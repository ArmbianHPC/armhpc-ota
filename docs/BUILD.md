# Software builds

[简体中文](BUILD.zh-CN.md)

Use clean, compatible commits of both repositories; their release versions may differ. See [independent versions](COMPATIBILITY.md). Device code supports Python 3.11+. Windows uses the SDK in `global.json`; `DEPENDENCIES.lock.json` and NuGet lock files pin release dependencies.

```sh
python3 -m pip install -r requirements-test.txt
PYTHONPATH=src python3 -m pytest tests
```

Run `ArmHpc.Ota.Tests` and `ArmHpc.Ota.UiTests` with the pinned .NET SDK. Python regression uses pytest so function tests and unittest cases are both collected.

Prepare redistributable board firmware explicitly, then build the runtime, signed maintenance and Windows portable input from committed sources:

```powershell
python ..\armbian-hpc\tools\build\prepare-firmware-inputs.py --project ..\armbian-hpc
python tools/build-release.py --framework-source ..\armbian-hpc --work BUILD_WORK --output PACKAGE_OUTPUT --helpers HELPERS --cache DOWNLOAD_CACHE --signing-key PRIVATE_KEY --key-id KEY_ID
```

`build-release.py` also runs firmware preparation, verifying cached bytes against the board's pinned SHA256 and license policy. Native helpers come from `tools/build-helpers.py --output HELPERS` and are checked for ARM64/ARMhf and Debian Bookworm glibc compatibility.

Build the Windows MSI from the verified portable directory with `tools/build-msi.py`, WiX 4.0.6 and `WixToolset.UI.wixext/4.0.6`. The installer provides license, destination, desktop shortcut, PATH, confirmation, progress and completion pages. Build the Linux x86_64/ARM64 host CLI archive with `tools/build-linux-cli.py`.

Release assets are exactly the MSI, Linux host CLI tar.gz and signed maintenance tar.xz. Keep intermediate portable/runtime/source packages locally; their needed source and license materials are embedded in the three assets. Signing keys remain outside repositories and public packages. Existing versioned assets are immutable.

Use `tools/release-policy.py --release-id ID` for a draft, verify the three uploaded SHA256 digests, then `--apply --publish` to publish with the version-only title. See [release policy](RELEASES.md).
