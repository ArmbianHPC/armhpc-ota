# Repository maintenance

[简体中文](MAINTENANCE.zh-CN.md)

This repository follows the [organization workflow](https://github.com/ArmbianHPC/.github/blob/main/GOVERNANCE.md). The sole maintainer is `chens32`; PRs require passing CI and resolved conversations, with zero approving reviews and no mandatory Code Owner review.

## CI

`CI` runs on PRs, pushes to `main` and manual dispatch. Python 3.11 and the pinned CI dependencies exercise the existing suite. License/source inventory and JSON/YAML checks run on the checkout. Windows core/WPF checks and Linux x64/ARM64 CLI builds use the SDK in global.json.

The public companion source is fixed in `.github/companion-source.json`. Update its commit and the corresponding workflow refs together after checking compatibility. Third-party Actions are pinned to full commits. Dependabot proposes grouped weekly updates; merges remain manual. CodeQL runs separately and uploads code-scanning results.

PR jobs use GitHub-hosted runners, read-only repository contents and no release/device secrets. They do not contact actual ARMHPC nodes. Compile or simulated results do not change hardware acceptance. Workflows must not check out untrusted PR code in a privileged `pull_request_target` context.

## Builds and releases

Run full firmware assembly and signing in the controlled build environment using recorded commits and explicit board inputs. Public PR CI does not receive signing keys, user backups or proprietary loaders. Follow [build instructions](BUILD.md) and the existing release policy.

Record hashes, source commits, dependency/license materials and initialization inputs. Fresh supplied images use the public default `root` / `1`; remove local credentials and SSH private keys before publication, including nested recovery templates. Keep existing-device identity and configuration preservation separate from fresh-image initialization.

Use a draft, upload the complete expected package set, verify remote sizes and SHA256, then publish with a version-only title and bilingual notes. Binary corrections use a new version. Existing published files and tags remain unchanged. Future immutable releases can be enabled after source/redistribution review and the complete draft are ready.

Owner-only emergency changes to repository rules should be restored and recorded. Do not set mandatory approvals or environment reviews that require a second person while the project has one maintainer.
