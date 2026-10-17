# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Package the shared .NET controller for Linux x86_64 and ARM64."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile

LAUNCHER = '''#!/bin/sh
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case $(uname -m) in
    x86_64|amd64) rid=linux-x64 ;;
    aarch64|arm64) rid=linux-arm64 ;;
    *) echo "Supported architectures: x86_64 and ARM64" >&2; exit 2 ;;
esac
exec "$base/runtimes/$rid/ARMHPC-OTA-CLI" "$@"
'''


def source_commit(repo, source_ref):
    status = subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain',
                                      '--untracked-files=all'], text=True)
    if status.strip():
        raise ValueError('Build the Linux CLI from a clean committed checkout; commit or remove pending source changes first')
    head = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', '--verify',
                                    'HEAD^{commit}'], text=True).strip()
    commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', '--verify',
                                      '--end-of-options', source_ref + '^{commit}'], text=True).strip()
    if commit != head:
        raise ValueError('The selected source ref differs from HEAD; check out that commit before building')
    return commit


def export_source(repo, commit, archive, checkout):
    with archive.open('xb') as stream:
        subprocess.run(['git', '-C', str(repo), 'archive', '--format=tar', commit], stdout=stream, check=True)
    checkout.mkdir()
    with tarfile.open(archive, 'r:') as source:
        for member in source:
            relative = PurePosixPath(member.name)
            path = checkout.joinpath(*relative.parts)
            if (relative.is_absolute() or '..' in relative.parts or '\\' in member.name or
                    not path.resolve().is_relative_to(checkout.resolve()) or
                    not (member.isfile() or member.isdir())):
                raise ValueError('Unsafe file or link in the committed source archive')
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as input, path.open('xb') as output:
                shutil.copyfileobj(input, output)
            path.chmod(member.mode & 0o777)


def build(output, work, source_ref='HEAD'):
    repo = Path(__file__).resolve().parents[1]
    output, work = Path(output).resolve(), Path(work).resolve()
    if output.exists():
        raise ValueError('Linux package already exists')
    if any((p / '.git').exists() for d in (output.parent, work) for p in (d, *d.parents)):
        raise ValueError('Build outside repositories')
    commit = source_commit(repo, source_ref)
    checkout, source_archive = work / 'source-tree', work / 'armhpc-ota-source.tar'
    if checkout.exists() or source_archive.exists():
        raise ValueError('Choose a new build directory for the committed source snapshot')
    work.mkdir(parents=True, exist_ok=True)
    export_source(repo, commit, source_archive, checkout)
    version = (checkout / 'VERSION').read_text(encoding='utf-8').strip()
    import ast
    tree=ast.parse((checkout/'src/armhpc_ota/__init__.py').read_text(encoding='utf-8'))
    revision=next((n.value.value for n in tree.body if isinstance(n,ast.Assign) and
                  any(isinstance(t,ast.Name) and t.id=='__revision__' for t in n.targets) and isinstance(n.value,ast.Constant)),None)
    if revision:version+='-'+revision
    root = work / ('armhpc-ota-cli-' + version)
    root.mkdir(parents=True)
    project = checkout / 'windows/ArmHpc.Ota.Cli/ArmHpc.Ota.Cli.csproj'
    for rid in ('linux-x64', 'linux-arm64'):
        dest = root / 'runtimes' / rid
        with (work / (rid + '.log')).open('w', encoding='utf-8') as log:
            subprocess.run(['dotnet', 'publish', str(project), '-c', 'Release', '-f', 'net10.0', '-r', rid,
                            '--self-contained', 'true', '-p:InvariantGlobalization=true',
                            '-p:RestoreLockedMode=true',
                            '-p:SourceRevisionId=' + commit,
                            '-o', str(dest)],
                           cwd=checkout, stdout=log, stderr=subprocess.STDOUT, check=True)
        for p in dest.glob('*.pdb'):
            p.unlink()
        library = dest / 'publisher/Lib/armhpc_ota'
        shutil.copytree(checkout / 'src/armhpc_ota', library,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
        (dest / 'ARMHPC-OTA-CLI').chmod(0o755)
        print('Published ' + rid, flush=True)
    (root / 'armhpc-ota-cli').write_text(LAUNCHER, encoding='utf-8', newline='\n')
    (root / 'armhpc-ota-cli').chmod(0o755)
    for name in ('LICENSE', 'COPYRIGHT', 'THIRD-PARTY-NOTICES.md'):
        shutil.copy2(checkout / name, root / name)
    shutil.copytree(checkout / 'LICENSES', root / 'LICENSES')
    source = root / 'source'
    source.mkdir()
    shutil.copy2(source_archive, source / 'armhpc-ota-source.tar')
    shutil.copy2(checkout / 'DEPENDENCIES.lock.json', root / 'DEPENDENCIES.lock.json')
    nuget = Path.home() / '.nuget/packages'
    for rid in ('linux-x64', 'linux-arm64'):
        directory = nuget / ('microsoft.netcore.app.runtime.' + rid) / '10.0.12'
        for name in ('LICENSE.TXT', 'THIRD-PARTY-NOTICES.TXT'):
            p = directory / name
            if p.is_file():
                target = root / 'LICENSES/third-party' / (rid + '-' + name)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, target)
    (root / 'README.md').write_text('''# ARMHPC OTA Linux CLI

[简体中文](README.zh-CN.md)

Manage ARMHPC devices from a Linux computer through SSH/SFTP or USB serial. The archive includes the .NET runtimes for x86_64 and ARM64.

```sh
./armhpc-ota-cli --version
./armhpc-ota-cli --help
./armhpc-ota-cli status --ssh 192.168.1.20 --username root
./armhpc-ota-cli status --serial /dev/ttyACM0 --username root
./armhpc-ota-cli tools-update --ssh 192.168.1.20 --bundle /path/maintenance.tar.xz --username root
./armhpc-ota-cli upgrade --ssh 192.168.1.20 --package /path/system-ota.tar.xz --bundle /path/maintenance.tar.xz --username root
```

Verify and register the SSH host fingerprint on the first connection. Serial connections require permission to access the selected port. Enter passwords locally or use an SSH private key. Linux does not save login passwords as plaintext; `--remember` uses Windows DPAPI only.

Local system package inspection requires Python 3.11 or later and cryptography, such as the `python3-cryptography` package on Debian/Ubuntu. Set ARMHPC_PYTHON to select an existing virtual environment. The supported environment is glibc Linux, including Debian 12 and Ubuntu 22.04 or later.

Device identity, package signatures, active-root protection and persistent tasks are handled by the shared engine. Device tool updates use the separate signed maintenance archive. Corresponding source is in source/; licenses and third-party notices are included in this directory.
''', encoding='utf-8')
    (root / 'README.zh-CN.md').write_text('''# ARMHPC OTA Linux CLI

Linux 上位机，通过 SSH/SFTP 或 USB 串口管理 ARMHPC。包含 x86_64 与 ARM64 的 .NET 运行时。

```sh
./armhpc-ota-cli --version
./armhpc-ota-cli --help
./armhpc-ota-cli status --ssh 192.168.1.20 --username root
./armhpc-ota-cli status --serial /dev/ttyACM0 --username root
./armhpc-ota-cli tools-update --ssh 192.168.1.20 --bundle /path/maintenance.tar.xz --username root
./armhpc-ota-cli upgrade --ssh 192.168.1.20 --package /path/system-ota.tar.xz --bundle /path/maintenance.tar.xz --username root
```

首次连接核对并登记 SSH 指纹；串口需当前用户有设备访问权限。密码在终端输入，或者使用 SSH 私钥。
设备身份、签名、活动根保护和持久任务由原升级引擎处理。Linux 不把登录密码保存为明文；`--remember` 仅用于 Windows DPAPI。

本地系统包解析需要 Python 3.11+ 和 cryptography，例如 Debian/Ubuntu 的 `python3-cryptography`。可用 ARMHPC_PYTHON 指定已有虚拟环境的解释器。运行环境为 glibc Linux，支持 Debian 12 / Ubuntu 22.04 或更新版本。

source/ 包含对应源码；许可与第三方通知位于本目录。设备工具升级使用另行提供的签名 maintenance 文件。
''', encoding='utf-8')
    with source_archive.open('rb') as stream:
        source_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    provenance = {'version': version, 'source_commit': commit, 'source_archive_sha256': source_hash,
                  'architectures': ['x86_64', 'aarch64'],
                  'role': 'Linux management controller', 'device_payload_included': False}
    (root / 'BUILD-INFO.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    output.parent.mkdir(parents=True, exist_ok=True)
    epoch = int(subprocess.check_output(['git', '-C', str(repo), 'show', '-s', '--format=%ct', commit], text=True))
    with output.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch) as gz, tarfile.open(fileobj=gz, mode='w') as archive:
        for p in sorted(root.rglob('*')):
            if not p.is_file():
                continue
            info = archive.gettarinfo(str(p), arcname=root.name + '/' + p.relative_to(root).as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = epoch
            info.mode = 0o755 if p.name in ('armhpc-ota-cli', 'ARMHPC-OTA-CLI') else 0o644
            with p.open('rb') as stream:
                archive.addfile(info, stream)
    return {**provenance, 'sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'bytes': output.stat().st_size}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--source-ref', default='HEAD', help='Committed ref matching the clean checkout HEAD.')
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.work, args.source_ref), indent=2))
