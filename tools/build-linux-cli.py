# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Package the shared .NET controller for Linux x86_64 and ARM64."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
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


def build(output, work, source_ref='HEAD'):
    repo = Path(__file__).resolve().parents[1]
    output, work = Path(output).resolve(), Path(work).resolve()
    version = (repo / 'VERSION').read_text(encoding='utf-8').strip()
    if output.exists():
        raise ValueError('Linux package already exists')
    if any((p / '.git').exists() for d in (output.parent, work) for p in (d, *d.parents)):
        raise ValueError('Build outside repositories')
    root = work / ('armhpc-ota-cli-' + version)
    root.mkdir(parents=True)
    project = repo / 'windows/ArmHpc.Ota.Cli/ArmHpc.Ota.Cli.csproj'
    for rid in ('linux-x64', 'linux-arm64'):
        dest = root / 'runtimes' / rid
        with (work / (rid + '.log')).open('w', encoding='utf-8') as log:
            subprocess.run(['dotnet', 'publish', str(project), '-c', 'Release', '-f', 'net10.0', '-r', rid,
                            '--self-contained', 'true', '-p:InvariantGlobalization=true',
                            '-o', str(dest)],
                           cwd=repo, stdout=log, stderr=subprocess.STDOUT, check=True)
        for p in dest.glob('*.pdb'):
            p.unlink()
        library = dest / 'publisher/Lib/armhpc_ota'
        shutil.copytree(repo / 'src/armhpc_ota', library,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
        (dest / 'ARMHPC-OTA-CLI').chmod(0o755)
        print('Published ' + rid, flush=True)
    (root / 'armhpc-ota-cli').write_text(LAUNCHER, encoding='utf-8', newline='\n')
    (root / 'armhpc-ota-cli').chmod(0o755)
    for name in ('LICENSE', 'COPYRIGHT', 'THIRD-PARTY-NOTICES.md'):
        shutil.copy2(repo / name, root / name)
    shutil.copytree(repo / 'LICENSES', root / 'LICENSES')
    source = root / 'source'
    source.mkdir()
    with (source / 'armhpc-ota-source.tar').open('wb') as stream:
        subprocess.run(['git', '-C', str(repo), 'archive', '--format=tar', source_ref], stdout=stream, check=True)
    commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', source_ref], text=True).strip()
    shutil.copy2(repo / 'DEPENDENCIES.lock.json', root / 'DEPENDENCIES.lock.json')
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
    provenance = {'version': version, 'source_commit': commit, 'architectures': ['x86_64', 'aarch64'],
                  'role': 'Linux management controller', 'device_payload_included': False}
    (root / 'BUILD-INFO.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    output.parent.mkdir(parents=True, exist_ok=True)
    epoch = int(subprocess.check_output(['git', '-C', str(repo), 'show', '-s', '--format=%ct', source_ref], text=True))
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
    parser.add_argument('--source-ref', default='HEAD')
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.work, args.source_ref), indent=2))
