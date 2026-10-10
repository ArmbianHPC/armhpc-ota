# SPDX-License-Identifier: GPL-3.0-only
"""Install shared source into an offline root, without duplicating it in the framework."""
import argparse
from pathlib import Path
import shutil
import os
import sys
import datetime
import runpy

parser = argparse.ArgumentParser()
parser.add_argument('--root', required=True, help='Offline staging root, never /')
parser.add_argument('--watchdog-binary', help='Target-architecture compiled watchdog-guard')
parser.add_argument('--bootstrap-hooks', action='store_true')
parser.add_argument('--live', action='store_true', help='Explicitly install agent source into the running Linux root')
parser.add_argument('--yes', action='store_true')
parser.add_argument('--framework-source', help='Matching armbian-hpc checkout; required for a live install of the public bridges')
args = parser.parse_args()
root = Path(args.root).resolve()
live = root == Path('/')
if live and not (args.live and args.yes and os.name != 'nt' and os.geteuid() == 0 and args.framework_source and args.watchdog_binary):
    parser.error('A live install requires Linux root, --live --yes, --framework-source and a target watchdog helper')
if not live and (root == Path(root.anchor) or not (root / 'etc').is_dir()):
    parser.error('Specify an existing offline root')
project = Path(__file__).resolve().parent.parent
if live:
    framework = Path(args.framework_source).resolve()
    if not (framework / 'components/common/rootfs-overlay/usr/lib/armhpc/cli.py').is_file():
        parser.error('Missing the matching public command bridges')
    backup = Path('/var/backups') / ('armhpc-ota-runtime-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    backup.mkdir(mode=0o700, parents=True)
    for relative in ('usr/lib/armhpc', 'usr/lib/armhpc-ota', 'usr/local/sbin/armhpc', 'usr/local/sbin/armhpc-rescue', 'usr/local/sbin/armhpc-kube',
                     'etc/profile.d/armhpc-configuration.sh'):
        existing = root / relative
        if existing.is_dir():
            shutil.copytree(existing, backup / relative, symlinks=True)
        elif existing.exists():
            target = backup / relative; target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(existing, target)
    rescue = (root / 'etc/armhpc/rescue-environment').exists()
    overlays = [framework / 'components/common/rootfs-overlay',
                framework / ('components/rescue/rootfs-overlay' if rescue else 'components/k3s/rootfs-overlay'),
                framework / 'adapters/boards/wxy-oect-original/rootfs-overlay']
    for overlay in overlays:
        library = overlay / 'usr/lib/armhpc'
        if library.exists():
            shutil.copytree(library, root / 'usr/lib/armhpc', dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for command in (overlay / 'usr/local/sbin').glob('armhpc*'):
            if command.name in ('armhpc', 'armhpc-rescue', 'armhpc-kube'):
                shutil.copy2(command, root / 'usr/local/sbin' / command.name)
                (root / 'usr/local/sbin' / command.name).chmod(0o755)
    runpy.run_path(str(root / 'usr/lib/armhpc/command_layout.py'))['finalize'](root, 'rescue' if rescue else 'normal')
    profile = framework / 'components/common/rootfs-overlay/etc/profile.d/armhpc-configuration.sh'
    if profile.is_file(): shutil.copy2(profile, root / 'etc/profile.d/armhpc-configuration.sh')
destination = root / 'usr/lib/armhpc-ota'
shutil.copytree(project / 'src/armhpc_ota', destination / 'armhpc_ota', dirs_exist_ok=True,
                ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
shutil.copytree(project / 'packaging', destination / 'resources', dirs_exist_ok=True)
for service in (project / 'packaging').glob('*.service'):
    target = root / 'etc/systemd/system' / service.name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(service, target)
    wanted = root / 'etc/systemd/system' / ('sysinit.target.wants' if 'watchdog' in service.name else 'multi-user.target.wants')
    wanted.mkdir(parents=True, exist_ok=True)
    link = wanted / service.name
    if not link.exists():
        link.symlink_to('../' + service.name)
shutil.copy2(project / 'packaging/fallback-health.py', destination / 'fallback-health.py')
shutil.copy2(project / 'boot/boot-entry.py', destination / 'boot-entry.py')
shutil.copy2(project / 'boot/squashfs-boot.py', destination / 'squashfs-boot.py')
shutil.copy2(project / 'boot/initramfs-armhpc', destination / 'resources/initramfs-armhpc')
if args.watchdog_binary:
    shutil.copy2(args.watchdog_binary, destination / 'watchdog-guard')
    os.chmod(destination / 'watchdog-guard', 0o755)
# DrvFS checkouts may expose mode 0777. Runtime code is never writable by other users.
for path in destination.rglob('*'):
    if path.is_symlink(): continue
    path.chmod(0o755 if path.is_dir() or path.name == 'watchdog-guard' else 0o644)
for service in (root / 'etc/systemd/system').glob('armhpc-ota-*.service'): service.chmod(0o644)
if args.bootstrap_hooks:
    for source, target in [('initramfs-hook', 'etc/initramfs-tools/hooks/armhpc-ota-anchor'),
                           ('initramfs-local-top', 'etc/initramfs-tools/scripts/local-top/armhpc-ota-anchor')]:
        path = root / target; path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(project / 'boot' / source, path); os.chmod(path, 0o755)
if live:
    import subprocess
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    print('Agent/code bridges installed; no partition, BOOT file, reboot or workload was changed. Backup: ' + str(backup))
print('Installed the single OTA runtime into ' + str(root))
