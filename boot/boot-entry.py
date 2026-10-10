# SPDX-License-Identifier: GPL-3.0-only
"""Runs only inside the fixed bootstrap initramfs, before mounting the final root."""
import os
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0, '/usr/lib/armhpc-ota')
from armhpc_ota.boot import select, verify_boot, fallback
from armhpc_ota.config import Config
from armhpc_ota.device import run
from armhpc_ota.io import read_json, atomic_json
from armhpc_ota.errors import require


def partition(label):
    for attempt in range(15):
        result = subprocess.run(['blkid', '-t', 'LABEL=' + label, '-o', 'device'], text=True, capture_output=True)
        devices = result.stdout.strip().splitlines()
        require(len(devices) <= 1, 'label_duplicate', 'Duplicate bootstrap partition label')
        if devices:
            return devices[0]
        time.sleep(1)
    raise RuntimeError('Missing ' + label)


def mount(path, destination, writable=False):
    destination.mkdir(parents=True, exist_ok=True)
    run('mount', '-t', 'ext4', '-o', 'rw' if writable else 'ro,noload', path, destination)


def load(selected, files, root_device, fallback_boot=False):
    root_uuid = run('blkid', '-s', 'PARTUUID', '-o', 'value', root_device)
    arguments = ['root=PARTUUID=' + root_uuid, 'rootfstype=ext4', 'rw', 'rootwait', 'net.ifnames=0',
                 'console=ttyS2,1500000', 'console=tty1', 'systemd.unified_cgroup_hierarchy=1',
                 'armhpc.target=' + selected['target'], 'armhpc.watchdog=1',
                 'watchdog.open_timeout=180', 'watchdog.stop_on_reboot=0', 'dw_wdt.nowayout=1']
    if selected.get('task'):
        arguments.append('armhpc.task=' + selected['task'])
    if selected.get('slot'):
        arguments.append('armhpc.slot=' + selected['slot'])
    if fallback_boot:
        arguments.append('armhpc.fallback=1')
    # sysboot passes a raw initramfs; kexec must also receive its unchanged bytes.
    run('kexec', '-l', files['kernel'], '--initrd=' + str(files['initramfs']),
        '--dtb=' + str(files['dtb']), '--append=' + ' '.join(arguments))
    run('sync')
    # Each filesystem is cleanly unmounted before SATA/eMMC drivers are handed to the target kernel.
    for location in ('/run/ota-shared', '/run/ota-fallback'):
        subprocess.run(['umount', location], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.execv('/usr/lib/armhpc-ota/watchdog-guard', ['watchdog-guard', '--kexec', '/dev/watchdog0', '60'])


def root_files_ready(root, kernel):
    """Check absolute symlinks in the target namespace, not in the fixed initramfs."""
    child = os.fork()
    if child == 0:
        try:
            os.chroot(root)
            os.chdir('/')
            ready = (Path('/sbin/init').is_file() and os.access('/sbin/init', os.X_OK) and
                     (Path('/lib/modules') / kernel).is_dir())
            os._exit(0 if ready else 1)
        except BaseException:
            os._exit(2)
    _, status = os.waitpid(child, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def probe(selected, device):
    root = Path('/run/ota-probe')
    mount(device, root)
    try:
        expected = selected['boot']
        marker = read_json(root / 'etc/armhpc/release.json')
        require(marker.get('release') == expected['release'] and marker.get('target') == selected['target'],
                'root_version', 'Selected root is a partial or mismatched deployment')
        require(root_files_ready(root, expected['kernel_release']),
                'root_modules', 'Selected root has no matching init or modules')
    finally:
        run('umount', root)


def main():
    config = Config(state=Path('/run/ota-shared'), trust=Path('/etc/armhpc/ota-trust.d'))
    labels = config.board()['labels']
    bad_slots = []
    try:
        mount(partition(labels['shared']), config.state, writable=True)
        selected = select(config)
        files = verify_boot(config, selected)
        root_label = labels['system'] if selected['target'] == 'system' else labels['rescue_' + selected['slot']]
        root_device = partition(root_label)
        probe(selected, root_device)
        load(selected, files, root_device)
    except Exception as error:
        print('ARMHPC bootstrap selected independent Rescue: ' + str(error), file=sys.stderr)
        try:
            bad_slots = read_json(config.state / 'control.json').get('bad_slots', [])
        except Exception:
            pass
        subprocess.run(['umount', '/run/ota-shared'], capture_output=True)
    for slot in ('a', 'b'):
        if slot in bad_slots:
            continue
        root = Path('/run/ota-fallback')
        try:
            device = partition(labels['rescue_' + slot])
            mount(device, root, writable=True)
            marker = root / 'var/lib/armhpc/fallback-trial.json'
            require(not marker.exists() or not read_json(marker).get('attempted'), 'fallback_failed',
                    'This independent Rescue already failed its last boot trial')
            copy = root / 'usr/lib/armhpc-ota/boot'
            selected, files = fallback(copy / 'manifest.json', copy, config.trust, slot=slot)
            require(root_files_ready(root, selected['kernel_release']),
                    'fallback_root', 'Independent Rescue root/modules are missing')
            atomic_json(marker, {'attempted': True, 'healthy': False})
            load(selected, files, device, fallback_boot=True)
        except Exception as error:
            print('ARMHPC Rescue ' + slot + ' unavailable: ' + str(error), file=sys.stderr)
            subprocess.run(['umount', '/run/ota-fallback'], capture_output=True)
    raise RuntimeError('No verified Rescue target is available; remain in the bootstrap console')


if __name__ == '__main__':
    main()
