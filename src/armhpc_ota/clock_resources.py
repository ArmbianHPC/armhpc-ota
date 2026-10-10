# SPDX-License-Identifier: GPL-3.0-only
"""Allowlisted clock resources, enable-link rollback and active service state."""
from pathlib import Path
import subprocess
from .errors import require
from .io import atomic_json, read_json, atomic_bytes

UNITS = ('armhpc-clock-floor.service', 'armhpc-clock-checkpoint.service',
         'armhpc-clock-checkpoint.timer', 'armhpc-clock-shutdown.service')
LINKS = {'multi-user.target.wants/armhpc-clock-floor.service': '../armhpc-clock-floor.service',
         'timers.target.wants/armhpc-clock-checkpoint.timer': '../armhpc-clock-checkpoint.timer',
         'multi-user.target.wants/armhpc-clock-shutdown.service': '../armhpc-clock-shutdown.service'}
ACTIVE = ('armhpc-clock-floor.service', 'armhpc-clock-checkpoint.timer', 'armhpc-clock-shutdown.service')


def files(payload):
    directory = Path(payload) / 'compat/clock-services'
    if not directory.is_dir(): return {}
    names = {unit: 'etc/systemd/system/' + unit for unit in UNITS}
    names['firstboot-clock.conf'] = 'etc/systemd/system/armhpc-firstboot.service.d/20-armhpc-clock.conf'
    require(all((directory / name).is_file() for name in names), 'clock_resources', 'Maintenance bundle is missing clock services')
    return {target: directory / name for name, target in names.items()}


def configure_links(root, backup=None, rollback=False):
    directory = Path(root) / 'etc/systemd/system'
    directory.mkdir(parents=True, exist_ok=True)
    inventory = Path(backup) / 'clock-links.json' if backup else None
    if inventory and not inventory.exists():
        entries = {}
        for relative in LINKS:
            link = directory / relative
            require(not link.exists() or link.is_symlink() or link.is_file(), 'clock_link', 'Invalid clock enable link')
            entries[relative] = {'kind': 'symlink', 'target': str(link.readlink())} if link.is_symlink() else (
                {'kind': 'file', 'content': link.read_text(), 'mode': link.stat().st_mode & 0o777} if link.is_file() else {'kind': 'absent'})
        atomic_json(inventory, entries)
    entries = read_json(inventory) if rollback and inventory and inventory.exists() else {}
    for relative, destination in LINKS.items():
        link = directory / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        old = entries.get(relative, {'kind': 'absent'})
        wanted = old.get('target') if rollback else destination
        if wanted and link.is_symlink() and str(link.readlink()) == wanted: continue
        link.unlink(missing_ok=True)
        if rollback and old['kind'] == 'file': atomic_bytes(link, old['content'].encode(), old['mode'])
        elif wanted: link.symlink_to(wanted)


def capture_active(config, root, backup):
    path = Path(backup) / 'clock-active.json'
    if not config.simulate and Path(root) == Path('/') and not path.exists():
        atomic_json(path, {name: subprocess.run(['systemctl', 'is-active', '--quiet', name], timeout=3).returncode == 0 for name in ACTIVE})


def stop_loaded(name):
    loaded = subprocess.run(['systemctl', 'show', '--property=LoadState', '--value', name], text=True, capture_output=True, timeout=3)
    if loaded.stdout.strip() in ('', 'not-found'): return
    result = subprocess.run(['systemctl', 'stop', name], timeout=15)
    if result.returncode:
        state = subprocess.run(['systemctl', 'show', '--property=ActiveState', '--value', name], text=True, capture_output=True, timeout=3)
        require(state.stdout.strip() in ('inactive', 'failed'), 'clock_service_stop', 'Clock service did not stop before rollback')


def prepare_rollback(config, root):
    if not config.simulate and Path(root) == Path('/'):
        for name in ('armhpc-clock-checkpoint.timer', 'armhpc-clock-checkpoint.service', 'armhpc-clock-shutdown.service'):
            stop_loaded(name)


def activate(config, backup, rollback=False):
    if config.simulate: return
    subprocess.run(['systemctl', 'daemon-reload'], check=True, timeout=10)
    if rollback:
        old = read_json(Path(backup) / 'clock-active.json') if (Path(backup) / 'clock-active.json').is_file() else {}
        for name in ACTIVE:
            if old.get(name):
                subprocess.run(['systemctl', 'restart', name], check=True, timeout=15)
            else:
                stop_loaded(name)
    else:
        subprocess.run(['systemctl', 'restart', 'armhpc-clock-floor.service'], check=True, timeout=15)
        subprocess.run(['systemctl', 'restart', 'armhpc-clock-checkpoint.timer', 'armhpc-clock-shutdown.service'], check=True, timeout=15)
        subprocess.run(['systemctl', 'start', 'armhpc-clock-checkpoint.service'], check=True, timeout=15)
