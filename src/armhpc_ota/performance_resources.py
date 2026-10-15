# SPDX-License-Identifier: GPL-3.0-only
"""Preserve performance service enablement and activation across maintenance."""
from pathlib import Path
import subprocess
from .errors import require
from .io import atomic_json, read_json, fsync_dir

UNITS = {'armhpc-performance.service':'multi-user.target.wants',
         'armhpc-performance.timer':'timers.target.wants'}


def enable_link(root, target, unit):
    root=Path(root)
    link=root/'etc/systemd/system'/target/unit
    require(not any(parent.is_symlink() for parent in link.parents if parent!=root and parent.is_relative_to(root)),
            'performance_link','Enable directory is a symbolic link')
    require(not link.exists() or link.is_symlink(),'performance_link','Enable target is not a symbolic link')
    return link


def capture(config, root, backup):
    root, backup = Path(root), Path(backup)
    destination = backup/'performance-service-state.json'
    if destination.exists():
        return
    result = {}
    for unit, target in UNITS.items():
        link = enable_link(root,target,unit)
        active = False
        if not config.simulate and root == Path('/'):
            active = subprocess.run(['systemctl','is-active','--quiet',unit], timeout=5).returncode == 0
        result[unit] = {'link':str(link.readlink()) if link.is_symlink() else None,'active':active}
    atomic_json(destination, result)


def configure(root, backup, rollback=False):
    root = Path(root)
    old = read_json(Path(backup)/'performance-service-state.json')
    for unit, target in UNITS.items():
        link = enable_link(root,target,unit)
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink():
            link.unlink()
        wanted = old[unit]['link'] if rollback else '../'+unit
        if wanted:
            link.symlink_to(wanted)
        fsync_dir(link.parent)


def enable(root):
    root=Path(root)
    require(all((root/'etc/systemd/system'/unit).is_file() for unit in UNITS),
            'performance_resources','Missing signed performance service or timer')
    for unit,target in UNITS.items():
        link=enable_link(root,target,unit)
        link.parent.mkdir(parents=True,exist_ok=True)
        if link.is_symlink():link.unlink()
        link.symlink_to('../'+unit)
        fsync_dir(link.parent)


def activate(config, backup, rollback=False):
    if config.simulate:
        return
    old = read_json(Path(backup)/'performance-service-state.json')
    if rollback:
        for unit in reversed(UNITS):
            result=subprocess.run(['systemctl','stop',unit], timeout=10)
            require(result.returncode in (0,5),'performance_activation','Could not stop the replaced performance unit')
        for unit in UNITS:
            if old[unit]['active']:
                subprocess.run(['systemctl','start',unit], check=True, timeout=15)
    else:
        for unit in UNITS:
            subprocess.run(['systemctl','restart',unit], check=True, timeout=15)
