# SPDX-License-Identifier: GPL-3.0-only
"""Back up, enable and restore node-foundation units during signed maintenance."""
from pathlib import Path
import subprocess
from .errors import require
from .io import atomic_json, read_json, fsync_dir
from .performance_resources import enable_link

UNITS = {'armhpc-state.service':'multi-user.target.wants',
         'armhpc-firewall.service':'multi-user.target.wants',
         'armhpc-runtime.service':'multi-user.target.wants',
         'armhpc-swap.service':'multi-user.target.wants',
         'armhpc-auth-recovery.service':'multi-user.target.wants',
         'armhpc-management-ready.service':'network-online.target.wants',
         'armhpc-health.timer':'timers.target.wants'}
WAIT = 'systemd-networkd-wait-online.service'


def selected(root):
    rescue = (Path(root)/'etc/armhpc/rescue-environment').is_file()
    return {unit: target for unit, target in UNITS.items()
            if not rescue or unit in ('armhpc-management-ready.service','armhpc-health.timer')}


def capture(config, root, backup):
    path = Path(backup)/'node-service-state.json'
    if path.exists():return
    saved = {}
    for unit, target in {**UNITS,WAIT:'network-online.target.wants'}.items():
        link=enable_link(root,target,unit)
        active = not config.simulate and Path(root)==Path('/') and subprocess.run(
            ['systemctl','is-active','--quiet',unit],timeout=5).returncode==0
        saved[unit]={'target':target,'link':str(link.readlink()) if link.is_symlink() else None,'active':active}
    atomic_json(path,saved)


def configure(root, backup=None, rollback=False):
    root=Path(root)
    saved=read_json(Path(backup)/'node-service-state.json') if backup else {}
    for unit,target in {**UNITS,WAIT:'network-online.target.wants'}.items():
        link=enable_link(root,target,unit)
        wanted=saved[unit]['link'] if rollback else '../'+unit if unit in selected(root) else None
        if wanted:
            require(rollback or (root/'etc/systemd/system'/unit).is_file(), 'node_resources', 'Missing signed node service: '+unit)
            link.parent.mkdir(parents=True,exist_ok=True)
        if link.is_symlink():link.unlink()
        if wanted:link.symlink_to(wanted)
        if link.parent.is_dir():fsync_dir(link.parent)


def activate(config, backup, rollback=False):
    if config.simulate:return
    if rollback:
        saved=read_json(Path(backup)/'node-service-state.json')
        for unit in reversed(UNITS):
            subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=10)
        for unit,item in saved.items():
            if item['active']:subprocess.run(['systemctl','start',unit],check=True,timeout=15)
    else:
        subprocess.run(['systemctl','restart','armhpc-health.timer'],check=True,timeout=10)
