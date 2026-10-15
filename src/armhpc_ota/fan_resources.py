# SPDX-License-Identifier: GPL-3.0-only
"""Fan service link and running-state preservation during signed maintenance."""
from pathlib import Path
import subprocess
from .errors import require
from .io import atomic_json,read_json

RELATIVE='etc/systemd/system/multi-user.target.wants/armhpc-fan.service'

def capture(config,root,backup):
    root=Path(root);backup=Path(backup);path=backup/'fan-service-state.json'
    if path.exists():return
    link=root/RELATIVE
    require(not link.exists() or link.is_symlink(),'fan_link','Fan enable link is not a symbolic link')
    value={'link':str(link.readlink()) if link.is_symlink() else None,'active':False}
    if not config.simulate and root==Path('/'):
        value['active']=subprocess.run(['systemctl','is-active','--quiet','armhpc-fan.service'],timeout=5).returncode==0
    atomic_json(path,value)

def configure(root,backup,rollback=False):
    root=Path(root);link=root/RELATIVE
    old=read_json(Path(backup)/'fan-service-state.json')
    policy=root/'etc/armhpc/fan.json'
    wanted=old['link'] if rollback else '../armhpc-fan.service' if policy.is_file() and read_json(policy).get('enabled') else old['link']
    link.parent.mkdir(parents=True,exist_ok=True)
    require(not link.exists() or link.is_symlink(),'fan_link','Fan enable target is not a symbolic link')
    if link.is_symlink():link.unlink()
    if wanted:link.symlink_to(wanted)

def activate(config,backup,rollback=False):
    if config.simulate:return
    old=read_json(Path(backup)/'fan-service-state.json')
    policy=Path('/etc/armhpc/fan.json')
    active=old['active'] if rollback else policy.is_file() and read_json(policy).get('enabled',False)
    if not active and not Path('/etc/systemd/system/armhpc-fan.service').exists():return
    subprocess.run(['systemctl','restart' if active else 'stop','armhpc-fan.service'],check=True,timeout=15)
