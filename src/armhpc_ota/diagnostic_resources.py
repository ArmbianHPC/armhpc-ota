# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
from .io import atomic_json, read_json
from .errors import require

UNITS = ('armhpc-ota-boot-diagnostics.service', 'armhpc-ota-boot-maintenance.service')


def configure(root, backup=None, rollback=False):
    directory=Path(root)/'etc/systemd/system'
    saved=Path(backup)/'diagnostic-links.json' if backup else None
    if saved and not saved.exists() and not rollback:
        inventory={}
        for name in UNITS:
            p=directory/'multi-user.target.wants'/name
            require(not p.exists() or p.is_symlink(),'unit_link','Unexpected regular enable file')
            inventory[name]=str(p.readlink()) if p.is_symlink() else None
        atomic_json(saved,inventory)
    inventory=read_json(saved) if rollback and saved and saved.exists() else {}
    for name in UNITS:
        p=directory/'multi-user.target.wants'/name
        p.parent.mkdir(parents=True,exist_ok=True)
        require(not p.exists() or p.is_symlink(),'unit_link','Unsafe unit enable link')
        if p.is_symlink():p.unlink()
        target=inventory.get(name) if rollback else '../'+name
        if target:p.symlink_to(target)


def capture_active(config,root,backup):
    import subprocess
    path=Path(backup)/'diagnostic-active.json'
    if not config.simulate and Path(root)==Path('/') and not path.exists():
        atomic_json(path,{name:subprocess.run(['systemctl','is-active','--quiet',name],timeout=3).returncode==0 for name in UNITS})


def activate(config,backup,rollback=False):
    if config.simulate: return
    from .device import run
    from .clock_resources import stop_loaded
    if rollback:
        old=read_json(Path(backup)/'diagnostic-active.json') if (Path(backup)/'diagnostic-active.json').exists() else {}
        # Never replay a persisted BOOT write merely to restore service state.
        stop_loaded('armhpc-ota-boot-maintenance.service')
        if old.get('armhpc-ota-boot-diagnostics.service'):run('systemctl','start','--no-block','armhpc-ota-boot-diagnostics.service')
        else:stop_loaded('armhpc-ota-boot-diagnostics.service')
    else:run('systemctl','start','--no-block','armhpc-ota-boot-diagnostics.service')
