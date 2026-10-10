# SPDX-License-Identifier: GPL-3.0-only
"""Bounded boot-stage snapshots, without credentials or network configuration."""
import json
import os
from pathlib import Path
import time
from .io import atomic_json, read_json
from .watchdog import boot_id, command, read, reset_registers


def shared_verified(config):
    if config.simulate: return False
    try:
        from .device import discover,layout,run
        device=discover(config);storage=layout(config,device,initialized=True)
        mounted=json.loads(run('findmnt','--json','--mountpoint',config.state,'-o','SOURCE,FSTYPE,LABEL'))['filesystems'][0]
        return mounted.get('fstype')=='ext4' and mounted.get('label')=='OTA_SHARED' and str(Path(mounted['source']).resolve())==storage['partitions']['shared']['path']
    except Exception: return False


def sample(config):
    stages = {'kernel_started': True,
              'shared_mounted': shared_verified(config),
              'root_selected': Path('/run/armhpc/ota-boot.json').is_file(),
              'usb_gadget': Path('/dev/ttyGS0').exists(),
              'ethernet_registered': Path('/sys/class/net/eth0').exists(),
              'link': read('/sys/class/net/eth0/carrier') == '1',
              'ssh': command('systemctl', 'is-active', 'ssh.service')['output'] == 'active'}
    n = command('ip', '-j', 'address', 'show', 'dev', 'eth0')
    try: stages['ipv4_ready'] = any(a['family'] == 'inet' for a in json.loads(n['output'])[0]['addr_info'])
    except (ValueError, KeyError, IndexError): stages['ipv4_ready'] = False
    r = {'boot_id': boot_id(), 'monotonic_seconds': time.monotonic(), 'kernel': os.uname().release,
         'early_stages':read_json('/run/armhpc/boot-stages.json') if Path('/run/armhpc/boot-stages.json').is_file() else None,
         'stages': stages, 'root': read_json('/run/armhpc/ota-boot.json') if stages['root_selected'] else None,
         'watchdog': {k: read('/sys/class/watchdog/watchdog0/' + k) for k in ('state','timeout','timeleft','bootstatus','nowayout')},
         'reset_registers': reset_registers(), 'phy': {'id': read('/sys/class/net/eth0/phydev/phy_id'),
                                                      'speed': read('/sys/class/net/eth0/speed')}}
    directory = config.state / 'watchdog/boots'
    # Do not create a hidden shared record if OTA_SHARED did not mount.
    if shared_verified(config):
        f = directory / (r['boot_id'] + '.json')
        old = read_json(f) if f.exists() else {'boot_id': r['boot_id'], 'samples': []}
        old['samples'].append(r); old['samples'] = old['samples'][-4:]
        atomic_json(f, old)
        for file in sorted(directory.glob('*.json'), key=lambda p:p.stat().st_mtime, reverse=True)[12:]:
            file.unlink(missing_ok=True)
    atomic_json('/run/armhpc/watchdog-boot-diagnostics.json', r)
    return r


def main():
    from .config import Config
    c = Config.load()
    for delay in (0, 15, 30):
        if delay: time.sleep(delay)
        sample(c)


if __name__ == '__main__': main()
