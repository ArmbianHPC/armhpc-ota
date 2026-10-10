# SPDX-License-Identifier: GPL-3.0-only
"""Only acknowledge independent Rescue fallback after storage/network/SSH are usable."""
import json
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0, '/usr/lib/armhpc-ota')
from armhpc_ota.io import atomic_json
from armhpc_ota.config import Config
from armhpc_ota.engine import Engine
from armhpc_ota.boot import fallback
from armhpc_ota.metadata import verify, validate_manifest
from armhpc_ota.io import atomic_bytes
from armhpc_ota.store import Store

deadline = time.monotonic() + 170
while time.monotonic() < deadline:
    status = subprocess.run(['systemctl', 'is-active', '--quiet', 'ssh.service']).returncode == 0
    addresses = json.loads(subprocess.check_output(['ip', '-j', 'address', 'show', 'scope', 'global']))
    connected = any(a.get('family') == 'inet' for interface in addresses for a in interface.get('addr_info', []))
    guardian = subprocess.run(['systemctl', 'is-active', '--quiet', 'armhpc-ota-watchdog.service']).returncode == 0
    from armhpc_ota.squashfs import boot_context
    context = boot_context()
    needed = context.get('watchdog') or 'armhpc.watchdog=1' in Path('/proc/cmdline').read_text().split()
    if status and connected and (guardian or not needed):
        if context.get('fallback') and context.get('shared_ready'):
            from armhpc_ota.squashfs import read_trailer
            from armhpc_ota.errors import OTAError
            from armhpc_ota.io import sha256
            config = Config.load(); engine = Engine(config); store = engine.store
            from armhpc_ota.device import discover, layout, run
            device = discover(config); storage = layout(config, device, initialized=True)
            slot = context['slot']; partition = storage['partitions']['rescue_' + slot]
            if device['root'] != partition['path']: raise SystemExit('Fallback is not the running Rescue slot')
            manifest, signed = read_trailer(partition['path'], partition['size'], config.trust)
            if manifest['kernels']['rescue'] != device['kernel']: raise SystemExit('Fallback kernel does not match')
            copy = Path(context['lower_mount']) / 'usr/lib/armhpc-ota/boot'
            atomic_bytes(config.state / 'manifests' / (manifest['release'] + '.json'), signed)
            for item in manifest['artifacts']:
                if item['role'] in ('rescue-kernel', 'rescue-initramfs', 'rescue-dtb'):
                    path = copy / item['role'].split('-', 1)[1]
                    if sha256(path) != item['sha256']: raise SystemExit('Fallback boot copy differs')
                    atomic_bytes(config.cache / item['sha256'], path.read_bytes())
            reference = engine.backend.boot_files({'release': manifest['release'], 'manifest': manifest}, 'rescue')
            with store.lock():
                control = store.control(); old_slot = control['confirmed']['rescue']['slot']
                job = store.read()
                if job and control.get('trial'):
                    store.fail(job, OTAError('trial_fallback', 'Verified independent Rescue was selected'))
                    control = store.control()
                control['confirmed']['rescue'] = {'slot': slot, 'boot': reference}
                control['bad_slots'] = [s for s in control.get('bad_slots', []) if s != slot]
                if old_slot != slot: control['bad_slots'] = sorted(set(control['bad_slots'] + [old_slot]))
                control['boot_attempt'] = None
                control['next'] = {'target': 'rescue', 'slot': slot, 'trial': False}
                store.write_control(control)
        if 'armhpc.fallback=1' in Path('/proc/cmdline').read_text().split():
            config = Config.load()
            store = Store(config.state, config.global_writer_lock)
            # A missing/broken shared mount must not turn independent Rescue into emergency mode
            # or make this helper write hidden stale control files on the slot root.
            mount = subprocess.run(['findmnt', '-rn', '--mountpoint', str(config.state), '-o', 'FSTYPE,LABEL'],
                                   text=True, capture_output=True)
            shared_ready = mount.returncode == 0 and mount.stdout.split() == ['ext4', 'OTA_SHARED']
            try:
                control = store.control() if shared_ready else None
            except Exception:
                control = None
            if control:
                slot = next(argument.split('=', 1)[1] for argument in Path('/proc/cmdline').read_text().split() if argument.startswith('armhpc.slot='))
                copy = Path('/usr/lib/armhpc-ota/boot')
                selected, files = fallback(copy / 'manifest.json', copy, config.trust, slot=slot)
                import platform
                if selected['kernel_release'] != platform.release():
                    raise SystemExit('Fallback kernel differs from its independent signed package')
                manifest = validate_manifest(verify((copy / 'manifest.json').read_bytes(), config.trust))
                atomic_bytes(config.state / 'manifests' / (manifest['release'] + '.json'), (copy / 'manifest.json').read_bytes())
                for item in manifest['artifacts']:
                    if item['role'] in ('rescue-kernel', 'rescue-initramfs', 'rescue-dtb'):
                        name = item['role'].split('-', 1)[1]
                        atomic_bytes(config.cache / item['sha256'], files[name].read_bytes())
                engine = Engine(config)
                reference = engine.backend.boot_files({'release': manifest['release'], 'manifest': manifest}, 'rescue')
                with store.lock():
                    control = store.control()
                    control['confirmed']['rescue'] = {'slot': slot, 'boot': reference}
                    control['boot_attempt'] = None
                    control['bad_slots'] = [old for old in control.get('bad_slots', []) if old != slot]
                    control['next'] = {'target': 'rescue', 'slot': slot, 'trial': False}
                    store.write_control(control)
        marker = Path('/var/lib/armhpc/fallback-trial.json')
        if marker.exists():
            atomic_json(marker, {'attempted': False, 'healthy': True})
        Path('/run/armhpc-ota-healthy').touch()
        raise SystemExit(0)
    time.sleep(2)
raise SystemExit(1)
