# SPDX-License-Identifier: GPL-3.0-only
"""Bootstrap selector: persist a one-shot trial before kexec and fail closed."""
import os
from pathlib import Path
from .errors import OTAError, require
from .io import sha256, inside, atomic_json
from .store import Store, TERMINAL


def select(config):
    store = Store(config.state, config.global_writer_lock)
    with store.lock():
        control = store.control()
        require(control.get('anchor_abi') == config.board()['anchor_abi'], 'anchor', 'Unsupported boot control ABI')
        trial = control.get('trial')
        if trial:
            job = store.read(trial['task'])
            require(job is not None, 'trial_job', 'Trial job is missing')
            if trial['target'] + '-health-passed' in job['checkpoints']:
                control['confirmed'][trial['target']] = trial['candidate']
                control['trial'] = None
                if trial['target'] == 'system':
                    control['system_blocked'] = False
                store.write_control(control)
            elif trial['attempted'] or job['stage'] in TERMINAL:
                # A reset before confirmation is a failed trial. Do not repeatedly boot it.
                store.fail(job, OTAError('trial_failed', 'Trial rebooted without health confirmation'))
                control = store.control()
            else:
                require(job['stage'] == 'trial-' + trial['target'], 'trial_state', 'Job is not ready for its boot trial')
                trial['attempted'] = True
                store.write_control(control)
                return {'target': trial['target'], 'slot': trial['candidate'].get('slot'),
                        'task': trial['task'], 'boot': trial['candidate']['boot'], 'trial': True}
        previous = control.get('boot_attempt')
        if previous and previous.get('pending'):
            control['boot_attempt'] = None
            if previous['target'] == 'system':
                control['system_blocked'] = True
                control['next'] = {'target': 'rescue', 'slot': control['confirmed']['rescue']['slot']}
                store.write_control(control)
            else:
                control['bad_slots'] = sorted(set(control.get('bad_slots', []) + [previous['slot']]))
                store.write_control(control)
                raise OTAError('confirmed_rescue_failed', 'Confirmed Rescue reset before health; use the independent alternate slot')
        target = control.get('next', {}).get('target', 'rescue')
        if target == 'system' and (control.get('system_blocked') or not control['confirmed'].get('system')):
            target = 'rescue'
        candidate = control['confirmed'][target]
        require(candidate.get('boot'), 'boot_missing', 'Confirmed target has no boot files')
        require(target != 'rescue' or candidate['slot'] not in control.get('bad_slots', []),
                'confirmed_rescue_failed', 'Confirmed Rescue is marked unhealthy; use the independent alternate slot')
        if control.get('next', {}).get('once'):
            control['next'] = {'target': 'system' if control['confirmed'].get('system') and not control.get('system_blocked') else 'rescue',
                               'slot': control['confirmed']['rescue']['slot'], 'trial': False}
            store.write_control(control)
        if control.get('monitor_confirmed_boots'):
            control['boot_attempt'] = {'target': target, 'slot': candidate.get('slot'), 'pending': True}
            store.write_control(control)
        return {'target': target, 'slot': candidate.get('slot'), 'task': None, 'boot': candidate['boot'], 'trial': False}


def verify_boot(config, selected):
    from .metadata import verify, validate_manifest
    manifest = validate_manifest(verify((config.state / 'manifests' / (selected['boot']['release'] + '.json')).read_bytes(), config.trust))
    require(manifest['board'] == config.profile and manifest['architecture'] == config.board()['architecture'],
            'boot_board', 'Selected boot package belongs to a different board')
    require(selected['boot']['kernel_release'] == manifest['kernels'][selected['target']],
            'boot_pairing', 'Kernel version reference differs from the signed manifest')
    result = {}
    for name in ('kernel', 'initramfs', 'dtb'):
        reference = selected['boot'][name]
        signed = next(item for item in manifest['artifacts'] if item['role'] == selected['target'] + '-' + name)
        require(reference['sha256'] == signed['sha256'], 'boot_manifest', 'Boot reference differs from the signed manifest')
        path = inside(config.state, reference['path'])
        require(path.is_file() and sha256(path) == reference['sha256'], 'boot_hash', 'Boot file failed verification', file=name)
        if name == 'initramfs':
            with path.open('rb') as source:
                require(source.read(4) != bytes.fromhex('27051956'), 'raw_initramfs', 'Expected raw initramfs')
        result[name] = path
    return result


def fallback(manifest_path, root, trust, target='rescue', slot='a', board=None):
    """A slot-local signed boot copy does not depend on readable shared control."""
    from .metadata import verify, validate_manifest
    manifest = validate_manifest(verify(Path(manifest_path).read_bytes(), trust))
    expected = board or {'id':'wxy-oect-original','architecture':'arm64'}
    require(manifest['board'] == expected['id'] and manifest['architecture'] == expected['architecture'],
            'fallback_board', 'Fallback belongs to a different board')
    result = {}
    for name in ('kernel', 'initramfs', 'dtb'):
        item = next(item for item in manifest['artifacts'] if item['role'] == target + '-' + name)
        path = Path(root) / name
        require(path.is_file() and sha256(path) == item['sha256'], 'fallback_hash', 'Independent Rescue boot copy is damaged')
        result[name] = path
    return {'target': target, 'slot': slot, 'task': None, 'trial': False,
            'kernel_release': manifest['kernels'][target]}, result
