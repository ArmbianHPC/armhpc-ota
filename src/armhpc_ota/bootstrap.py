# SPDX-License-Identifier: GPL-3.0-only
"""Append-only eMMC migration, with the legacy boot entry kept until cutover."""
import hashlib
import os
from pathlib import Path
import shutil
import uuid
from .backend import Backend
from .device import discover, layout, check_gate, run
from .errors import require, OTAError
from .io import atomic_json, atomic_bytes, read_json, sha256, parse_json
from .metadata import verify, valid_sha, anchor_digest
from .store import Store


def align(value, sectors=2048):
    return ((value + sectors - 1) // sectors) * sectors


def disk_partitions(config, path):
    if config.simulate:
        return []
    table = parse_json(run('sfdisk', '--json', path).encode())['partitiontable']
    require(table['label'] == 'gpt' and table['unit'] == 'sectors' and table['sectorsize'] == 512,
            'gpt', 'OECT migration requires a 512-byte GPT disk')
    return table['partitions']


def preview(config):
    device = discover(config)
    storage = layout(config, device)
    if storage['board'].get('rescue_fstype') == 'squashfs':
        layout(config, device, initialized=True)
        return {'device_id': device['device_id'], 'complete': bool((config.state / 'bootstrap.json').exists() and read_json(config.state / 'bootstrap.json').get('complete')),
                'factory_prepartitioned': True, 'append': [], 'system_partition_table_changed': False, 'reboot_required': False}
    board, emmc = storage['board'], storage['emmc']
    a = storage['partitions']['rescue_a']
    b_start = align(a['start'] + a['size'] // board['sector_size'])
    b_end = b_start + board['rescue_a_sectors'] - 1
    shared_start = align(b_end + 1)
    shared_end = emmc['size'] // board['sector_size'] - 34
    require(shared_end - shared_start >= 512 * 1024 * 1024 // board['sector_size'],
            'bootstrap_space', 'No room for equal-size Rescue B and a shared ext4 partition')
    planned = [{'number': 3, 'start': b_start, 'end': b_end, 'label': board['labels']['rescue_b']},
               {'number': 4, 'start': shared_start, 'end': shared_end, 'label': board['labels']['shared']}]
    journal = read_json(config.state / 'bootstrap.json') if (config.state / 'bootstrap.json').exists() else {}
    if journal:
        require(journal.get('device_id') == device['device_id'], 'bootstrap_identity', 'Migration journal belongs to another device')
    known_guids = journal.get('partition_guids', {})
    on_disk = disk_partitions(config, emmc['path'])
    for number, item in enumerate(on_disk, start=1):
        if number <= 2:
            expected = storage['partitions']['boot' if number == 1 else 'rescue_a']
            require(item['start'] == expected['start'] and item['size'] * 512 == expected['size'] and
                    item['uuid'].lower() == expected['partuuid'].lower(), 'gpt_geometry', 'On-disk GPT differs from the mounted legacy partitions')
        else:
            expected = next((part for part in planned if part['number'] == number), None)
            known = known_guids.get(str(number))
            existing = storage['partitions']['rescue_b' if number == 3 else 'shared'] if number in (3, 4) else None
            require(expected and item['start'] == expected['start'] and item['size'] == expected['end'] - expected['start'] + 1 and
                    (item['uuid'].lower() == (known or '').lower() or (existing and item['uuid'].lower() == existing['partuuid'].lower())),
                    'foreign_partition', 'Unknown or mismatched on-disk GPT partition')
    original_parts = [node for node in device['blocks'] if node.get('parent') == emmc['path']]
    require(all(node['label'] in board['labels'].values() or node.get('partuuid') in known_guids.values() for node in original_parts), 'foreign_partition',
            'Unexpected eMMC partition; migration refuses to reuse its space')
    for part in planned:
        expected_role = 'rescue_b' if part['number'] == 3 else 'shared'
        existing = storage['partitions'][expected_role] or next((node for node in original_parts
                    if known_guids.get(str(part['number'])) and node.get('partuuid') == known_guids[str(part['number'])]), None)
        if existing:
            require(existing['start'] == part['start'] and existing['size'] == (part['end'] - part['start'] + 1) * 512,
                    'bootstrap_geometry', 'An existing OTA partition differs from the planned geometry')
    try:
        gate = check_gate(config, device)
    except OTAError as error:
        gate = {'passed': False, 'code': error.code, 'reason': str(error)}
    return {'device_id': device['device_id'], 'emmc': emmc['path'], 'preserved': [storage['partitions']['boot'], a],
            'append': planned, 'protected_prefix_bytes': board['protected_prefix_bytes'],
            'hardware_gate': gate, 'write_allowed': gate.get('write_allowed', gate['passed']), 'system_partition_table_changed': False}


def _hash_reserved(device_path, prefix_size):
    digest = hashlib.sha256()
    with Path(device_path).open('rb') as source:
        source.seek(34 * 512)  # GPT primary header/table are the only changed bytes in the reserved prefix.
        remaining = prefix_size - 34 * 512
        while remaining:
            data = source.read(min(1024 * 1024, remaining))
            require(data, 'reserved_read', 'Could not read the protected boot region')
            digest.update(data); remaining -= len(data)
    return digest.hexdigest()


def execute(engine, initial_manifest, anchor_location):
    config, backend, store = engine.config, engine.backend, engine.store
    with store.lock():
        planned = preview(config)
        if planned.get('factory_prepartitioned'):
            require(planned['complete'], 'factory_initialization', 'Factory first-boot identity initialization is incomplete')
            return planned
        require(planned['write_allowed'], 'hardware_gate', 'Bootstrap is disabled until physical kexec/watchdog acceptance')
        device = discover(config)
        journal_path = config.state / 'bootstrap.json'
        journal = read_json(journal_path) if journal_path.exists() else {'device_id': device['device_id'], 'steps': []}
        require(journal['device_id'] == device['device_id'], 'identity', 'Migration journal belongs to another device')
        if journal.get('complete'):
            return {'complete': True, 'already_initialized': True, 'device_id': device['device_id'], 'steps': journal['steps']}
        # Check the complete device toolchain before recording migration state or fetching payloads.
        if not config.simulate:
            backend.require_runtime_resources()
        if 'partition_guids' not in journal:
            journal['partition_guids'] = {str(part['number']): str(uuid.uuid4()) for part in planned['append']}
            atomic_json(journal_path, journal)
        engine.compatible(initial_manifest, device)
        require(not journal.get('initial_release') or journal['initial_release'] == initial_manifest['release'],
                'bootstrap_release', 'A resumed migration cannot change its initial baseline')
        journal['initial_release'] = initial_manifest['release']
        atomic_json(journal_path, journal)
        if not config.simulate:
            existing_storage = layout(config, device)
            from .bootstrap_space import prepare_cache
            prepare_cache(config, existing_storage)
            for role in ('rescue_a', 'system'):
                partition = existing_storage['partitions'][role]
                if not partition or partition['path'] == device['root']:
                    continue
                with backend.mount(partition) as root:
                    run('chroot', root, '/usr/bin/python3', '-B', '-c',
                        'import sys,cryptography; assert sys.version_info >= (3,11)')
        require(all(any(item['role'] == target + '-rootfs' for item in initial_manifest['artifacts'])
                    for target in ('system', 'rescue')), 'initial_baseline', 'Bootstrap needs a signed complete initial recovery baseline')
        raw_anchor = Path(anchor_location).read_bytes() if Path(anchor_location).is_file() else engine.transport.metadata(anchor_location)
        anchor = verify(raw_anchor, config.trust)
        require(anchor.get('kind') == 'anchor' and anchor.get('board') == config.profile and
                anchor.get('anchor_abi') == config.board()['anchor_abi'], 'anchor', 'Invalid fixed-bootstrap manifest')
        valid_sha(anchor.get('anchor_sha256'))
        require(anchor.get('artifacts') and {item['id'] for item in anchor['artifacts']} == {'kernel', 'initramfs', 'dtb'},
                'anchor_files', 'Fixed bootstrap must contain kernel, raw initramfs and DTB')
        require(anchor['anchor_sha256'] == anchor_digest(anchor['artifacts']), 'anchor_hash', 'Fixed bootstrap content digest differs from its manifest')
        require(isinstance(anchor.get('trusted_key_ids'), list) and anchor['trusted_key_ids'],
                'anchor_trust', 'Fixed bootstrap must declare its pinned signing key IDs')
        if not config.simulate and config.hardware_policy != 'development':
            gate = verify((config.state / 'hardware-gate.json').read_bytes(), config.trust)
            require(gate['anchor_sha256'] == anchor['anchor_sha256'], 'hardware_gate', 'Accepted anchor hash differs from the installation')
        engine.download(initial_manifest, 'all')
        if not config.simulate:
            require(initial_manifest['kernels']['system'] == initial_manifest['kernels']['rescue'] == device['kernel'],
                    'bootstrap_kernel', 'Initial baseline must match the currently running legacy kernel')
            legacy_boot = {'kernel': Path('/boot/Image'), 'dtb': Path('/boot/dtb/rockchip/rk3566-wxy-oec-turbo-4g.dtb')}
            for target in ('system', 'rescue'):
                for name, path in legacy_boot.items():
                    item = next(item for item in initial_manifest['artifacts'] if item['role'] == target + '-' + name)
                    require(sha256(path) == item['sha256'], 'bootstrap_kernel', 'Initial boot bundle differs from the working legacy BOOT')
        for item in anchor['artifacts']:
            valid_sha(item['sha256'])
            engine.prime_bootstrap_asset(item)
            engine.transport.download(item, config.cache)
        initrd = next(item for item in anchor['artifacts'] if item['id'] == 'initramfs')
        with (config.cache / initrd['sha256']).open('rb') as source:
            require(source.read(4) != bytes.fromhex('27051956'), 'raw_initramfs', 'Fixed bootstrap needs a raw initramfs')
        def completed(step):
            if step not in journal['steps']:
                journal['steps'].append(step)
                atomic_json(journal_path, journal)
        original = layout(config, device)
        if config.simulate:
            for item, role in zip(planned['append'], ('rescue_b', 'shared')):
                if not original['partitions'][role]:
                    device['blocks'].append({'path': '/dev/mmcblk0p' + str(item['number']), 'parent': planned['emmc'],
                        'type': 'part', 'size': (item['end'] - item['start'] + 1) * 512, 'start': item['start'],
                        'fstype': 'ext4', 'label': item['label'], 'uuid': str(uuid.uuid4()), 'partuuid': str(uuid.uuid4()),
                        'mountpoints': [], 'fixture_role': role, 'maj:min': '179:' + str(item['number'])})
            atomic_json(config.simulate / 'device.json', device)
            completed('partitions')
        else:
            require(os.geteuid() == 0, 'root', 'Bootstrap requires root')
            backups = config.cache.parent / 'bootstrap-backup'
            backups.mkdir(parents=True, exist_ok=True, mode=0o700)
            if 'backup' not in journal['steps']:
                run('sgdisk', '--backup=' + str(backups / 'gpt.bin'), planned['emmc'])
                from .bootstrap_space import backup_prefix
                journal['prefix_backup'] = backup_prefix(planned['emmc'], backups / 'protected-prefix.bin.zst',
                                                          config.board()['protected_prefix_bytes'])
                boot_dir = Path('/boot/extlinux')
                atomic_bytes(backups / 'extlinux.conf', (boot_dir / 'extlinux.conf').read_bytes())
                atomic_json(backups / 'geometry.json', original)
                journal['reserved_sha256'] = _hash_reserved(planned['emmc'], config.board()['protected_prefix_bytes'])
                completed('backup')
            if 'partitions' not in journal['steps']:
                run('sgdisk', '--move-second-header', planned['emmc'])
                for item, role in zip(planned['append'], ('rescue_b', 'shared')):
                    if not original['partitions'][role]:
                        guid = journal['partition_guids'][str(item['number'])]
                        table = disk_partitions(config, planned['emmc'])
                        existing = next((node for node in table if node.get('uuid', '').lower() == guid.lower()), None)
                        if not existing:
                            run('sgdisk', '--new=' + str(item['number']) + ':' + str(item['start']) + ':' + str(item['end']),
                                '--typecode=' + str(item['number']) + ':8300', '--change-name=' + str(item['number']) + ':' + item['label'],
                                '--partition-guid=' + str(item['number']) + ':' + guid, planned['emmc'])
                        # Add only the new partition to the live kernel table; do not reread/move the active A partition.
                        path = planned['emmc'] + 'p' + str(item['number'])
                        if not Path(path).exists():
                            run('partx', '--add', '--nr', str(item['number']), planned['emmc'])
                        if 'partition-' + str(item['number']) not in journal['steps']:
                            run('mkfs.ext4', '-F', '-L', item['label'], path)
                        completed('partition-' + str(item['number']))
                require(_hash_reserved(planned['emmc'], config.board()['protected_prefix_bytes']) == journal['reserved_sha256'],
                        'protected_boot_changed', 'Protected permanent boot/vendor region changed')
                completed('partitions')
            shared = layout(config, discover(config), initialized=True)['partitions']['shared']
            if 'shared' not in journal['steps']:
                with backend.mount(shared, writable=True) as root:
                    for path in config.state.iterdir():
                        if path.name == 'writer.lock':
                            continue
                        if path.is_dir():
                            shutil.copytree(path, root / path.name, dirs_exist_ok=True)
                        else:
                            shutil.copy2(path, root / path.name)
                    atomic_json(root / 'identity.json', {'device_id': device['device_id']})
                # The installed shared mount is activated on reboot. Continue this transaction on that filesystem.
                run('mount', '-t', 'ext4', shared['path'], config.state)
                completed('shared')
        storage = layout(config, discover(config), initialized=True)
        if not config.simulate and 'identity-and-runtime' not in journal['steps']:
            for target, role in [('rescue', 'rescue_a'), ('system', 'system')]:
                partition = storage['partitions'][role]
                if not partition:
                    continue
                if partition['path'] == device['root']:
                    root = Path('/')
                    backend.save_shared_identity(root, target)
                    backend.install_existing_runtime(root, storage)
                    atomic_json(root / 'etc/armhpc/release.json', {'release': initial_manifest['release'], 'target': target})
                else:
                    with backend.mount(partition, writable=True) as root:
                        backend.save_shared_identity(root, target)
                        backend.install_existing_runtime(root, storage)
                        atomic_json(root / 'etc/armhpc/release.json', {'release': initial_manifest['release'], 'target': target})
            completed('identity-and-runtime')
        fake_job = {'job_id': 'bootstrap-' + device['device_id'][:16], 'release': initial_manifest['release'],
                    'manifest': initial_manifest, 'target': 'all'}
        if 'rescue-config' not in journal['steps']:
            partition = storage['partitions']['rescue_a']
            if partition['path'] == device['root']:
                source = config.simulate / 'roots/rescue_a' if config.simulate else Path('/')
                path, inventory = backend.preserve(fake_job, source, 'rescue')
            else:
                with backend.mount(partition) as source:
                    path, inventory = backend.preserve(fake_job, source, 'rescue')
            journal['rescue_snapshot'] = path
            completed('rescue-config')
        fake_job['rescue_snapshot'] = journal['rescue_snapshot']
        if 'baseline-validated' not in journal['steps']:
            backend.validate_payloads(fake_job)
            completed('baseline-validated')
        if 'rescue-b' not in journal['steps']:
            artifact = next(item for item in initial_manifest['artifacts'] if item['role'] == 'rescue-rootfs')
            from .deployment import begin, complete
            partition = storage['partitions']['rescue_b']
            begin(config, discover(config), 'rescue_b', partition, fake_job)
            partition['_deployment_role'] = 'rescue_b'
            backend.verify_resources(fake_job)
            backend.write_image(artifact, partition)
            backend.restore(fake_job, partition, 'rescue')
            backend.prepare_root(fake_job, 'rescue', storage['partitions']['rescue_b'])
            completed('rescue-b')
            complete(config, 'rescue_b')
        # Both slots keep a verified boot copy even when shared state is damaged.
        rescue_boot = backend.boot_files(fake_job, 'rescue', storage['partitions']['rescue_b'])
        if config.simulate:
            backend.boot_files(fake_job, 'rescue', storage['partitions']['rescue_a'])
        else:
            if device['mode'] == 'rescue':
                backend.install_slot_fallback(fake_job, Path('/'))
            else:
                with backend.mount(storage['partitions']['rescue_a'], writable=True) as root:
                    backend.install_slot_fallback(fake_job, root)
        system_boot = backend.boot_files(fake_job, 'system') if storage['partitions']['system'] else None
        if 'control' not in journal['steps']:
            store.write_control({'protocol': 1, 'anchor_abi': config.board()['anchor_abi'],
                'anchor_sha256': anchor['anchor_sha256'], 'device_id': device['device_id'],
                'confirmed': {'rescue': {'slot': 'a', 'boot': rescue_boot},
                              **({'system': {'boot': system_boot}} if system_boot else {})},
                'highest_sequence': initial_manifest['sequence'], 'system_blocked': False, 'trial': None,
                'monitor_confirmed_boots': True, 'boot_attempt': None, 'bad_slots': [],
                'anchor_key_ids': anchor.get('trusted_key_ids', []),
                'next': {'target': 'rescue', 'slot': 'a', 'trial': False}})
            atomic_json(config.state / 'identity.json', {'device_id': device['device_id']})
            backend.baseline(fake_job, 'rescue'); backend.baseline(fake_job, 'system')
            completed('control')
        if 'anchor-installed' not in journal['steps']:
            backend.install_anchor(anchor, raw_anchor, storage)
            completed('anchor-installed')
        journal['complete'] = True
        atomic_json(journal_path, journal)
        return {'complete': True, 'device_id': device['device_id'], 'steps': journal['steps'], 'reboot_required': True}
