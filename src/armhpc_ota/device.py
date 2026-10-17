# SPDX-License-Identifier: GPL-3.0-only
"""Read-only Linux discovery. No watchdog device is opened during discovery."""
import hashlib
import os
from pathlib import Path
import platform
import subprocess
from .errors import OTAError, require
from .io import read_json, parse_json
from .dependencies import SYSTEM_PATH, TOOL_PACKAGES


def run(*args, accepted=(0,), capture=True, environment=None):
    try:
        result = subprocess.run([str(arg) for arg in args], capture_output=capture, text=capture,
                                env={**os.environ, **(environment or {}), 'PATH': SYSTEM_PATH, 'LC_ALL': 'C.UTF-8'})
    except FileNotFoundError as error:
        command = str(args[0])
        package = TOOL_PACKAGES.get(Path(command).name)
        hint = ' Install Debian package: ' + package if package else ''
        raise OTAError('command_missing', 'Required command was not found: ' + command + '.' + hint,
                       command=command, package=package) from error
    require(result.returncode in accepted, 'command_failed', 'Required command failed', command=str(args[0]),
            exit_code=result.returncode,
            program=str(args[2]) if str(args[0]) == 'chroot' and len(args) > 2 else str(args[0]),
            diagnostic=(result.stderr or '')[-1000:] if capture and str(args[0]) in
                       ('mount', 'sgdisk', 'sfdisk', 'partx', 'e2fsck', 'resize2fs', 'lsblk', 'blkid') else None,
            operation='simulation' if str(args[0]) == 'chroot' and '-s' in args else
                      'install' if str(args[0]) == 'chroot' and 'install' in args else None)
    return result.stdout.strip() if capture else ''


def flatten(items, parent=None):
    result = []
    for original in items:
        node = {key: value for key, value in original.items() if key != 'children'}
        node['parent'] = parent
        result.append(node)
        result.extend(flatten(original.get('children', []), node['path']))
    return result


def discover(config, recovery=False):
    if config.simulate:
        return read_json(config.simulate / 'device.json')
    require(platform.system() == 'Linux', 'platform', 'Device operations require Linux; use --simulate-root for fixtures')
    board = config.board()
    compatible = Path('/proc/device-tree/compatible').read_bytes().rstrip(b'\0').decode().split('\0')
    require(all(item in compatible for item in board['compatible']), 'board_mismatch', 'Device tree does not match the selected adapter')
    blocks = flatten(parse_json(run('lsblk', '--json', '--bytes', '--paths', '--output',
        'NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,UUID,PARTUUID,START,LOG-SEC,MOUNTPOINTS,TRAN,PKNAME,MAJ:MIN,MODEL,SERIAL,WWN,PARTLABEL').encode())['blockdevices'])
    root_source = run('findmnt', '-n', '-o', 'SOURCE', '/')
    root = str(Path(root_source.split('[')[0]).resolve())
    for node in blocks:
        if node.get('fstype') == 'squashfs' and not node.get('label'):
            node['label'] = node.get('partlabel')
    if root_source == 'overlay':
        from .squashfs import boot_context
        record = boot_context()
        backing = record.get('lower_mount', '')
        require(record.get('target') == 'rescue' and backing.startswith('/run/armhpc-ota/'), 'overlay_identity', 'Overlay root has no verified backing record')
        lower = run('findmnt', '-n', '-o', 'SOURCE,FSTYPE', '--mountpoint', backing).split()
        require(len(lower) == 2 and lower[1] == 'squashfs' and str(Path(lower[0]).resolve()) == record.get('root'),
                'overlay_identity', 'Overlay lower mount differs from the selected Rescue slot')
        root = record['root']
        require(any(n.get('path') == root and n.get('partuuid') == record.get('partuuid') for n in blocks),
                'overlay_identity', 'Overlay backing partition identity changed')
    architecture = run('dpkg', '--print-architecture')
    mode = 'rescue' if Path('/etc/armhpc/rescue-environment').exists() else 'system'
    state_identity = config.state / 'identity.json'
    if state_identity.is_file():
        device_id = read_json(state_identity)['device_id']
    else:
        # CID is stable across both environments; only publish its hash.
        cids = [p.read_text().strip() for p in Path('/sys/bus/mmc/devices').glob('*/cid')
                if (p.parent / 'type').read_text().strip() == 'MMC']
        require(len(cids) == 1, 'identity_missing', 'Cannot uniquely identify the eMMC for OTA bootstrap')
        device_id = hashlib.sha256(('armhpc:' + ':'.join(sorted(cids))).encode()).hexdigest()
    recovery_boot=None;recovery_slot=None
    if recovery and board.get('partition_table')=='dos':
        from .squashfs import boot_context
        context=boot_context()
        if context.get('maintenance_recovery'):
            require(context.get('shared_ready') and context.get('target')=='rescue',
                    'recovery_context','Recovery requires a verified Rescue and mounted shared partition')
            recovery_boot=context.get('boot_device');recovery_slot=context.get('slot')
            require(recovery_boot and recovery_slot in ('a','b'),'recovery_context','Recovery partition identity is missing')
    device={'device_id': device_id, 'board': config.profile, 'architecture': architecture,
            'distribution': 'bookworm', 'mode': mode, 'root': root, 'kernel': platform.release(),
            'blocks': blocks, 'compatible': compatible,
            'boot_recovery':recovery_boot is not None,
            'installation_medium': Path('/run/armhpc-install-medium').exists()}
    from .platform import storage_view
    return storage_view(config,device,lambda disk: parse_json(run('sfdisk','--json',disk).encode())['partitiontable'],
                        recovery_boot,recovery_slot)


def unique_block(device, label, optional=False):
    matches = [node for node in device['blocks'] if node.get('label') == label]
    require(len(matches) <= 1, 'ambiguous_label', 'Duplicate filesystem label', label=label)
    require(optional or len(matches) == 1, 'partition_missing', 'Required partition was not found', label=label)
    return matches[0] if matches else None


def layout(config, device, initialized=False):
    from .deployment import view
    device = view(config, device)
    board = config.board()
    require(device['architecture'] == board['architecture'] and device['board'] == board['id'],
            'board_mismatch', 'Device architecture or model does not match adapter')
    labels = board['labels']
    found = {role: unique_block(device, name, optional=role in ('rescue_b', 'shared', 'system', 'data'))
             for role, name in labels.items()}
    boot, rescue = found['boot'], found['rescue_a']
    require(boot['parent'] == rescue['parent'] and boot['parent'], 'emmc_layout', 'BOOT and Rescue A must share eMMC')
    emmc = next((item for item in device['blocks'] if item['path'] == boot['parent']), None)
    require(emmc and int(emmc['size']) >= board['minimum_emmc_bytes'] and int(emmc['log-sec']) == board['sector_size'],
            'emmc_geometry', 'Unsupported eMMC capacity or logical sector size')
    for role, start, size in [('boot', board['boot_start'], board['boot_sectors']),
                             ('rescue_a', board['rescue_a_start'], board['rescue_a_sectors'])]:
        item = found[role]
        require(int(item['start']) == start and int(item['size']) == size * board['sector_size'] and item['fstype'] == (board.get('boot_fstype', 'ext4') if role == 'boot' else board.get('rescue_fstype', 'ext4')),
                'partition_geometry', 'Existing BOOT/Rescue geometry differs from the adapter', role=role)
    if initialized:
        for role in ('rescue_b', 'shared'):
            item = found[role]
            require(item and item['parent'] == emmc['path'] and item['fstype'] == (board.get('rescue_fstype', 'ext4') if role == 'rescue_b' else 'ext4'),
                    'bootstrap_required', 'OTA A/B layout is not initialized', role=role)
        require(found['rescue_b']['size'] == found['rescue_a']['size'], 'slot_size', 'Rescue slots must be the same size')
        a_end = rescue['start'] + rescue['size'] // 512
        expected_b = ((a_end + 2047) // 2048) * 2048
        b_end = expected_b + rescue['size'] // 512
        expected_shared = ((b_end + 2047) // 2048) * 2048
        require(found['rescue_b']['start'] == expected_b and found['shared']['start'] == expected_shared,
                'slot_overlap', 'Rescue B/shared layout overlaps or differs from the append-only layout')
        require(found['shared']['start'] + found['shared']['size'] // 512 <= emmc['size'] // 512 - board.get('disk_tail_reserved_sectors', 33),
                'shared_geometry', 'Shared filesystem exceeds the usable GPT disk range')
        require(len([node for node in device['blocks'] if node.get('parent') == emmc['path']]) == 4,
                'foreign_partition', 'Unexpected eMMC partitions in the OTA layout')
    if found['system']:
        system, data = found['system'], found['data']
        require(data and system['parent'] == data['parent'] and system['parent'] != emmc['path'],
                'sata_layout', 'System and DATA must be separate partitions on SATA')
        disk = next(item for item in device['blocks'] if item['path'] == system['parent'])
        if board['id']=='wxy-oesp-v22':
            require(disk.get('serial') or disk.get('wwn'),'disk_identity','OESP SATA requires a serial number or WWN')
        require(disk.get('tran') == 'sata' and system['fstype'] == data['fstype'] == 'ext4' and
                int(system['size']) == board['system_bytes'], 'sata_layout', 'Expected a 64 GiB ext4 SATA root and ext4 DATA')
        require(system['type'] == data['type'] == 'part' and int(data['start']) >= int(system['start']) + int(system['size']) // 512,
                'sata_overlap', 'DATA overlaps the system partition')
    return {'partitions': found, 'emmc': emmc, 'board': board}


def ensure_unmounted(config, device, target):
    require(not device.get('installation_medium'), 'installation_medium', 'USB commissioning media cannot deploy OTA targets')
    require(target['path'] != device['root'], 'running_root', 'Refusing to write the running root filesystem')
    require(not any(target.get('mountpoints') or []), 'mounted', 'Target partition is mounted', target=target['path'])
    labels = config.board()['labels']
    require(target['label'] not in (labels['data'], labels['boot'], labels['shared']),
            'protected_partition', 'DATA, BOOT and OTA_SHARED are never rootfs update targets')
    if not config.simulate:
        major_minor = target['maj:min']
        # Include mount namespaces of other processes, not just the SSH session.
        for path in Path('/proc').glob('[0-9]*/mountinfo'):
            try:
                mounted = any(line.split()[2] == major_minor for line in path.read_text().splitlines())
            except (FileNotFoundError, ProcessLookupError):
                continue
            require(not mounted, 'mounted_namespace', 'Target is mounted in a process namespace')
        swaps = Path('/proc/swaps').read_text().splitlines()[1:]
        require(not any(str(Path(line.split()[0]).resolve()) == target['path'] for line in swaps),
                'swap_target', 'Target is used for swap')
        holders = Path('/sys/dev/block') / major_minor / 'holders'
        require(not list(holders.iterdir()), 'holders', 'Target has active device-mapper/RAID holders')


def check_gate(config, device, control=None):
    require(not device.get('boot_recovery'),'boot_recovery','Finish explicit BOOT recovery before automatic OTA')
    require(not device.get('installation_medium'), 'installation_medium', 'OTA writing is disabled on USB commissioning media')
    if config.hardware_policy == 'development':
        board = config.board()
        require(board.get('development_ota_supported') is True and device['board'] == board['id'] and
                device['architecture'] == board['architecture'], 'development_board',
                'Development authorization is restricted to the explicitly supported board adapter')
        return {'passed': False, 'write_allowed': True, 'policy': 'development',
                'simulated': bool(config.simulate), 'hardware_verified': False,
                'reason': 'OTA writes enabled by explicit board authorization'}
    if config.simulate:
        require(device.get('simulated_gate') is True, 'hardware_gate', 'Fixture gate is disabled')
        return {'passed': True, 'write_allowed': True, 'policy': 'verified', 'simulated': True}
    path = config.state / 'hardware-gate.json'
    require(path.is_file(), 'hardware_gate', 'OECT kexec/watchdog physical acceptance is required before OTA writes')
    from .metadata import verify
    gate = verify(path.read_bytes(), config.trust)
    require(gate.get('kind') == 'hardware-acceptance' and gate.get('device_id') == device['device_id'] and
            gate.get('board') == config.profile and gate.get('anchor_abi') == config.board()['anchor_abi'],
            'hardware_gate', 'Hardware evidence does not match this device and bootstrap')
    needed = ('kexec', 'sata_handoff', 'emmc_handoff', 'ethernet_handoff', 'early_kernel_failure_reset',
              'userspace_failure_reset', 'rescue_fallback', 'raw_initramfs')
    require(all(gate.get('checks', {}).get(item) is True for item in needed),
            'hardware_gate', 'Physical acceptance is incomplete')
    from .metadata import valid_sha
    valid_sha(gate.get('evidence_sha256'))
    valid_sha(gate.get('anchor_sha256'))
    if control:
        require(gate['anchor_sha256'] == control['anchor_sha256'], 'hardware_gate', 'Bootstrap differs from the accepted hardware test')
    return {'passed': True, 'write_allowed': True, 'policy': 'verified', 'simulated': False, 'evidence_sha256': gate['evidence_sha256']}
