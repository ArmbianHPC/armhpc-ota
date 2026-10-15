# SPDX-License-Identifier: GPL-3.0-only
"""Board-scoped storage and boot policy; discovery never changes a disk."""
from copy import deepcopy
from pathlib import Path
import json
import re
import subprocess
from .errors import require

def partition_table(board):
    return board.get('partition_table', 'gpt')

def boot_fstype(board):
    value = board.get('boot_fstype', 'ext4')
    require(value in ('ext4', 'vfat'), 'boot_filesystem', 'Unsupported BOOT filesystem')
    return value

def slot_nodes(board, blocks, table, recovery_boot=None):
    """Bind MBR slots to a unique BOOT disk, signature, number and geometry."""
    boots = [b for b in blocks if b.get('label') == board['labels']['boot']]
    if recovery_boot is not None:
        require(not boots or (len(boots)==1 and boots[0]['path']==recovery_boot),
                'recovery_disk', 'BOOT label conflicts with the recovery disk')
        boots=[b for b in blocks if b.get('path')==recovery_boot]
    require(len(boots) == 1 and boots[0].get('parent'), 'ambiguous_label', 'Expected one BOOT partition')
    disk = boots[0]['parent']
    require(table.get('device') == disk and table.get('label') == 'dos'
            and table.get('sectorsize', 512) == 512, 'mbr_layout', 'Unexpected MBR disk identity')
    signature = table.get('id', '').lower()
    require(re.fullmatch(r'0x[0-9a-f]{8}', signature) and int(signature, 16) != 0,
            'mbr_signature', 'A nonzero MBR disk signature is required')
    entries = table.get('partitions', [])
    require(len(entries) == 4, 'mbr_layout', 'Exactly four primary partitions are required')
    actual = {b['path']: b for b in blocks if b.get('parent') == disk}
    expected = [(board['boot_start'], board['boot_sectors']),
                (board['rescue_a_start'], board['rescue_a_sectors']),
                (board['rescue_b_start'], board['rescue_a_sectors']),
                (board['shared_start'], None)]
    result = {}
    for role, number in board['partition_numbers'].items():
        row = entries[number-1]
        start, size = expected[number-1]
        node = actual.get(row.get('node'))
        require(node and row.get('start') == start and (size is None or row.get('size') == size)
                and node.get('start') == start and node.get('size') == row['size']*512,
                'partition_geometry', 'MBR partition geometry differs from the adapter', role=role)
        require(node.get('partuuid', '').lower() == signature[2:]+'-'+format(number, '02x'),
                'mbr_signature', 'Partition identity differs from MBR signature', role=role)
        require(str(row.get('type', '')).lower() in (('c', '0c', 'b', '0b') if role == 'boot' else ('83',)),
                'mbr_type', 'Unexpected MBR partition type', role=role)
        result[role] = node
    return result

def bind_mbr_labels(config, blocks, table_loader, recovery_boot=None, recovery_slot=None, admitted_targets=()):
    board = config.board()
    if partition_table(board) != 'dos':
        return blocks
    result = deepcopy(blocks)
    boots = [b for b in result if b.get('label') == board['labels']['boot']]
    if recovery_boot is not None:
        require(not boots or (len(boots)==1 and boots[0]['path']==recovery_boot),
                'recovery_disk', 'BOOT label conflicts with the recovery disk')
        boots=[b for b in result if b.get('path')==recovery_boot]
    require(len(boots) == 1, 'ambiguous_label', 'Expected one OESP BOOT partition')
    nodes = slot_nodes(board, result, table_loader(boots[0]['parent']),recovery_boot)
    if recovery_boot is not None:
        nodes['boot']['label']=board['labels']['boot']
    for role in ('rescue_a', 'rescue_b'):
        node = nodes[role]
        if node.get('fstype') == 'squashfs':
            from .squashfs import read_trailer
            if node['path'] in admitted_targets and node.get('_deployment_role')==role:
                node['_mbr_role']=role
                continue
            if recovery_boot is not None and role!='rescue_'+str(recovery_slot):
                continue
            manifest, _ = read_trailer(node['path'], node['size'], config.trust)
            require(manifest['board'] == board['id'] and manifest['layout'] == board['layout'],
                    'slot_board', 'SquashFS slot signature belongs to another board/layout')
            node['label'] = board['labels'][role]
            node['_mbr_role'] = role
    return result


def storage_view(config,device,table_loader,recovery_boot=None,recovery_slot=None):
    if partition_table(config.board())!='dos':return device
    from .deployment import view
    raw=deepcopy(device)
    for node in raw['blocks']:
        node.pop('_deployment_role',None);node.pop('_mbr_role',None)
    logical=view(config,raw)
    admitted={node['path'] for node in logical['blocks'] if node.get('_deployment_role') in ('rescue_a','rescue_b')}
    logical['blocks']=bind_mbr_labels(config,logical['blocks'],table_loader,recovery_boot,recovery_slot,admitted)
    return logical

def grow_mbr_shared(parent, device, board, table, sectors):
    entries = table['partitions']
    require(table['label'] == 'dos' and len(entries) == 4, 'mbr_layout', 'Cannot grow a foreign partition table')
    require(entries[3]['node'] == device and entries[3]['start'] == board['shared_start'],
            'shared_geometry', 'Cannot grow a foreign shared partition')
    start = entries[3]['start']; wanted = sectors-start
    if entries[3]['size'] >= wanted:
        return False
    with Path(parent).open('rb') as source:
        before = source.read(512)
    payload = f'{start}, {wanted}, 83\n'
    result = subprocess.run(['sfdisk', '--no-reread', '--no-tell-kernel', '--wipe', 'never',
                             '--wipe-partitions', 'never', '-N', '4', parent],
                            input=payload, text=True, capture_output=True)
    require(result.returncode == 0, 'shared_grow', 'MBR shared growth failed', diagnostic=result.stderr[-800:])
    with Path(parent).open('rb') as source:
        after = source.read(512)
    # Only the fourth entry may change; this also pins the disk signature and first three entries.
    require(before[:494] == after[:494] and before[510:] == after[510:],
            'shared_grow', 'MBR growth changed protected metadata')
    return True

def require_fixed_boot(config, manifest, control):
    if not config.board().get('fixed_boot_only'):
        return
    from .io import read_json
    old_release = control['confirmed']['rescue']['boot']['release']
    old = read_json(config.state/'manifests'/(old_release+'.json'))['payload']
    baseline = {a['role'].split('-', 1)[1]: a['sha256'] for a in old['artifacts']
                if a['role'] in ('rescue-kernel','rescue-dtb','rescue-initramfs')}
    for artifact in manifest['artifacts']:
        kind = artifact['role'].split('-', 1)[1]
        if kind in baseline:
            require(artifact['sha256'] == baseline[kind], 'kernel_ota_unverified',
                    'This board requires the confirmed fixed kernel, DTB and initramfs')

def console_arguments(board):
    return ['console='+board.get('console', 'ttyS2,1500000'), 'console=tty1',
            'systemd.unified_cgroup_hierarchy=1']
