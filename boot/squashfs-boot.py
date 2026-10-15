# SPDX-License-Identifier: GPL-3.0-only
"""Mount a direct Rescue slot, or hand off to its independently paired kernel."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
sys.path.insert(0, '/usr/lib/armhpc-ota')
from armhpc_ota.config import Config
from armhpc_ota.boot import select, verify_boot
from armhpc_ota.device import run
from armhpc_ota.errors import require
from armhpc_ota.io import atomic_json, read_json, sha256, atomic_bytes
from armhpc_ota.metadata import verify, validate_manifest
from armhpc_ota.squashfs import read_trailer, generation, OVERLAY_OPTIONS, BOOT_RECORD

BASE = Path('/run/armhpc-ota')
BOARD = {}
BOOT_DEVICE = None


def partition(label, squash=False, optional=False):
    if squash and BOARD.get('partition_table') == 'dos':
        from armhpc_ota.device import flatten
        from armhpc_ota.platform import slot_nodes
        parent = run('lsblk', '-n', '-d', '-p', '-o', 'PKNAME', BOOT_DEVICE)
        blocks = flatten(json.loads(run('lsblk','--json','--bytes','--paths','--output',
            'NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,PARTUUID,START,LOG-SEC',parent))['blockdevices'])
        table = json.loads(run('sfdisk','--json',parent))['partitiontable']
        nodes = slot_nodes(BOARD,blocks,table,BOOT_DEVICE if 'armhpc.recovery-slot=' in Path('/proc/cmdline').read_text() else None)
        roles = [r for r in ('rescue_a','rescue_b') if BOARD['labels'][r] == label]
        require(len(roles)==1,'slot_label','Unknown Rescue role')
        return nodes[roles[0]]['path']
    query = ('PARTLABEL=' if squash else 'LABEL=') + label
    for _ in range(15 if not optional else 1):
        items = run('blkid', '-c', '/dev/null', '-t', query, '-o', 'device', accepted=(0, 2)).splitlines()
        require(len(items) <= 1, 'ambiguous_label', 'Multiple partitions match ' + query)
        if items: return str(Path(items[0]).resolve())
        time.sleep(1)
    require(optional, 'partition_missing', 'Missing ' + query)
    return None


def mount(device, path, kind, writable=False):
    path.mkdir(parents=True, exist_ok=True)
    run('mount', '-t', kind, '-o', 'rw,noatime' if writable else ('ro,noload' if kind == 'ext4' else 'ro'), device, path)


def recovery_boot_partition(board):
    from armhpc_ota.device import flatten
    from armhpc_ota.platform import slot_nodes
    shared=partition(board['labels']['shared'])
    parent=run('lsblk','-n','-d','-p','-o','PKNAME',shared)
    require((Path('/sys/class/block')/Path(parent).name/'device/cid').is_file(),
            'recovery_disk','Recovery shared partition is not on eMMC')
    blocks=flatten(json.loads(run('lsblk','--json','--bytes','--paths','--output',
        'NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,PARTUUID,START,LOG-SEC',parent))['blockdevices'])
    table=json.loads(run('sfdisk','--json',parent))['partitiontable']
    require(len(table.get('partitions',[]))==4,'mbr_layout','Incomplete recovery partition table')
    boot=table['partitions'][0]['node']
    nodes=slot_nodes(board,blocks,table,boot)
    require(nodes['shared']['path']==shared and nodes['shared']['fstype']=='ext4',
            'recovery_disk','Recovery shared partition differs from the MBR layout')
    return boot


def capacity(device): return int(run('blockdev', '--getsize64', device))


def identity(state):
    saved = state / 'identity.json'
    if saved.exists(): return read_json(saved)['device_id']
    cids = [p.read_text().strip() for p in Path('/sys/bus/mmc/devices').glob('*/cid')
            if (p.parent / 'type').read_text().strip() == 'MMC']
    require(len(cids) == 1, 'identity_missing', 'No unique eMMC identity for fresh installation')
    value = hashlib.sha256(('armhpc:' + ':'.join(sorted(cids))).encode()).hexdigest()
    atomic_json(saved, {'device_id': value})
    return value


def grow_shared(device, board):
    """Only extend the last shared partition. BOOT, A/B and reserved prefix never move."""
    parent = run('lsblk', '-n', '-d', '-p', '-o', 'PKNAME', device)
    require(parent.startswith('/dev/') and Path(parent).is_block_device(), 'shared_disk', 'Shared must belong to an eMMC disk')
    table = json.loads(run('sfdisk', '--json', parent))['partitiontable']
    p = table['partitions']
    require(table['label'] == board.get('partition_table','gpt') and len(p) == 4 and table.get('sectorsize', 512) == 512,
            'shared_geometry', 'Unexpected initial GPT layout')
    expected = [(board['boot_start'], board['boot_sectors']), (board['rescue_a_start'], board['rescue_a_sectors']),
                (board['rescue_b_start'], board['rescue_a_sectors'])]
    require(all(x['start'] == start and x['size'] == size for x, (start, size) in zip(p[:3], expected)) and
            p[3]['start'] == board['shared_start'] and p[3]['node'] == device,
            'shared_geometry', 'Shared growth would affect protected geometry')
    sectors = capacity(parent) // 512
    require(sectors * 512 >= board['minimum_emmc_bytes'], 'emmc_geometry', 'eMMC is too small')
    if board.get('partition_table') == 'dos':
        from armhpc_ota.platform import grow_mbr_shared
        if grow_mbr_shared(parent,device,board,table,sectors):
            run('partx','--update','--nr','4',parent);run('udevadm','settle','--timeout=15')
        run('e2fsck','-f','-p',device,accepted=(0,1));run('resize2fs',device)
        return
    last = sectors - 34
    if p[3]['start'] + p[3]['size'] - 1 < last:
        guid = p[3]['uuid']
        run('sgdisk', '-e', '--delete=4', '--new=4:' + str(p[3]['start']) + ':' + str(last),
            '--typecode=4:8300', '--change-name=4:' + board['labels']['shared'], '--partition-guid=4:' + guid, parent)
        run('partx', '--update', '--nr', '4', parent)
        run('udevadm', 'settle', '--timeout=15')
    # Retrying after a power cut between GPT and resize is safe and idempotent.
    run('e2fsck', '-f', '-p', device, accepted=(0, 1))
    run('resize2fs', device)


def kexec_target(selected, files, device, kind):
    require(not BOARD.get('fixed_boot_only'),'kernel_ota_unverified','This board has not accepted kernel handoff')
    args = ['root=PARTUUID=' + run('blkid', '-s', 'PARTUUID', '-o', 'value', device), 'rootfstype=' + kind,
            'boot=armhpc', 'armhpc.direct=1', 'armhpc.target=' + selected['target'], 'net.ifnames=0',
            'console=ttyS2,1500000', 'console=tty1', 'systemd.unified_cgroup_hierarchy=1',
            'armhpc.watchdog=1', 'watchdog.open_timeout=180', 'watchdog.stop_on_reboot=0', 'dw_wdt.nowayout=1']
    if selected.get('slot'): args.append('armhpc.slot=' + selected['slot'])
    if selected.get('task'): args.append('armhpc.task=' + selected['task'])
    run('kexec', '-l', files['kernel'], '--initrd=' + str(files['initramfs']), '--dtb=' + str(files['dtb']), '--append=' + ' '.join(args))
    run('sync')
    for path in (BASE / 'lower', BASE / 'shared', BASE / 'boot'):
        subprocess.run(['umount', str(path)], capture_output=True)
    os.execv('/usr/lib/armhpc-ota/watchdog-guard', ['watchdog-guard', '--kexec', '/dev/watchdog0', '60'])


def stage(name,shared=None):
    from armhpc_ota.io import atomic_json
    from time import monotonic
    path=Path('/run/armhpc/boot-stages.json')
    value=read_json(path) if path.is_file() else {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'stages':[]}
    value['stages'].append({'stage':name,'monotonic_seconds':monotonic()})
    value['stages']=value['stages'][-16:];atomic_json(path,value)
    if shared is not None:atomic_json(shared/'watchdog/boots'/('early-'+value['boot_id']+'.json'),value)


def main(root):
    global BOARD, BOOT_DEVICE
    config = Config.load(); config.state = BASE / 'shared'
    board = config.board(); labels = board['labels']; BOARD = board
    cmd = dict(x.split('=',1) for x in Path('/proc/cmdline').read_text().split() if '=' in x)
    forced_recovery=cmd.get('armhpc.recovery-slot')
    boot_ready=False;boot_error=None
    if forced_recovery:
        require(forced_recovery in ('a','b'),'recovery_slot','Invalid recovery slot')
    BOOT_DEVICE = recovery_boot_partition(board) if forced_recovery and board.get('partition_table')=='dos' else partition(labels['boot'])
    try:
        mount(BOOT_DEVICE, BASE / 'boot', board.get('boot_fstype','ext4'));boot_ready=True
    except Exception as error:
        if not forced_recovery:raise
        boot_error=str(error)
    install_medium = 'armhpc.install-medium=usb' in Path('/proc/cmdline').read_text().split()
    if install_medium: Path('/run/armhpc-install-medium').touch()
    shared_ok = False
    selected = None
    stage('kernel-initramfs-entered')
    errors = []
    try:
        shared_device = partition(labels['shared'])
        bootcmd=Path('/proc/cmdline').read_text().split()
        restricted=any(x.startswith(('armhpc.recovery-slot=','armhpc.boot-maintenance=')) for x in bootcmd)
        if not install_medium and not restricted and not (BASE / 'boot/armhpc-grow-disabled').exists(): grow_shared(shared_device, board)
        mount(shared_device, config.state, 'ext4', True)
        device_id = identity(config.state)
        control = read_json(config.state / 'control.json')
        require(control.get('device_id') in (None, device_id), 'identity', 'Boot control belongs to a different device')
        if control.get('device_id') is None:
            control['device_id'] = device_id; atomic_json(config.state / 'control.json', control)
            atomic_json(config.state / 'bootstrap.json', {'complete': True, 'device_id': device_id,
                'initial_release': control['confirmed']['rescue']['boot']['release'], 'steps': ['factory-prepartitioned', 'factory-slots-verified', 'identity-bound']})
        cmd = dict(a.split('=', 1) for a in Path('/proc/cmdline').read_text().split() if '=' in a)
        forced=cmd.get('armhpc.recovery-slot')
        maintenance=cmd.get('armhpc.boot-maintenance')
        if forced:
            require(forced in ('a','b'),'recovery_slot','Invalid recovery slot')
            Path('/run/armhpc-ota-maintenance-recovery').touch()
            selected={'target':'rescue','slot':forced,'task':None,'fallback':True}
        elif maintenance:
            from armhpc_ota.boot_maintenance import record
            task=record(config)
            require(task and task['task_id']==maintenance and task['stage'] in ('entry-switching','awaiting-watchdog','preparing-system'),
                    'boot_maintenance','Candidate is not admitted')
            bundle=verify((config.state/'boot-maintenance/releases'/task['release']/'manifest.json').read_bytes(),config.trust)
            require(bundle['release']==task['release'] and bundle['board']==board['id'] and
                    all(bundle['files'][k]['sha256']==task['candidate_boot'][k]['sha256'] for k in ('kernel','dtb','initramfs')),
                    'boot_candidate_signature','Candidate selection differs from signed BOOT bundle')
            selected={'target':'rescue','slot':task['inactive_slot'],'task':None,'boot':task['candidate_boot'],'trial':False}
        else:
            selected=None
        trial = control.get('trial')
        if selected is not None:
            pass
        elif cmd.get('armhpc.direct') == '1' and cmd.get('armhpc.task') and trial and cmd['armhpc.task'] == trial['task']:
            selected = {'target': trial['target'], 'slot': trial['candidate'].get('slot'), 'task': trial['task'],
                        'boot': trial['candidate']['boot'], 'trial': True}
        else:
            selected = {'target':'rescue','slot':'a','task':None,'fallback':True} if install_medium else select(config)
            if install_medium: selected['boot'] = control['confirmed']['rescue']['boot']
        if not cmd.get('armhpc.recovery-slot'): files = verify_boot(config, selected)
        shared_ok = True
        stage('shared-and-selection-verified',config.state)
    except Exception as error:
        errors.append(str(error) + ' ' + json.dumps(getattr(error, 'details', {})))
        if config.state.is_mount(): run('umount', config.state)
    cmd = dict(a.split('=', 1) for a in Path('/proc/cmdline').read_text().split() if '=' in a)
    if cmd.get('armhpc.recovery-slot') and selected is None:
        Path('/run/armhpc-ota-maintenance-recovery').touch()
        selected={'target':'rescue','slot':cmd['armhpc.recovery-slot'],'task':None,'fallback':True}
    candidates = [selected] if selected else []
    candidates += [{'target': 'rescue', 'slot': s, 'fallback': True, 'task': None} for s in ('a', 'b')
                   if not selected or s != selected.get('slot') or selected['target'] != 'rescue']
    if cmd.get('armhpc.recovery-slot'): candidates=candidates[:1]
    for choice in candidates:
        lower = BASE / 'lower'
        try:
            target = choice['target']; slot = choice.get('slot')
            device = partition(labels['system'] if target == 'system' else labels['rescue_' + slot], target == 'rescue')
            kind = 'ext4' if target == 'system' else 'squashfs'
            if target == 'rescue':
                manifest, signed = read_trailer(device, capacity(device), config.trust)
                require(manifest['layout'] == board['layout'] and manifest['board'] == board['id'], 'slot_board', 'Wrong Rescue layout/model')
                if choice.get('boot'):
                    require(choice['boot']['release'] == manifest['release'], 'slot_version', 'Selected Rescue has a different committed image')
            mount(device, lower, kind, target == 'system')
            stage('root-lower-mounted',config.state if shared_ok else None)
            marker = read_json(lower / 'etc/armhpc/release.json')
            if target == 'rescue':
                require(marker['release'] == manifest['release'] and marker['target'] == 'rescue', 'slot_version', 'Wrong root marker')
                local = lower / 'usr/lib/armhpc-ota/boot'
                local_files = {name: local / name for name in ('kernel', 'initramfs', 'dtb')}
                for name, path in local_files.items():
                    require(sha256(path) == next(a['sha256'] for a in manifest['artifacts'] if a['role'] == 'rescue-' + name),
                            'fallback_hash', 'Independent boot copy is damaged')
                files = local_files
            else:
                require(marker['release'] == choice['boot']['release'] and marker['target'] == 'system', 'root_version', 'SATA root is incomplete')
            require((lower / 'lib/modules' / marker['kernel']).is_dir(), 'modules', 'Missing paired modules')
            # The initial fixed kernel is the same paired build, so root switching requires no kexec.
            running_hash = Path('/etc/armhpc/anchor-kernel-sha256').read_text().strip()
            running_dtb=Path('/etc/armhpc/anchor-dtb-sha256')
            require(running_dtb.is_file(),'anchor_dtb','New bootstrap needs an embedded DTB identity')
            if sha256(files['kernel']) != running_hash or sha256(files['dtb']) != running_dtb.read_text().strip():
                require(not choice.get('fallback'), 'fallback_kernel', 'Independent fallback needs its separately paired kernel')
                require(not cmd.get('armhpc.boot-maintenance') and not cmd.get('armhpc.recovery-slot'),
                        'diagnostic_pair','Diagnostic/recovery must boot directly with paired kernel AND DTB')
                kexec_target(choice, files, device, kind)
            if target == 'rescue':
                if shared_ok:
                    g = generation(config.state, slot, marker['release'])
                    ready = g / 'ready.json'
                    require(ready.is_file() and read_json(ready)['root_sha256'] ==
                            next(a['sha256'] for a in manifest['artifacts'] if a['role'] == 'rescue-rootfs'),
                            'overlay_uncommitted', 'Rescue writable generation is incomplete')
                else:
                    g = BASE / 'emergency'
                    mount('tmpfs', g, 'tmpfs', True)
                for name in ('upper', 'work'):
                    (g / name).mkdir(parents=True, exist_ok=True, mode=0o755 if name == 'upper' else 0o700)
                (g / 'upper').chmod(0o755)
                if not shared_ok:
                    defaults = Path('/etc/armhpc/rescue-defaults')
                    shutil.copytree(defaults, g / 'upper', dirs_exist_ok=True)
                    (g / 'upper').chmod(0o755)
                root.mkdir(parents=True, exist_ok=True)
                run('mount', '-t', 'overlay', '-o', 'lowerdir=' + str(lower) + ',upperdir=' + str(g / 'upper') + ',workdir=' + str(g / 'work') + ',' + OVERLAY_OPTIONS, 'overlay', root)
            else:
                root.mkdir(parents=True, exist_ok=True); run('mount', '-o', 'move', lower, root)
            (root / 'boot').mkdir(exist_ok=True)
            if boot_ready: run('mount', '-o', 'bind', BASE / 'boot', root / 'boot')
            elif forced_recovery:
                fstab=root/'etc/fstab'
                require(fstab.is_file() and not fstab.is_symlink(),'recovery_fstab','Rescue fstab is missing or linked')
                masked=BASE/'recovery.fstab'
                masked.write_text(''.join(line for line in fstab.read_text().splitlines(keepends=True)
                    if len(line.split())<2 or line.lstrip().startswith('#') or line.split()[1]!='/boot'))
                run('mount','-o','bind',masked,fstab)
            if shared_ok:
                (root / 'var/lib/armhpc/ota').mkdir(parents=True, exist_ok=True)
                run('mount', '-o', 'bind', config.state, root / 'var/lib/armhpc/ota')
            if not (root / 'etc/armhpc/ota.json').is_file(): raise RuntimeError('Missing OTA config')
            # Systemd and the same CLI use this record to identify an overlay's backing slot.
            stage('root-and-overlay-ready',config.state if shared_ok else None)
            BOOT_RECORD.parent.mkdir(parents=True, exist_ok=True)
            record = {'target': target, 'slot': slot, 'task': choice.get('task'), 'root': device,
                      'partuuid': run('blkid', '-s', 'PARTUUID', '-o', 'value', device),
                      'release': marker['release'], 'lower_mount': str(lower), 'shared_ready': shared_ok,
                      'fallback': not shared_ok or bool(choice.get('fallback')), 'maintenance_recovery':bool(cmd.get('armhpc.recovery-slot')), 'boot_maintenance':cmd.get('armhpc.boot-maintenance'),
                      'installation_medium':install_medium,
                      'boot_device':BOOT_DEVICE,'boot_ready':boot_ready,'boot_error':boot_error,
                      'watchdog': (bool(choice.get('trial')) and board.get('watchdog_trial_enabled',True)) or cmd.get('armhpc.watchdog') == '1'}
            atomic_json(BOOT_RECORD, record)
            if record['watchdog']: Path('/run/armhpc-ota-watchdog-required').touch()
            if errors: (BOOT_RECORD.parent / 'boot-errors.log').write_text('\n'.join(errors) + '\n')
            print('ARMHPC mounted ' + target + ' ' + str(slot) + ' from ' + device, flush=True)
            return
        except Exception as error:
            errors.append(str(error) + ' ' + json.dumps(getattr(error, 'details', {}))); print('ARMHPC boot target refused: ' + str(error), file=sys.stderr, flush=True)
            for location in (root / 'var/lib/armhpc/ota', root / 'boot', root, lower):
                if location.is_mount(): subprocess.run(['umount', str(location)], capture_output=True)
    BOOT_RECORD.parent.mkdir(parents=True, exist_ok=True)
    (BOOT_RECORD.parent / 'boot-errors.log').write_text('\n'.join(errors) + '\n')
    raise RuntimeError('No valid SquashFS Rescue root')


if __name__ == '__main__': main(Path(sys.argv[1]))
