# SPDX-License-Identifier: GPL-3.0-only
"""Separate signed BOOT transactions. No raw eMMC/GPT/loader writes."""
from contextlib import contextmanager
import lzma
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import uuid
from .device import discover, layout, ensure_unmounted, run
from .errors import require
from .io import atomic_json, atomic_bytes, atomic_copy, read_json, sha256, identifier, fsync_dir
from .metadata import verify, validate_manifest, valid_sha, parse_json
from .store import TERMINAL

DONE = ('rolled-back', 'committed')


def record(config):
    p = config.state / 'boot-maintenance/task.json'
    return read_json(p) if p.is_file() else None


def status(config):
    return {'task': record(config), 'hardware_verified': False, 'requires_rescue': True,
            'scope': 'BOOT filesystem and inactive Rescue; loaders and protected prefix excluded'}


def require_idle(config, diagnostic=False):
    r = record(config)
    require(not r or r['stage'] in DONE or (diagnostic and r['stage'] == 'awaiting-watchdog'),
            'boot_maintenance_active', 'Finish or roll back BOOT maintenance before another write task')


def stream_copy(src, dest, size):
    dest = Path(dest); temp = dest.with_name('.' + dest.name + '.partial')
    require(size >= 0 and not temp.is_symlink() and not dest.is_symlink(), 'boot_path', 'Unsafe copy path/size')
    with temp.open('wb') as out:
        left = size
        while left:
            data = src.read(min(left, 1024*1024)); require(data, 'copy_incomplete', 'Truncated source')
            out.write(data); left -= len(data)
        out.flush(); os.fsync(out.fileno())
    os.replace(temp, dest); dest.chmod(0o600); fsync_dir(dest.parent)


def validate_initramfs(config, path, kernel_hash, dtb_hash):
    if config.simulate: return
    with tempfile.TemporaryDirectory(prefix='boot-initrd-', dir=config.cache) as temp:
        run('unmkinitramfs', path.resolve(strict=True), temp)
        found = next((p for p in (Path(temp),Path(temp)/'main') if (p/'etc/armhpc/anchor-kernel-sha256').is_file()), None)
        require(found, 'boot_initramfs', 'Missing embedded bootstrap identity')
        require((found/'etc/armhpc/anchor-kernel-sha256').read_text().strip() == kernel_hash and
                (found/'etc/armhpc/anchor-dtb-sha256').read_text().strip() == dtb_hash,
                'boot_initramfs_pair', 'Embedded kernel/DTB hashes do not match')
        selector = found/'usr/lib/armhpc-ota/squashfs-boot.py'
        require(selector.is_file() and 'armhpc.recovery-slot' in selector.read_text() and
                'armhpc.boot-maintenance' in selector.read_text(), 'boot_selector', 'Missing recovery/candidate selector')


def validate_bundle(engine, bundle):
    c = engine.config; b = c.board(); d = discover(c)
    path = Path(bundle).resolve(strict=True)
    require(path.stat().st_size <= 2*1024**3, 'boot_bundle_size', 'BOOT bundle exceeds size limit')
    digest = sha256(path); base = c.cache/'boot-maintenance'/digest; base.mkdir(parents=True,exist_ok=True)
    with tarfile.open(path,'r:xz') as t:
        members = t.getmembers()
        require(len(members)<=16 and all(m.isfile() and '/' not in m.name and '\\' not in m.name and
                m.name not in ('.','..') for m in members) and len({m.name for m in members})==len(members),
                'boot_archive', 'Unsafe or duplicate BOOT archive members')
        names={m.name:m for m in members}
        require('manifest.json' in names and names['manifest.json'].size<=1024**2,'boot_manifest','Missing signed BOOT manifest')
        raw=t.extractfile(names['manifest.json']).read(); m=verify(raw,c.trust)
        require(m.get('kind')=='boot-maintenance' and m.get('protocol')==1,'boot_manifest','Wrong signed package type')
        require(m['board']==d['board'] and m['architecture']==d['architecture'] and
                m['layout']==b['layout']=='oect-squashfs-ab-v2' and m['anchor_abi']==b['anchor_abi'],
                'boot_compatibility','Wrong board/architecture/layout/ABI')
        require(m.get('minimum_agent')=='0.3.4','boot_agent','Unexpected BOOT package revision')
        identifier(m['release'])
        require(isinstance(m['sequence'],int) and m['sequence']>engine.store.control().get('highest_boot_sequence',0),
                'boot_sequence','BOOT sequence must increase')
        require(parse_json(raw)['key_id'] in engine.store.control().get('anchor_key_ids',[]),'boot_key','Signer is not pinned')
        entries=m['files']
        require(set(entries)=={'kernel','dtb','initramfs','recovery-initramfs','rescue-rootfs','rescue.manifest.json'} and
                set(names)=={'manifest.json',*entries},'boot_files','Incomplete/extra paired BOOT payload')
        require(sum(n.size for n in members)<=2*1024**3 and
                shutil.disk_usage(base).free>=sum(n.size for n in members)+64*1024**2,'boot_space','No staging capacity')
        for name,item in entries.items():
            valid_sha(item['sha256']);require(names[name].size==item['size'],'boot_size','Signed size mismatch')
            target=base/name
            require(not target.is_symlink(),'boot_path','Payload cannot be a link')
            if not target.is_file() or sha256(target)!=item['sha256']:
                with t.extractfile(names[name]) as src:stream_copy(src,target,item['size'])
            require(sha256(target)==item['sha256'],'boot_hash','BOOT payload hash mismatch',file=name)
        atomic_bytes(base/'manifest.json',raw)
    rescue=validate_manifest(verify((base/'rescue.manifest.json').read_bytes(),c.trust))
    engine.compatible(rescue,d)
    require(rescue['release']==m['release'] and rescue['kernels']['rescue']==m['kernel_release'],
            'boot_pair','Rescue version/kernel differs from candidate')
    for name in ('kernel','dtb','initramfs','rootfs'):
        a=next(a for a in rescue['artifacts'] if a['role']=='rescue-'+name)
        file='rescue-rootfs' if name=='rootfs' else name
        require(a['sha256']==entries[file]['sha256'] and a['size']==entries[file]['size'],'boot_pair','Rescue/BOOT pairing differs')
        atomic_copy(base/file,c.cache/a['sha256'])
    atomic_bytes(c.state/'manifests'/(rescue['release']+'.json'),(base/'rescue.manifest.json').read_bytes())
    for name,kh,dh in [('initramfs',entries['kernel']['sha256'],entries['dtb']['sha256']),
                       ('recovery-initramfs',m['requires']['kernel_sha256'],m['requires']['dtb_sha256'])]:
        with (base/name).open('rb') as f:require(f.read(4)!=bytes.fromhex('27051956'),'raw_initramfs','Raw initramfs required')
        validate_initramfs(c,base/name,kh,dh)
    stored=c.state/'boot-maintenance/releases'/m['release']/'manifest.json'
    require(not stored.exists() or stored.read_bytes()==raw,'release_reuse','Signed BOOT release IDs are immutable')
    from .metadata import anchor_digest
    expected=anchor_digest([{'id':k,**entries[k]} for k in ('kernel','initramfs','dtb')])
    require(m.get('anchor_sha256')==expected,'boot_anchor_hash','Anchor digest differs from candidate triple')
    atomic_bytes(stored,raw)
    return m,rescue,base,digest


@contextmanager
def boot_root(engine, storage):
    if engine.config.simulate:
        p=engine.config.simulate/'roots/boot';p.mkdir(exist_ok=True);yield p;return
    p=Path('/boot')
    source=str(Path(run('findmnt','-n','-o','SOURCE','--mountpoint',p).split('[')[0]).resolve())
    require(source==storage['partitions']['boot']['path'],'boot_mount','BOOT differs from GPT')
    readonly='ro' in run('findmnt','-n','-o','OPTIONS','--mountpoint',p).split(',')
    if readonly:run('mount','-o','remount,rw',p)
    try:yield p
    finally:
        run('sync','-f',p)
        if readonly:run('mount','-o','remount,ro',p)


def entry_files(directory, append):
    require(directory.startswith('/') and '..' not in directory and
            all(c.isalnum() or c in '/-._' for c in directory),'boot_path','Unsafe boot directory')
    ext=('DEFAULT ARMHPC\nTIMEOUT 10\nLABEL ARMHPC\n  LINUX '+directory+'/kernel\n  INITRD '+directory+
         '/initramfs\n  FDT '+directory+'/dtb\n  APPEND '+append+'\n')
    script=('# SPDX-License-Identifier: GPL-3.0-only\n'
            'if test -z "${devtype}"; then setenv devtype mmc; fi\n'
            'if test -z "${devnum}"; then setenv devnum 0; fi\n'
            'if test -z "${distro_bootpart}"; then setenv distro_bootpart 1; fi\n'
            'setenv kernel_addr_r 0x02000000\nsetenv fdt_addr_r 0x12000000\nsetenv ramdisk_addr_r 0x12180000\n'
            'setenv bootargs "'+append+'"\n'
            'if load ${devtype} ${devnum}:${distro_bootpart} ${kernel_addr_r} '+directory+'/kernel; then\n'
            ' if load ${devtype} ${devnum}:${distro_bootpart} ${fdt_addr_r} '+directory+'/dtb; then\n'
            '  if load ${devtype} ${devnum}:${distro_bootpart} ${ramdisk_addr_r} '+directory+'/initramfs; then\n'
            '   setenv armhpc_initrd_size ${filesize}\n'
            '   booti ${kernel_addr_r} ${ramdisk_addr_r}:${armhpc_initrd_size} ${fdt_addr_r}\n  fi\n fi\nfi\n')
    return ext.encode(),script.encode()


def install_entries(config,root,directory,arguments):
    ext,script=entry_files(directory,arguments)
    cmd=root/'armhpc-maintenance.cmd';atomic_bytes(cmd,script,0o644);scr=root/'.armhpc-maintenance.scr'
    if config.simulate:atomic_bytes(scr,b'SIMULATED-SCRIPT\n'+script,0o644)
    else:run('mkimage','-A','arm','-O','linux','-T','script','-C','none','-n','ARMHPC maintenance','-d',cmd,scr)
    atomic_copy(scr,root/'boot.scr',0o644);atomic_bytes(root/'extlinux/extlinux.conf',ext,0o644);scr.unlink(missing_ok=True)


def args(slot,task=None,recovery=False):
    v='rootfstype=squashfs ro rootwait boot=armhpc net.ifnames=0 console=ttyS2,1500000 console=tty1 systemd.unified_cgroup_hierarchy=1'
    if recovery:return v+' armhpc.recovery-slot='+slot
    return v+' armhpc.boot-maintenance='+task+' armhpc.watchdog=1 watchdog.open_timeout=180 watchdog.stop_on_reboot=0 dw_wdt.nowayout=1'


def save(c,task):atomic_json(c.state/'boot-maintenance/task.json',task)


def backup(engine,storage,task,base):
    c=engine.config;private=c.cache/'boot-backups'/task['task_id'];private.mkdir(parents=True,mode=0o700,exist_ok=True)
    image=private/'BOOT-original.img'
    with boot_root(engine,storage) as root:
        for rel in ('boot.scr','boot.cmd','extlinux/extlinux.conf','armbianEnv.txt'):
            p=root/rel;require(p.is_file() and not p.is_symlink(),'boot_entry','Missing/linked boot entry',file=rel)
            atomic_copy(p,private/'entries'/rel)
        ctl=engine.store.control();atomic_json(private/'selection.json',{k:ctl.get(k) for k in ('next','trial','system_blocked','anchor_sha256')})
        if not image.exists():
            if c.simulate:atomic_bytes(image,b'SIMULATED-BOOT-NOT-FLASHABLE')
            else:
                run('sync','-f',root);run('fsfreeze','-f',root)
                try:
                    with Path(storage['partitions']['boot']['path']).open('rb') as src:stream_copy(src,image,storage['partitions']['boot']['size'])
                finally:run('fsfreeze','-u',root)
                run('e2fsck','-f','-n',image)
    for name in ('kernel','dtb'):
        require(sha256(c.state/task['original_boot'][name]['path'])==task['original_boot'][name]['sha256'],
                'backup_pair','Original confirmed boot files changed')
    rescue_image=private/'BOOT-rescue.img'
    completed=private/'recovery-complete.json'
    if completed.exists():
        require(rescue_image.is_file() and sha256(rescue_image)==read_json(completed)['sha256'],'boot_backup_changed','Completed recovery image changed')
    else:
        atomic_copy(image,rescue_image)
        if c.simulate:recovery=c.simulate/'recovery-boot';recovery.mkdir(exist_ok=True)
        else:loop=run('losetup','--find','--show',rescue_image)
        try:
            with tempfile.TemporaryDirectory(prefix='recovery-boot-',dir=c.cache) as temp:
                if not c.simulate:run('mount','-t','ext4',loop,temp)
                try:
                    root=recovery if c.simulate else Path(temp);folder=root/'armhpc-recovery';folder.mkdir(exist_ok=True)
                    for name in ('kernel','dtb'):atomic_copy(c.state/task['original_boot'][name]['path'],folder/name,0o644)
                    atomic_copy(base/'recovery-initramfs',folder/'initramfs',0o644)
                    install_entries(c,root,'/armhpc-recovery',args(task['original_slot'],recovery=True))
                    if not c.simulate:run('sync','-f',root)
                finally:
                    if not c.simulate:run('umount',temp)
        finally:
            if not c.simulate:run('losetup','--detach',loop)
        if not c.simulate:run('e2fsck','-f','-n',rescue_image)
        atomic_json(completed,{'sha256':sha256(rescue_image)})
    compressed=private/'BOOT-rescue.img.xz'
    if not compressed.exists():
        temporary=compressed.with_suffix('.xz.partial')
        with rescue_image.open('rb') as src,lzma.open(temporary,'wb',preset=6) as out:shutil.copyfileobj(src,out,1024*1024)
        with temporary.open('rb') as f:os.fsync(f.fileno())
        os.replace(temporary,compressed);compressed.chmod(0o600);fsync_dir(private)
    task['backups']={p.name:{'path':str(p),'sha256':sha256(p),'bytes':p.stat().st_size} for p in (image,rescue_image,compressed)}
    task['entry_hashes']={rel:sha256(private/'entries'/rel) for rel in ('boot.scr','boot.cmd','extlinux/extlinux.conf','armbianEnv.txt')}
    task['exports']=str(private/'EXPORT.json')
    atomic_json(task['exports'],{'task_id':task['task_id'],'start_lba':storage['partitions']['boot']['start'],
                'sectors':storage['partitions']['boot']['size']//512,'files':task['backups'],'private':True,'whole_emmc_image':False})
    task['stage']='backup-ready';save(c,task)


def plan(engine,bundle):
    c=engine.config;d=discover(c);storage=layout(c,d,initialized=True);engine._require_shared_mount(storage)
    m,rescue,base,digest=validate_bundle(engine,bundle);original=engine.store.control()['confirmed']['rescue']
    require(original['boot']['kernel']['sha256']==m['requires']['kernel_sha256'] and
            original['boot']['dtb']['sha256']==m['requires']['dtb_sha256'],'boot_baseline','Recovery differs from original Rescue')
    p=storage['partitions']['boot'];needed=p['size']*3+128*1024**2+sum(v['size'] for v in m['files'].values())
    if not c.simulate:
        candidate_bytes=sum(m['files'][k]['size'] for k in ('kernel','dtb','initramfs'))
        recovery_bytes=sum((c.state/original['boot'][k]['path']).stat().st_size for k in ('kernel','dtb'))+m['files']['recovery-initramfs']['size']
        require(shutil.disk_usage('/boot').free>=max(candidate_bytes,recovery_bytes)+16*1024**2,'boot_partition_space','BOOT lacks capacity for retained and candidate/recovery files')
    require(shutil.disk_usage(c.cache).free>=needed,'boot_space','No capacity for BOOT backup/recovery')
    return {'release':m['release'],'sequence':m['sequence'],'device_id':d['device_id'],'mode':d['mode'],
            'boot':{'path':p['path'],'start_lba':p['start'],'sectors':p['size']//512},
            'inactive_slot':'b' if original['slot']=='a' else 'a','required_cache_bytes':needed,
            'bundle_sha256':digest,'original_slot':original['slot'],'recovery_export_required':True,'hardware_verified':False}


def apply(engine,bundle=None,request_id=None,exported=None,commit=False):
    c=engine.config;require(c.simulate or os.geteuid()==0,'root','BOOT maintenance requires root')
    with engine.store.lock():
        d=discover(c);storage=layout(c,d,initialized=True);engine._require_shared_mount(storage)
        require(d['mode']=='rescue','boot_mode','Reboot into confirmed Rescue before BOOT writes')
        from .maintenance import require_complete
        require_complete(c)
        from .watchdog import require_idle
        require_idle(c)
        job=engine.store.read();require(not job or job['stage'] in TERMINAL,'job_active','Another OTA job is active')
        old=record(c)
        if old and old['stage'] not in DONE:
            require(request_id==old['task_id'],'boot_task','Resume original BOOT ID');task=old;bundle=task['bundle']
            require(sha256(bundle)==task['bundle_sha256'],'boot_bundle_changed','Approved bundle changed')
        else:
            require(bundle and request_id and str(uuid.UUID(request_id))==request_id,'boot_request','Supply bundle and canonical ID')
            preview=plan(engine,bundle);ctl=engine.store.control()
            task={**preview,'task_id':request_id,'bundle':str(Path(bundle).resolve()),'stage':'preparing',
                  'original_boot':ctl['confirmed']['rescue']['boot'],'original_root':d['root'],'original_system':ctl['confirmed'].get('system'),
                  'previous_system_blocked':ctl.get('system_blocked',False),'previous_next':ctl.get('next'),'checkpoints':[]}
            require(d['root']==storage['partitions']['rescue_'+task['original_slot']]['path'],'boot_running_slot','First enter the original confirmed Rescue')
            save(c,task)
        require(task['device_id']==d['device_id'],'boot_binding','BOOT task belongs to another device')
        m,rescue,base,_=validate_bundle(engine,bundle)
        if task['stage']=='failed-needs-recovery':
            task['stage']=task.pop('resume_stage');task.pop('error',None);save(c,task)
        if task['stage']=='preparing':backup(engine,storage,task,base)
        if task['stage']=='backup-ready':
            if not exported:return status(c)
            require(exported==task['backups']['BOOT-rescue.img.xz']['sha256'],'boot_export','Export/verify private recovery first')
            for item in task['backups'].values():
                require(Path(item['path']).stat().st_size==item['bytes'] and sha256(item['path'])==item['sha256'],'boot_backup_hash','Private backup changed before BOOT switch')
            task['backup_exported_sha256']=exported;task['stage']='queued';save(c,task)
        elif task['stage']=='awaiting-watchdog' and commit:return commit_candidate(engine,task,storage)
        if task['stage'] in ('queued','deploying-rescue','installing-entries','entry-switching'):
            if not c.simulate:run('systemctl','start','--no-block','armhpc-ota-boot-maintenance.service')
            else:return run_candidate(engine,task,m,rescue,base,storage,d)
        return status(c)


def worker(engine):
    with engine.store.lock():
        c=engine.config;task=record(c)
        if not task or task['stage'] not in ('queued','deploying-rescue','installing-entries','entry-switching'):return status(c)
        d=discover(c);storage=layout(c,d,initialized=True);engine._require_shared_mount(storage)
        require(d['mode']=='rescue' and d['device_id']==task['device_id'],'boot_binding','Wrong maintenance environment')
        m,rescue,base,_=validate_bundle(engine,task['bundle'])
        return run_candidate(engine,task,m,rescue,base,storage,d)


def run_candidate(engine,task,m,rescue,base,storage,d):
    try:return worker_locked(engine,task,m,rescue,base,storage,d)
    except Exception as error:
        task['error']={'code':getattr(error,'code','boot_io'),'message':str(error)}
        task['resume_stage']=task['stage'];task['stage']='failed-needs-recovery';save(engine.config,task)
        raise


def worker_locked(engine,task,m,rescue,base,storage,d):
    c=engine.config;p=storage['partitions']['rescue_'+task['inactive_slot']]
    ensure_unmounted(c,d,p);ctl=engine.store.control();ctl['system_blocked']=True
    ctl['next']={'target':'rescue','slot':task['original_slot'],'trial':False};engine.store.write_control(ctl)
    if 'rescue-written' not in task['checkpoints']:
        job={'job_id':'boot-'+task['task_id'],'manifest':rescue,'release':rescue['release'],'target':'rescue',
             'local_only':True,'device_id':d['device_id']}
        if 'rescue_snapshot' in task:job['rescue_snapshot']=task['rescue_snapshot']
        else:
            root=c.simulate/'roots'/('rescue_'+task['original_slot']) if c.simulate else Path('/')
            snapshot,inventory=engine.backend.preserve(job,root,'rescue')
            task['rescue_snapshot']=snapshot;save(c,task);job['rescue_snapshot']=snapshot;job['rescue_inventory']=inventory
        engine.backend.validate_payloads(job);engine.clock.flush('boot-candidate-write')
        task['stage']='deploying-rescue';save(c,task)
        from .deployment import begin,complete
        begin(c,d,'rescue_'+task['inactive_slot'],p,job);p['_deployment_role']='rescue_'+task['inactive_slot']
        a=next(a for a in rescue['artifacts'] if a['role']=='rescue-rootfs')
        engine.backend.write_image(a,p);engine.backend.restore(job,p,'rescue');engine.backend.prepare_root(job,'rescue',p)
        task['candidate_boot']=engine.backend.boot_files(job,'rescue',p)
        complete(c,'rescue_'+task['inactive_slot']);task['checkpoints'].append('rescue-written');save(c,task)
    task['stage']='installing-entries';save(c,task)
    with boot_root(engine,storage) as root:
        folder=root/'armhpc-maintenance'/task['release'];folder.mkdir(parents=True,exist_ok=True)
        for name in ('kernel','dtb','initramfs'):
            atomic_copy(base/name,folder/name,0o644);require(sha256(folder/name)==m['files'][name]['sha256'],'boot_hash','Installed BOOT file changed')
        task['stage']='entry-switching';save(c,task)
        install_entries(c,root,'/armhpc-maintenance/'+task['release'],args(task['inactive_slot'],task['task_id']))
    task['stage']='awaiting-watchdog';task['checkpoints'].append('entries-switched');save(c,task)
    engine.clock.flush('boot-candidate-reboot')
    if not c.simulate:engine.backend.request_reboot()
    return status(c)


def rollback(engine,request_id=None):
    c=engine.config
    require(c.simulate or os.geteuid()==0,'root','BOOT rollback requires root')
    with engine.store.lock():
        task=record(c);require(task and request_id==task['task_id'],'boot_task','Use original BOOT task ID')
        d=discover(c);storage=layout(c,d,initialized=True);engine._require_shared_mount(storage)
        require(d['mode']=='rescue','boot_mode','BOOT rollback requires Rescue')
        from .watchdog import require_idle
        require_idle(c);task['stage']='rolling-back';save(c,task)
        entries=Path(task['backups']['BOOT-original.img']['path']).parent/'entries'
        for rel,digest in task['entry_hashes'].items():
            require(sha256(entries/rel)==digest,'boot_backup_hash','Saved boot entry changed')
        with boot_root(engine,storage) as root:
            for rel in ('boot.scr','boot.cmd','extlinux/extlinux.conf','armbianEnv.txt'):atomic_copy(entries/rel,root/rel,0o644)
        ctl=engine.store.control()
        ctl['confirmed']['rescue']={'slot':task['original_slot'],'boot':task['original_boot']}
        ctl['next']={'target':'rescue','slot':task['original_slot'],'trial':False};ctl['trial']=None
        ctl['system_blocked']=task['previous_system_blocked'];engine.store.write_control(ctl)
        from .deployment import complete
        complete(c,'rescue_'+task['inactive_slot'])
        task['stage']='rolled-back';save(c,task);return status(c)


def commit_candidate(engine,task,storage):
    c=engine.config;require(task.get('ordinary_boot_healthy'),'boot_health','No candidate health evidence')
    records=[read_json(p) for p in (c.state/'watchdog').glob('????????-????-????-????-????????????.json')]
    records=[r for r in records if r.get('stage')=='recovered-confirmed' and
             r.get('boot')==task['candidate_boot'] and r.get('slot')==task['inactive_slot']]
    for sata in ('present','absent'):
        require(sum(r.get('kind')=='expire' and r.get('sata_condition')==sata for r in records)>=3,
                'watchdog_acceptance','Need three real expiry recoveries with AND without SATA')
    require(any(r.get('kind')=='panic' for r in records) and not c.simulate,'watchdog_acceptance','Real panic acceptance required')
    system=task.get('original_system')
    require(not system or all(system['boot'][k]['sha256']==task['candidate_boot'][k]['sha256'] for k in ('kernel','dtb')),
            'normal_pairing','Normal system must have paired kernel/DTB before final BOOT commit')
    with boot_root(engine,storage) as root:
        install_entries(c,root,'/armhpc-maintenance/'+task['release'],
                        'rootfstype=squashfs ro rootwait boot=armhpc net.ifnames=0 console=ttyS2,1500000 console=tty1 systemd.unified_cgroup_hierarchy=1')
    ctl=engine.store.control();ctl['confirmed']['rescue']={'slot':task['inactive_slot'],'boot':task['candidate_boot']}
    ctl['system_blocked']=task['previous_system_blocked'];ctl['next']=task['previous_next'];ctl['trial']=None
    ctl['highest_boot_sequence']=task['sequence']
    # Anchor digest is recomputed from the actual candidate bytes by the publisher.
    ctl['anchor_sha256']=verify((c.cache/'boot-maintenance'/task['bundle_sha256']/'manifest.json').read_bytes(),c.trust)['anchor_sha256']
    engine.store.write_control(ctl);task['stage']='committed';task['internal_watchdog_passed']=True;save(c,task)
    return status(c)


def confirm_diagnostic(engine):
    task=record(engine.config)
    if not task or task['stage']!='awaiting-watchdog':return False
    d=discover(engine.config);storage=layout(engine.config,d,initialized=True)
    require(d['mode']=='rescue' and d['root']==storage['partitions']['rescue_'+task['inactive_slot']]['path'],
            'boot_candidate','Wrong diagnostic root')
    dummy={'job_id':'boot-'+task['task_id'],'checkpoints':['rescue-health-passed'],
           'manifest':{'kernels':{'rescue':task['candidate_boot']['kernel_release']}},
           'rescue_candidate':{'slot':task['inactive_slot']}}
    engine.backend.health(dummy,'rescue',storage)
    task['ordinary_boot_healthy']=True;save(engine.config,task);return True
