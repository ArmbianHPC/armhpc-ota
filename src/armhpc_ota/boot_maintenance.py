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
from . import boot_platform

DONE = ('rolled-back', 'committed')


def record(config):
    p = config.state / 'boot-maintenance/task.json'
    return read_json(p) if p.is_file() else None


def status(config):
    return {'task': record(config), 'hardware_verified': False, 'requires_rescue': True,
            'supported': boot_platform.supported(config.board()),
            'scope': 'BOOT filesystem and inactive Rescue; loaders and protected prefix excluded'}


def require_idle(config, diagnostic=False, job_id=None):
    r = record(config)
    paired=r and r['stage']=='updating-system' and job_id and job_id==r.get('system_job_id')
    require(not r or r['stage'] in DONE or paired or (diagnostic and r['stage'] == 'awaiting-watchdog'),
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
                m['layout']==b['layout'] and boot_platform.supported(b) and m['anchor_abi']==b['anchor_abi'],
                'boot_compatibility','Wrong board/architecture/layout/ABI')
        from . import __version__
        minimum=m.get('minimum_agent')
        require(minimum in ('0.3.4','1.1.1','1.1.2','1.1.3','1.1.4') and tuple(map(int,__version__.split('.'))) >= tuple(map(int,minimum.split('.'))),
                'boot_agent','Update the OTA agent before BOOT maintenance')
        require(b['id']!='wxy-oesp-v22' or minimum in ('1.1.1','1.1.2','1.1.3','1.1.4'),'boot_agent','OESP BOOT maintenance requires agent 1.1.1 or later')
        identifier(m['release'])
        require(isinstance(m['sequence'],int) and m['sequence']>engine.store.control().get('highest_boot_sequence',0),
                'boot_sequence','BOOT sequence must increase')
        require(parse_json(raw)['key_id'] in engine.store.control().get('anchor_key_ids',[]),'boot_key','Signer is not pinned')
        entries=m['files']
        required_files={'kernel','dtb','initramfs','recovery-initramfs','rescue-rootfs','rescue.manifest.json'}
        require(set(entries) in (required_files,required_files|{'system-rootfs'}) and
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
    if 'system-rootfs' in entries:
        require(m['minimum_agent'] in ('1.1.1','1.1.2','1.1.3','1.1.4'),'boot_agent','Paired system deployment requires agent 1.1.1 or later')
        require(rescue['kernels'].get('system')==m['kernel_release'],'boot_system_pair','System kernel differs')
        for name in ('kernel','dtb','initramfs','rootfs'):
            a=next(a for a in rescue['artifacts'] if a['role']=='system-'+name)
            file='system-rootfs' if name=='rootfs' else name
            require(a['sha256']==entries[file]['sha256'] and a['size']==entries[file]['size'],
                    'boot_system_pair','System/BOOT pairing differs')
            atomic_copy(base/file,c.cache/a['sha256'])
    atomic_bytes(c.state/'manifests'/(rescue['release']+'.json'),(base/'rescue.manifest.json').read_bytes())
    for name,kh,dh in [('initramfs',entries['kernel']['sha256'],entries['dtb']['sha256']),
                       ('recovery-initramfs',m['requires']['kernel_sha256'],m['requires']['dtb_sha256'])]:
        with (base/name).open('rb') as f:require(f.read(4)!=bytes.fromhex('27051956'),'raw_initramfs','Raw initramfs required')
        validate_initramfs(c,base/name,kh,dh)
    if not c.simulate:
        boot_platform.validate_load_window(b,base/'kernel',base/'dtb',base/'initramfs')
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
    require(source==storage['partitions']['boot']['path'],'boot_mount','BOOT differs from the verified partition')
    require(run('findmnt','-n','-o','FSTYPE','--mountpoint',p)==engine.config.board().get('boot_fstype','ext4'),
            'boot_mount','BOOT filesystem differs from the board adapter')
    readonly='ro' in run('findmnt','-n','-o','OPTIONS','--mountpoint',p).split(',')
    if readonly:run('mount','-o','remount,rw',p)
    try:yield p
    finally:
        run('sync','-f',p)
        if readonly:run('mount','-o','remount,ro',p)


def entry_files(directory, append):
    return boot_platform.entry_files(directory,append)


def install_entries(config,root,directory,arguments):
    ext,script=boot_platform.entry_files(directory,arguments,config.board())
    if config.board()['id']=='wxy-oesp-v22':
        ramdisk=root/directory.lstrip('/')/'initramfs'
        require(ramdisk.is_file(),'boot_initramfs','Missing raw candidate/recovery initramfs')
        boot_platform.write(config,ramdisk.with_name('initramfs.uboot'),boot_platform.ramdisk(ramdisk.read_bytes()))
    cmd=root/'armhpc-maintenance.cmd';boot_platform.write(config,cmd,script)
    image=b'SIMULATED-SCRIPT\n'+script if config.simulate else boot_platform.script_image(script)
    boot_platform.write(config,root/'extlinux/extlinux.conf',ext)
    boot_platform.write(config,root/'boot.cmd',script)
    if config.board()['id']=='wxy-oesp-v22':
        usb=b'setenv devtype usb\nsetenv devnum 0\n'+script
        boot_platform.write(config,root/'aml_autoscript.cmd',usb)
        image_usb=b'SIMULATED-SCRIPT\n'+usb if config.simulate else boot_platform.script_image(usb)
        boot_platform.write(config,root/'aml_autoscript',image_usb)
    boot_platform.write(config,root/'boot.scr',image)


def args(slot,task=None,recovery=False,board=None):
    board=board or {'id':'wxy-oect-original'}
    return boot_platform.arguments(board,slot,task,recovery)


def save(c,task):atomic_json(c.state/'boot-maintenance/task.json',task)


def backup(engine,storage,task,base):
    c=engine.config;private=c.cache/'boot-backups'/task['task_id'];private.mkdir(parents=True,mode=0o700,exist_ok=True)
    image=private/'BOOT-original.img'
    with boot_root(engine,storage) as root:
        for rel in boot_platform.entry_names(c.board()):
            p=root/rel;require(p.is_file() and not p.is_symlink(),'boot_entry','Missing/linked boot entry',file=rel)
            atomic_copy(p,private/'entries'/rel)
        ctl=engine.store.control();atomic_json(private/'selection.json',{k:ctl.get(k) for k in ('next','trial','system_blocked','anchor_sha256')})
        if not image.exists():
            if c.simulate:atomic_bytes(image,b'SIMULATED-BOOT-NOT-FLASHABLE')
            else:
                run('sync','-f',root)
                frozen=c.board().get('boot_fstype','ext4')=='ext4'
                run('fsfreeze','-f',root) if frozen else run('mount','-o','remount,ro',root)
                try:
                    with Path(storage['partitions']['boot']['path']).open('rb') as src:stream_copy(src,image,storage['partitions']['boot']['size'])
                finally:
                    run('fsfreeze','-u',root) if frozen else run('mount','-o','remount,rw',root)
                run('e2fsck','-f','-n',image) if frozen else run('fsck.fat','-n',image)
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
                if not c.simulate:run('mount','-t',c.board().get('boot_fstype','ext4'),loop,temp)
                try:
                    root=recovery if c.simulate else Path(temp);folder=root/'armhpc-recovery';folder.mkdir(exist_ok=True)
                    for name in ('kernel','dtb'):boot_platform.copy(c,c.state/task['original_boot'][name]['path'],folder/name)
                    boot_platform.copy(c,base/'recovery-initramfs',folder/'initramfs')
                    if not c.simulate:boot_platform.validate_load_window(c.board(),folder/'kernel',folder/'dtb',folder/'initramfs')
                    install_entries(c,root,'/armhpc-recovery',args(task['original_slot'],recovery=True,board=c.board()))
                    if not c.simulate:run('sync','-f',root)
                finally:
                    if not c.simulate:run('umount',temp)
        finally:
            if not c.simulate:run('losetup','--detach',loop)
        if not c.simulate:
            run('fsck.fat','-n',rescue_image) if c.board().get('boot_fstype')=='vfat' else run('e2fsck','-f','-n',rescue_image)
        atomic_json(completed,{'sha256':sha256(rescue_image)})
    compressed=private/'BOOT-rescue.img.xz'
    if not compressed.exists():
        temporary=compressed.with_suffix('.xz.partial')
        with rescue_image.open('rb') as src,lzma.open(temporary,'wb',preset=6) as out:shutil.copyfileobj(src,out,1024*1024)
        with temporary.open('rb') as f:os.fsync(f.fileno())
        os.replace(temporary,compressed);compressed.chmod(0o600);fsync_dir(private)
    task['backups']={p.name:{'path':str(p),'sha256':sha256(p),'bytes':p.stat().st_size} for p in (image,rescue_image,compressed)}
    task['entry_hashes']={rel:sha256(private/'entries'/rel) for rel in boot_platform.entry_names(c.board())}
    if c.board()['id']=='wxy-oesp-v22':
        from .boot_recovery import physical_identity
        task['emmc_cid_sha256']=physical_identity(c,storage['partitions']['boot']['parent'])
        task['recovery']={'protocol':1,'board':c.profile,'layout':c.board()['layout'],'anchor_abi':c.board()['anchor_abi'],
            'slot':task['original_slot'],'files':{name:{'sha256':sha256(path),'bytes':path.stat().st_size} for name,path in
            [('kernel',c.state/task['original_boot']['kernel']['path']),('dtb',c.state/task['original_boot']['dtb']['path']),
             ('initramfs',base/'recovery-initramfs')]},'signed_manifest':read_json(base/'manifest.json')}
    task['exports']=str(private/'EXPORT.json')
    atomic_json(task['exports'],{'protocol':1,'task_id':task['task_id'],'device_id':task['device_id'],
                'emmc_cid_sha256':task.get('emmc_cid_sha256'),'recovery':task.get('recovery'),
                'start_lba':storage['partitions']['boot']['start'],
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
        elif task['stage'] in ('awaiting-watchdog','preparing-system','updating-system') and commit:
            return commit_candidate(engine,task,storage)
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
            boot_platform.copy(c,base/name,folder/name);require(sha256(folder/name)==m['files'][name]['sha256'],'boot_hash','Installed BOOT file changed')
        task['stage']='entry-switching';save(c,task)
        install_entries(c,root,'/armhpc-maintenance/'+task['release'],args(task['inactive_slot'],task['task_id'],board=c.board()))
    task['stage']='awaiting-watchdog';task['checkpoints'].append('entries-switched');save(c,task)
    engine.clock.flush('boot-candidate-reboot')
    if not c.simulate:engine.backend.request_reboot()
    return status(c)


def rollback(engine,request_id=None):
    c=engine.config
    require(c.simulate or os.geteuid()==0,'root','BOOT rollback requires root')
    with engine.store.lock():
        task=record(c);require(task and request_id==task['task_id'],'boot_task','Use original BOOT task ID')
        d=discover(c,recovery=True)
        if d.get('boot_recovery'):
            from .boot_recovery import recovery_storage
            storage=recovery_storage(engine,d,task)
        else:storage=layout(c,d,initialized=True)
        engine._require_shared_mount(storage)
        require(d['mode']=='rescue','boot_mode','BOOT rollback requires Rescue')
        from .watchdog import require_idle
        require_idle(c)
        system_job=engine.store.read(task['system_job_id']) if task.get('system_job_id') else None
        require(not system_job or system_job['stage'] in TERMINAL,'job_active','Finish the paired system task before BOOT rollback')
        task['stage']='rolling-back';save(c,task)
        entries=Path(task['backups']['BOOT-original.img']['path']).parent/'entries'
        for rel,digest in task['entry_hashes'].items():
            require(sha256(entries/rel)==digest,'boot_backup_hash','Saved boot entry changed')
        with boot_root(engine,storage) as root:
            for rel in task['entry_hashes']:boot_platform.copy(c,entries/rel,root/rel)
        ctl=engine.store.control()
        ctl['confirmed']['rescue']={'slot':task['original_slot'],'boot':task['original_boot']}
        ctl['next']={'target':'rescue','slot':task['original_slot'],'trial':False};ctl['trial']=None
        ctl['system_blocked']=task['previous_system_blocked'] or bool(system_job and system_job.get('write_started'))
        if system_job and system_job.get('write_started'):ctl['confirmed']['system']=task.get('original_system')
        engine.store.write_control(ctl)
        from .deployment import abandon_boot
        task['stage']='rolled-back'
        abandon_boot(c,'rescue_'+task['inactive_slot'],task)
        save(c,task);return status(c)


def commit_candidate(engine,task,storage):
    c=engine.config
    if task['stage']=='updating-system':
        finish_paired_system(engine,engine.store.read(task['system_job_id']))
        return status(c)
    if task['stage']=='preparing-system':
        require(task.get('watchdog_checks_completed'),'watchdog_acceptance','BOOT acceptance was not completed')
        return begin_paired_system(engine,task,storage)
    require(task.get('ordinary_boot_healthy'),'boot_health','No candidate health evidence')
    records=[read_json(p) for p in (c.state/'watchdog').glob('????????-????-????-????-????????????.json')]
    records=[r for r in records if r.get('stage')=='recovered-confirmed' and
             r.get('boot')==task['candidate_boot'] and r.get('slot')==task['inactive_slot']]
    for sata in ('present','absent'):
        require(sum(r.get('kind')=='expire' and r.get('sata_condition')==sata for r in records)>=3,
                'watchdog_acceptance','Need three real expiry recoveries with AND without SATA')
    require(any(r.get('kind')=='panic' for r in records) and not c.simulate,'watchdog_acceptance','Real panic acceptance required')
    system=task.get('original_system')
    paired=not system or all(system['boot'][k]['sha256']==task['candidate_boot'][k]['sha256'] for k in ('kernel','dtb'))
    if not paired:
        bundle=verify((c.cache/'boot-maintenance'/task['bundle_sha256']/'manifest.json').read_bytes(),c.trust)
        require('system-rootfs' in bundle['files'],'normal_pairing','Supply the signed paired system payload before BOOT commit')
        task['watchdog_checks_completed']=True;task['stage']='preparing-system';save(c,task)
        return begin_paired_system(engine,task,storage)
    with boot_root(engine,storage) as root:
        install_entries(c,root,'/armhpc-maintenance/'+task['release'],
                        boot_platform.arguments(c.board()))
    ctl=engine.store.control();ctl['confirmed']['rescue']={'slot':task['inactive_slot'],'boot':task['candidate_boot']}
    ctl['system_blocked']=task['previous_system_blocked'];ctl['next']=task['previous_next'];ctl['trial']=None
    ctl['highest_boot_sequence']=task['sequence']
    # Anchor digest is recomputed from the actual candidate bytes by the publisher.
    ctl['anchor_sha256']=verify((c.cache/'boot-maintenance'/task['bundle_sha256']/'manifest.json').read_bytes(),c.trust)['anchor_sha256']
    engine.store.write_control(ctl);task['stage']='committed';task['internal_watchdog_passed']=True;save(c,task)
    return status(c)


def begin_paired_system(engine,task,storage):
    c=engine.config
    require(task['stage']=='preparing-system' and task.get('watchdog_checks_completed'),
            'watchdog_acceptance','Paired deployment requires completed BOOT acceptance')
    d=discover(c)
    require(d['mode']=='rescue' and d['root']==storage['partitions']['rescue_'+task['inactive_slot']]['path'],
            'boot_candidate','Enter the healthy paired Rescue before updating the system')
    require(storage['partitions'].get('system') and storage['partitions'].get('data'),
            'system_missing','Reconnect the bound SATA system and DATA disk')
    m,rescue,base,_=validate_bundle(engine,task['bundle'])
    require('system-rootfs' in m['files'],'normal_pairing','Signed paired system payload is missing')
    control=engine.store.control()
    control['confirmed']['rescue']={'slot':task['inactive_slot'],'boot':task['candidate_boot']}
    control['system_blocked']=True;control['trial']=None
    control['next']={'target':'rescue','slot':task['inactive_slot'],'trial':False}
    engine.store.write_control(control)
    preview=engine.plan(rescue,target='system')
    job_id=task.get('system_job_id') or str(uuid.uuid5(uuid.UUID(task['task_id']),'paired-system'))
    job_path=engine.store.job_path(job_id)
    if job_path.is_file():
        job=engine.store.read(job_id)
        require(job.get('kind')=='boot-maintenance-system' and job['release']==task['release'] and
                job['device_id']==task['device_id'],'boot_system_binding','Paired system job binding changed')
    else:
        job=engine.store.create(rescue,'system',preview,kind='boot-maintenance-system',request_id=job_id,local_only=True)
    task['system_job_id']=job_id;save(c,task)
    with boot_root(engine,storage) as root:
        install_entries(c,root,'/armhpc-maintenance/'+task['release'],boot_platform.arguments(c.board(),watchdog=True))
    task['stage']='updating-system';save(c,task)
    if not c.simulate:run('systemctl','start','--no-block','armhpc-ota-worker.service')
    return status(c)


def finish_paired_system(engine,job):
    c=engine.config;task=record(c)
    if not task or task['stage']!='updating-system' or not job or job['job_id']!=task.get('system_job_id'):
        return False
    require(job.get('kind')=='boot-maintenance-system' and job['release']==task['release'] and
            job['device_id']==task['device_id'],'boot_system_binding','Paired system job differs')
    if job['stage']!='succeeded':return False
    require('system-health-passed' in job['checkpoints'] and task.get('watchdog_checks_completed'),
            'boot_health','Paired system has no health confirmation')
    _,_,control=engine._recheck(job)
    require(control['confirmed']['system']['boot']==job['system_candidate']['boot'],
            'boot_system_binding','Confirmed system differs from the paired deployment')
    control['highest_boot_sequence']=task['sequence']
    control['anchor_sha256']=verify((c.cache/'boot-maintenance'/task['bundle_sha256']/'manifest.json').read_bytes(),c.trust)['anchor_sha256']
    engine.store.write_control(control)
    task.update(stage='committed',internal_watchdog_passed=not bool(c.simulate));save(c,task)
    return True


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
