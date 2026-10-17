# SPDX-License-Identifier: GPL-3.0-only
"""Restore one task-bound BOOT partition from a verified Rescue environment."""
import hashlib
import os
from pathlib import Path
import re
import stat
from .device import discover, ensure_unmounted, run, unique_block
from .errors import require
from .io import sha256
from .metadata import verify
from .platform import slot_nodes


def physical_identity(config, disk):
    if config.simulate:
        return hashlib.sha256(('fixture:'+str(config.simulate)).encode()).hexdigest()
    cid=Path('/sys/class/block')/Path(disk).name/'device/cid'
    require(cid.is_file(),'recovery_identity','Verified eMMC CID is unavailable')
    value=cid.read_text().strip().lower()
    require(re.fullmatch('[0-9a-f]{32}',value),'recovery_identity','Invalid eMMC CID')
    return hashlib.sha256(bytes.fromhex(value)).hexdigest()


def recovery_storage(engine,device,task):
    c=engine.config
    root=next((p for p in device['blocks'] if p['path']==device['root']),None)
    require(root and root.get('parent'),'boot_mode','Running Rescue backing partition is missing')
    boot=next((p for p in device['blocks'] if p.get('parent')==root['parent'] and p.get('start')==c.board()['boot_start']),None)
    require(boot,'recovery_disk','Missing BOOT geometry')
    if c.simulate:
        nodes={role:unique_block(device,label) for role,label in c.board()['labels'].items()
               if role in ('boot','rescue_a','rescue_b','shared')}
    else:
        from .metadata import parse_json
        table=parse_json(run('sfdisk','--json',root['parent']).encode())['partitiontable']
        nodes=slot_nodes(c.board(),device['blocks'],table,boot['path'])
    require(root['path']==nodes['rescue_'+task['original_slot']]['path'] and root.get('fstype')=='squashfs',
            'boot_running_slot','Recovery must run the retained confirmed Rescue slot')
    require(nodes['shared'].get('fstype')=='ext4','shared_mount','Shared recovery state is not ext4')
    engine._require_shared_mount({'partitions':nodes})
    require(physical_identity(c,root['parent'])==task.get('emmc_cid_sha256'),
            'recovery_identity','BOOT backup does not match the physical eMMC')
    require(boot['start']==task['boot']['start_lba'] and boot['size']==task['boot']['sectors']*512 and
            boot['path']==nodes['boot']['path'],'recovery_geometry','BOOT range differs from the approved task')
    return {'partitions':nodes}


def restore(engine, request_id, execute=False):
    from . import boot_maintenance as bm
    c=engine.config
    require(c.simulate or os.geteuid()==0,'root','BOOT restoration requires root')
    require(c.board()['id']=='wxy-oesp-v22','boot_recovery_board','This restore adapter requires OESP')
    with engine.store.lock():
        task=bm.record(c)
        require(task and request_id==task['task_id'] and task['stage'] not in bm.DONE,
                'boot_task','Use the unfinished original BOOT task ID')
        d=discover(c,recovery=True)
        require(d['device_id']==task['device_id'] and d['mode']=='rescue' and not d.get('installation_medium'),
                'boot_binding','BOOT recovery requires the original device in Rescue')
        storage=recovery_storage(engine,d,task);boot=storage['partitions']['boot']
        from .maintenance import require_complete
        from .watchdog import require_idle
        require_complete(c);require_idle(c)
        job=engine.store.read()
        from .store import TERMINAL
        require(not job or job['stage'] in TERMINAL,'job_active','Finish the original OTA job before BOOT restore')
        item=task['backups']['BOOT-rescue.img'];image=Path(item['path'])
        expected=c.cache/'boot-backups'/task['task_id']/'BOOT-rescue.img'
        require(image==expected and not image.is_symlink() and image.is_file(),
                'boot_backup_path','Use the original locally retained recovery image')
        require(image.stat().st_size==boot['size']==item['bytes'] and sha256(image)==item['sha256'],
                'boot_backup_hash','BOOT recovery image size or SHA256 differs')
        signed=verify((c.cache/'boot-maintenance'/task['bundle_sha256']/'manifest.json').read_bytes(),c.trust)
        recovery_name=bm.select_recovery_initramfs(signed,task['original_boot'])
        require(task.get('recovery_initramfs','recovery-initramfs')==recovery_name and
                signed['files'][recovery_name]['sha256']==task['recovery']['files']['initramfs']['sha256'],
                'boot_pair','Recovery image differs from the signed original kernel/DTB pair')
        preview={'task_id':request_id,'device_id':d['device_id'],'boot':task['boot'],
                 'image_sha256':item['sha256'],'bytes':item['bytes'],'original_slot':task['original_slot'],
                 'next_action':'boot rollback with the same request ID','hardware_verified':False}
        if not execute:return preview
        if not c.simulate:
            for mountpoint in ('/boot','/run/armhpc-ota/boot'):
                source=run('findmnt','-n','-o','SOURCE','--mountpoint',mountpoint,accepted=(0,1))
                if source:
                    require(str(Path(source.split('[')[0]).resolve())==boot['path'],
                            'boot_mount','Foreign filesystem at a BOOT mount point')
                    run('umount',mountpoint)
            ensure_unmounted(c,d,{**boot,'mountpoints':[]})
        engine.clock.flush('boot-recovery-restore')
        task['recovery_restore']={**preview,'stage':'writing'};bm.save(c,task)
        if c.simulate:
            target=c.simulate/'restored-BOOT.img'
            with image.open('rb') as source:bm.stream_copy(source,target,item['bytes'])
        else:
            target=Path(boot['path'])
            fd=os.open(target,os.O_WRONLY|os.O_NOFOLLOW)
            try:
                require(stat.S_ISBLK(os.fstat(fd).st_mode),'boot_target','Recovery target is not a block partition')
                with image.open('rb') as source:
                    require(os.fstat(source.fileno()).st_size==item['bytes'],'boot_backup_hash','Backup changed before restore')
                    copied=0;digest=hashlib.sha256()
                    while copied<item['bytes']:
                        chunk=source.read(min(1024**2,item['bytes']-copied))
                        require(chunk,'boot_backup_hash','Truncated BOOT recovery image');digest.update(chunk)
                        position=0
                        while position<len(chunk):
                            count=os.write(fd,chunk[position:]);require(count>0,'boot_write','Short BOOT write');position+=count
                        copied+=len(chunk)
                    os.fsync(fd)
                    require(digest.hexdigest()==item['sha256'],'boot_backup_hash','Backup changed during restoration')
            finally:os.close(fd)
        require(sha256(target)==item['sha256'],'boot_readback','Restored BOOT failed readback verification')
        if not c.simulate:
            run('fsck.fat','-n',target)
            run('mount','-t','vfat','-o','ro',target,'/run/armhpc-ota/boot')
            run('mount','-o','bind','/run/armhpc-ota/boot','/boot')
        task['recovery_restore']={**preview,'stage':'restored-awaiting-rollback'};bm.save(c,task)
        return task['recovery_restore']
