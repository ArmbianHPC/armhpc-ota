# SPDX-License-Identifier: GPL-3.0-only
"""Authenticated, resumable SFTP staging into the verified device cache."""
import os
from pathlib import Path
import pwd
import uuid
from .device import discover, layout
from .errors import require
from .io import atomic_json, read_json, sha256, fsync_dir
from .store import TERMINAL
from .download import required_artifacts


def receive(engine, manifest_path, target, request_id, phase='prepare'):
    c=engine.config
    require(phase in ('prepare','commit'), 'push_phase', 'Unknown receive phase')
    require(str(uuid.UUID(request_id))==request_id, 'request_id', 'Use a canonical push request UUID')
    require(c.simulate or os.geteuid()==0, 'root', 'Push staging requires root')
    with engine.store.lock():
        from .maintenance import require_complete
        require_complete(c)
        from .watchdog import require_idle as watchdog_idle
        from .boot_maintenance import require_idle as boot_idle
        watchdog_idle(c); boot_idle(c)
        job=engine.store.read()
        require(not job or job['stage'] in TERMINAL, 'job_active', 'Finish the active OTA task before importing payloads')
        manifest=engine.manifest(location=manifest_path,target=target)
        plan=engine.plan(manifest,target)
        require(plan['write_allowed'], 'hardware_gate', 'The device rejects this upgrade plan')
        directory=c.cache/'incoming'/request_id
        record=c.state/'imports'/(request_id+'.json')
        binding={'device_id':plan['device_id'],'release':manifest['release'],'target':target,
                 'manifest_sha256':sha256(c.state/'manifests'/(manifest['release']+'.json'))}
        if record.is_file():
            existing=read_json(record)
            require(all(existing.get(k)==v for k,v in binding.items()),'push_conflict','Push request is bound to another device/package')
        directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        require(not directory.is_symlink() and directory.resolve().is_relative_to(c.cache.resolve()),'push_path','Unsafe push staging directory')
        if not c.simulate and os.environ.get('SUDO_USER'):
            uploader=pwd.getpwnam(os.environ['SUDO_USER']);os.chown(directory,uploader.pw_uid,uploader.pw_gid)
        artifacts=[]
        selected={}
        for item in required_artifacts(manifest,target):
            previous=selected.get(item['sha256'])
            require(not previous or previous['size']==item['size'], 'push_size', 'One hash cannot have different signed sizes')
            selected.setdefault(item['sha256'],item)
        for item in selected.values():
            complete=engine._cached(item);part=directory/(item['sha256']+'.part')
            require(not part.is_symlink(),'push_path','Payload cannot be a symbolic link')
            offset=part.stat().st_size if part.is_file() else 0
            require(offset<=item['size'],'push_size','Staged payload is larger than the signed size')
            if phase=='prepare' and offset==item['size'] and sha256(part)!=item['sha256']:
                part.unlink();offset=0
            if phase=='commit' and not complete:
                require(offset==item['size'] and sha256(part)==item['sha256'],'push_hash','Uploaded payload differs from signed size/hash',role=item['role'])
                with part.open('rb') as stream:os.fsync(stream.fileno())
                os.replace(part,c.cache/item['sha256'])
                if not c.simulate:os.chown(c.cache/item['sha256'],0,0)
                (c.cache/item['sha256']).chmod(0o600);fsync_dir(c.cache);complete=True;offset=0
            artifacts.append({'role':item['role'],'sha256':item['sha256'],'size':item['size'],'complete':complete,
                              'offset':offset,'path':str(part)})
        result={**binding,'request_id':request_id,'directory':str(directory),'artifacts':artifacts,
                'complete':all(a['complete'] for a in artifacts),'manifest':str(c.state/'manifests'/(manifest['release']+'.json'))}
        atomic_json(record,{**binding,'complete':result['complete']})
        return result
