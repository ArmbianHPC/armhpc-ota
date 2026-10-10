# SPDX-License-Identifier: GPL-3.0-only
"""General signed-bundle staging and private BOOT export, never disk deployment."""
import base64
import hashlib
import os
from pathlib import Path
import select
import uuid
from .errors import require
from .io import atomic_json, read_json, sha256, writer_lock
from .serial_stream import reply, MAX_CHUNK


def upload(config, upload_id, digest, size, source, output):
    require(str(uuid.UUID(upload_id))==upload_id and len(digest)==64 and all(c in 'abcdef0123456789' for c in digest),
            'serial_binding','Invalid upload ID/hash')
    require(0<size<=2*1024**3,'serial_size','Bundle exceeds staging limit')
    from .device import discover
    device=discover(config)
    directory=config.cache/'uploads'/upload_id
    directory.mkdir(parents=True,mode=0o700,exist_ok=True)
    require(not directory.is_symlink() and directory.resolve().is_relative_to(config.cache.resolve()),
            'serial_path','Unsafe upload directory')
    import shutil
    existing=directory/'bundle'
    require(not existing.is_symlink(),'serial_path','Unsafe upload file')
    pending=max(0,size-(existing.stat().st_size if existing.exists() else 0))
    require(shutil.disk_usage(directory).free>=pending+64*1024**2,'serial_space','No staging space')
    binding={'device_id':device['device_id'],'sha256':digest,'size':size}
    with writer_lock(directory/'upload.lock'):
        manifest=directory/'binding.json'
        if manifest.is_file():require(read_json(manifest)==binding,'serial_binding','Upload request already bound')
        else:atomic_json(manifest,binding)
        path=directory/'bundle';require(not path.is_symlink(),'serial_path','Unsafe bundle path')
        with os.fdopen(os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600),'r+b',buffering=0) as stream:
            offset=os.fstat(stream.fileno()).st_size;require(offset<=size,'serial_offset','Bundle exceeds declared size');stream.seek(offset)
            reply({'state':'ready','offset':offset,'size':size,'sha256':digest,'path':str(path)},output)
            while True:
                import json
                line=source.readline(MAX_CHUNK*2+256);require(line and len(line)<MAX_CHUNK*2+256,'serial_frame','Missing/oversized frame')
                f=json.loads(line)
                if f.get('operation')=='cancel':
                    os.fsync(stream.fileno());reply({'state':'paused','offset':offset},output);return
                if f.get('operation')=='finish':
                    require(offset==size and sha256(path)==digest,'serial_hash','Bundle size/hash differs')
                    os.fsync(stream.fileno());reply({'state':'verified','offset':offset,'sha256':digest,'path':str(path)},output);return
                require(f.get('operation')=='chunk' and f.get('offset')==offset,'serial_offset','Unexpected offset')
                data=base64.b64decode(f['data'],validate=True)
                require(0<len(data)<=MAX_CHUNK and offset+len(data)<=size and
                        hashlib.sha256(data).hexdigest()==f.get('sha256'),'serial_chunk','Invalid chunk')
                stream.write(data);os.fsync(stream.fileno());offset+=len(data);reply({'state':'ack','offset':offset},output)


def export_boot(config, task_id, name, offset, source, output):
    from .boot_maintenance import record
    task=record(config)
    require(task and task['task_id']==task_id and name in ('BOOT-original.img','BOOT-rescue.img','BOOT-rescue.img.xz'),
            'boot_export','Export only the original task private BOOT backup')
    from .device import discover
    require(task['device_id']==discover(config)['device_id'],'serial_identity','Private backup belongs to another device')
    item=task['backups'][name];path=Path(item['path'])
    require(path.resolve().is_relative_to((config.cache/'boot-backups'/task_id).resolve()) and not path.is_symlink() and
            path.stat().st_size==item['bytes'] and sha256(path)==item['sha256'],'boot_export','Private BOOT backup changed')
    require(0<=offset<=item['bytes'],'serial_offset','Export offset exceeds file')
    reply({'state':'ready','offset':offset,'size':item['bytes'],'sha256':item['sha256']},output)
    with path.open('rb') as file:
        file.seek(offset)
        while offset<item['bytes']:
            data=file.read(min(MAX_CHUNK,item['bytes']-offset));require(data,'serial_truncated','Backup changed')
            reply({'state':'chunk','offset':offset,'sha256':hashlib.sha256(data).hexdigest(),
                   'data':base64.b64encode(data).decode()},output)
            import json
            ack=json.loads(source.readline(512));require(ack.get('operation')=='ack' and ack.get('offset')==offset+len(data),
                                                        'serial_ack','Invalid export acknowledgement')
            offset+=len(data)
    reply({'state':'verified','offset':offset,'sha256':item['sha256']},output)
