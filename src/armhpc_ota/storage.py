# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded backup export and conservative shared-storage reclamation.

Backup bytes are streamed to the controller. Compression never runs here.
An export receipt is recorded only after the controller verifies its archive.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import time
import uuid
import shutil
from .device import discover, layout, run
from .errors import require, OTAError
from .io import atomic_json, canonical, fsync_dir, read_json, sha256

UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
HASH = re.compile(r'[0-9a-f]{64}')
MIN_AGE = 3600
BOOT_FILES = {'manifest.json', 'kernel', 'dtb', 'initramfs', 'recovery-initramfs',
              'rescue-rootfs', 'rescue.manifest.json', 'system-rootfs', 'bundle.tar.xz'}


def ledger(c):
    return c.state / "storage"


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def plain(path):
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink() and path.resolve() == path,
            'storage_path', 'Storage path contains a link or unexpected component')
    return path


def context(engine, rescue=False):
    c = engine.config
    d = discover(c)
    s = layout(c, d, initialized=True)
    engine._require_shared_mount(s)
    require(not rescue or d['mode'] == 'rescue', 'storage_mode', 'Enter Rescue before exporting or cleaning backups')
    return c, d, s


def records(c):
    result = {}
    for name, relative in [('boot', 'boot-maintenance/task.json'), ('tools', 'maintenance/task.json')]:
        p = c.state / relative
        result[name] = read_json(plain(p)) if p.exists() else None
    return result


def idle(engine, r):
    job = engine.store.read()
    require(not job or job.get('stage') in ('succeeded', 'cancelled'), 'storage_busy',
            'Finish or recover the OTA job before shared-storage cleanup')
    require(not r['boot'] or r['boot'].get('stage') in ('committed', 'rolled-back'),
            'storage_busy', 'Finish or roll back the BOOT task before cleanup')
    require(not r['tools'] or r['tools'].get('stage') in ('succeeded', 'rolled-back'),
            'storage_busy', 'Finish or roll back tool maintenance before cleanup')
    pending = engine.config.state / 'watchdog/test.json'
    if pending.exists():
        t = read_json(plain(pending))
        require(t.get('stage') in ('cancelled', 'recovered-confirmed', 'manual-recovery'),
                'storage_busy', 'Finish the watchdog diagnostic before cleanup')


def caches(c, s):
    roots = [c.state / 'cache']
    if c.simulate:
        roots.append(c.cache)
    elif Path('/data').is_mount() and s['partitions'].get('data'):
        source = run('findmnt', '-n', '-o', 'SOURCE', '--mountpoint', '/data')
        if str(Path(source).resolve()) == str(Path(s['partitions']['data']['path']).resolve()):
            roots.append(Path('/data/armhpc-ota/cache'))
    return list(dict.fromkeys(plain(p) for p in roots if p.is_dir()))


def tree(path, hashes=False):
    root = plain(path)
    rows = []
    rootdev = root.stat().st_dev
    for base, dirs, files in os.walk(root, followlinks=False):
        require(len(rows) + len(dirs) + len(files) <= 10000, 'storage_limit', 'Backup has too many files')
        for name in dirs:
            child = plain(Path(base) / name)
            require(child.stat().st_dev == rootdev and not child.is_mount(), 'storage_path', 'Nested mount in backup')
        for name in files:
            child = plain(Path(base) / name)
            st = child.stat()
            require(stat.S_ISREG(st.st_mode) and st.st_dev == rootdev and st.st_nlink == 1,
                    'storage_path', 'Backup contains a special, linked or foreign file')
            relative = child.relative_to(root).as_posix()
            require('\\' not in relative and not any(ord(x) < 32 for x in relative), 'storage_path', 'Unsafe file name')
            item = {'name': relative, 'bytes': st.st_size, 'mtime_ns': st.st_mtime_ns,
                    'inode': st.st_ino, 'device': st.st_dev}
            if hashes:
                item['sha256'] = sha256(child)
                after = child.stat()
                require((after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns) ==
                        (st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns),
                        'storage_changed', 'Backup changed while hashing')
            rows.append(item)
    return sorted(rows, key=lambda row: row['name'])


def groups(c, s, r):
    result = []
    parents = [(p / 'boot-backups', 'boot') for p in caches(c, s)]
    parents.append((c.state / 'maintenance/backups', 'tools'))
    for parent, kind in parents:
        if not parent.exists():
            continue
        for p in sorted(plain(parent).iterdir()):
            if not UUID.fullmatch(p.name) or not p.is_dir():
                continue
            try:
                files = tree(p)
                key = digest({'path': str(p), 'kind': kind})
                active = r[kind]
                same = active and active.get('task_id') == p.name
                protected = kind == 'tools' and same
                reason = 'Current tool rollback backup' if protected else None
                if kind == 'boot' and same and active.get('stage') not in ('committed', 'rolled-back'):
                    protected, reason = True, 'Current BOOT rollback/recovery backup'
                result.append({'id': key, 'task_id': p.name, 'kind': kind, 'path': str(p),
                               'bytes': sum(f['bytes'] for f in files), 'files': files,
                               'protected': bool(protected), 'reason': reason})
            except (OSError, ValueError, OTAError) as error:
                result.append({'id': digest({'path': str(p), 'kind': kind}), 'task_id': p.name,
                               'kind': kind, 'path': str(p), 'bytes': 0, 'files': [],
                               'protected': True, 'reason': 'Unrecognized backup: ' + str(error)})
    return result


def receipt(c, group):
    p = ledger(c) / 'receipts' / (group['id'] + '.json')
    if not p.is_file() or p.is_symlink():
        return None
    value = read_json(plain(p))
    current = group['files']
    saved = [{k: f[k] for k in ('name', 'bytes', 'mtime_ns', 'inode', 'device')} for f in value['inventory']['files']]
    return value if current == saved and value.get('archive_verified') is True else None


def status(engine):
    with engine.store.lock():
        c, d, s = context(engine)
        r = records(c)
        backups = groups(c, s, r)
        for g in backups:
            saved = receipt(c, g)
            g['exported'] = bool(saved)
            g['archive_sha256'] = saved['archive_sha256'] if saved else None
            g.pop('files')
        usage = shutil.disk_usage(c.state)
        return {'device_id': d['device_id'], 'mode': d['mode'], 'shared': {
            'total_bytes': usage.total, 'used_bytes': usage.used, 'free_bytes': usage.free},
            'backups': backups, 'compression_location': 'controller', 'minimum_staging_age_seconds': MIN_AGE}


def export(engine, backup_id):
    require(HASH.fullmatch(backup_id or ''), 'storage_id', 'Invalid backup ID')
    with engine.store.lock():
        c, d, s = context(engine, True)
        r = records(c)
        group = next((g for g in groups(c, s, r) if g['id'] == backup_id), None)
        require(group and group['files'], 'storage_backup', 'Backup is missing or cannot be exported safely')
        files = tree(Path(group['path']), True)
        task = r[group['kind']]
        if group['kind'] == 'boot' and task and task.get('task_id') == group['task_id']:
            for name, item in task.get('backups', {}).items():
                found = next((f for f in files if f['name'] == name), None)
                require(found and found['sha256'] == item['sha256'] and found['bytes'] == item['bytes'],
                        'storage_backup', 'Original BOOT backup differs from its task')
            for name, expected in task.get('entry_hashes', {}).items():
                found = next((f for f in files if f['name'] == 'entries/' + name), None)
                require(found and found['sha256'] == expected, 'storage_backup', 'BOOT entry backup changed')
        inventory = {'protocol': 1, 'kind': 'private-backup-export', 'device_id': d['device_id'],
                     'backup_id': backup_id, 'task_id': group['task_id'], 'backup_kind': group['kind'],
                     'source': group['path'], 'files': files}
        if group['kind'] == 'boot' and task and task.get('task_id') == group['task_id'] and task.get('stage') in ('committed', 'rolled-back'):
            inventory['completed_boot_task'] = group['task_id']
        require(len(canonical(inventory)) <= 3 * 1024**2, 'storage_limit', 'Backup inventory exceeds its metadata limit')
        token = digest(inventory)
        atomic_json(ledger(c) / 'exports' / (token + '.json'), inventory)
        return {'inventory': inventory, 'inventory_sha256': token,
                'bytes': sum(f['bytes'] for f in files), 'compression_location': 'controller'}


def export_file(c, token, name):
    require(HASH.fullmatch(token or ''), 'storage_id', 'Invalid export hash')
    inventory = read_json(plain(ledger(c) / 'exports' / (token + '.json')))
    require(digest(inventory) == token and inventory['device_id'] == discover(c)['device_id'],
            'storage_binding', 'Export inventory or device identity changed')
    item = next((f for f in inventory['files'] if f['name'] == name), None)
    require(item, 'storage_path', 'File is outside the approved backup inventory')
    path = plain(Path(inventory['source']) / name)
    require(path.is_relative_to(plain(Path(inventory['source']))) and path.is_file() and
            path.stat().st_size == item['bytes'] and sha256(path) == item['sha256'],
            'storage_changed', 'Backup file changed after export preparation')
    return path, item


def acknowledge(engine, token, archive_hash):
    require(HASH.fullmatch(token or ''), 'storage_id', 'Invalid export hash')
    require(HASH.fullmatch(archive_hash or ''), 'storage_archive', 'Provide the verified controller archive SHA256')
    with engine.store.lock():
        c, d, s = context(engine, True)
        inventory = read_json(plain(ledger(c) / 'exports' / (token + '.json')))
        require(HASH.fullmatch(token or '') and digest(inventory) == token and inventory['device_id'] == d['device_id'],
                'storage_binding', 'Export inventory changed')
        group = next((g for g in groups(c, s, records(c)) if g['id'] == inventory['backup_id']), None)
        require(group and tree(Path(group['path']), True) == inventory['files'],
                'storage_changed', 'Backup changed before archive acknowledgment')
        value = {'device_id': d['device_id'], 'inventory': inventory, 'inventory_sha256': token,
                 'archive_sha256': archive_hash, 'archive_verified': True,
                 'verified_at_unix': int(time.time())}
        atomic_json(ledger(c) / 'receipts' / (group['id'] + '.json'), value)
        return {'backup_id': group['id'], 'archive_verified': True, 'archive_sha256': archive_hash}


def _temp_root(c):
    if c.simulate:
        return c.simulate / 'tmp'
    text = run('findmnt', '-n', '-o', 'FSTYPE,OPTIONS', '-T', '/tmp')
    fields = text.split(maxsplit=1)
    if fields and fields[0] == 'overlay' and len(fields) == 2:
        upper = next((v[9:] for v in fields[1].split(',') if v.startswith('upperdir=')), None)
        if upper and plain(upper).stat().st_dev == c.state.stat().st_dev:
            return Path('/tmp')
    return Path('/tmp') if Path('/tmp').stat().st_dev == c.state.stat().st_dev else None


def _open_files():
    found = set()
    for pid in Path('/proc').glob('[0-9]*'):
        try:
            for fd in (pid / 'fd').iterdir():
                try:
                    found.add(os.readlink(fd))
                except OSError:
                    pass
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return found


def cleanup_plan(engine, unlocked=False):
    if not unlocked:
        with engine.store.lock():
            return cleanup_plan(engine, True)
    c, d, s = context(engine, True)
    r = records(c)
    idle(engine, r)
    candidates, protected = [], []
    opened = set() if c.simulate else _open_files()
    cutoff = time.time() - MIN_AGE

    def add(path, kind, exported=None):
        if not path.exists():
            return
        try:
            require(path.is_dir() or stat.S_ISREG(plain(path).stat().st_mode) and path.stat().st_nlink == 1,
                    'storage_path', 'Linked or special cache files are retained')
            files = tree(path) if path.is_dir() else [{
                'name': path.name, 'bytes': plain(path).stat().st_size,
                'mtime_ns': path.stat().st_mtime_ns, 'inode': path.stat().st_ino,
                'device': path.stat().st_dev}]
            require(files and all(str(path / f['name'] if path.is_dir() else path) not in opened for f in files),
                    'storage_open', 'Files are open or the directory is empty')
            if kind != 'exported-backup':
                require(max([path.stat().st_mtime, *[f['mtime_ns'] / 1e9 for f in files]]) <= cutoff,
                        'storage_recent', 'Recent staging files are retained for at least one hour')
            item = {'id': digest({'path': str(path), 'kind': kind}), 'path': str(path), 'kind': kind,
                    'bytes': sum(f['bytes'] for f in files), 'files': files}
            if exported:
                item['export_receipt_sha256'] = digest(exported)
            candidates.append(item)
        except (OSError, ValueError, OTAError) as error:
            protected.append({'path': str(path), 'reason': str(error)})

    boot_bundle = str(Path(r['boot']['bundle']).parent) if r['boot'] and r['boot'].get('bundle') else None
    # Only disposable caches are eligible; baselines, factory, overlays, identity,
    # configuration, jobs and task metadata never appear in this allowlist.
    for root in caches(c, s):
        if root.stat().st_dev != c.state.stat().st_dev:
            continue
        for p in root.iterdir():
            if HASH.fullmatch(p.name) and p.is_file():
                add(p, 'download-cache')
        parent = root / 'boot-maintenance'
        if parent.is_dir() and not parent.is_symlink():
            for p in parent.iterdir():
                if not HASH.fullmatch(p.name) or not p.is_dir():
                    continue
                if str(p) == boot_bundle:
                    protected.append({'path': str(p), 'reason': 'Retained BOOT task payload'})
                elif all(f.is_file() and not f.is_symlink() and
                         (f.name in BOOT_FILES or f.name.startswith('.') and f.name.endswith('.partial')) for f in p.iterdir()):
                    add(p, 'boot-staging')
        uploads = root / 'uploads'
        if uploads.is_dir() and not uploads.is_symlink():
            for p in uploads.iterdir():
                if UUID.fullmatch(p.name) and p.is_dir():
                    add(p, 'upload-staging')
    tmp = _temp_root(c)
    if tmp and tmp.is_dir():
        for p in tmp.glob('armhpc-ota-upload-*'):
            if re.fullmatch(r'armhpc-ota-upload-[0-9a-f]{32}', p.name) and p.is_dir():
                add(p, 'upload-staging')
    for group in groups(c, s, r):
        if Path(group['path']).stat().st_dev != c.state.stat().st_dev:
            continue
        saved = receipt(c, group)
        if saved and not group['protected']:
            # An unrecognized historical task may be exported, but removal needs
            # evidence that this was the completed BOOT task at acknowledgment.
            inv = saved['inventory']
            known = inv.get('completed_boot_task')
            current = r['boot']
            terminal = group['kind'] == 'boot' and (known == group['task_id'] or
                        current and current.get('task_id') == group['task_id'] and current.get('stage') in ('committed', 'rolled-back'))
            if terminal:
                add(Path(group['path']), 'exported-backup', saved)
                continue
        protected.append({'path': group['path'], 'reason': group['reason'] or 'Keep until a completed task backup is exported and verified'})
    items = sorted(candidates, key=lambda x: x['path'])
    identity = {'device_id': d['device_id'], 'items': items,
                'boot_task': r['boot'], 'tools_task': r['tools']}
    return {'device_id': d['device_id'], 'plan_id': digest(identity), 'items': items,
            'reclaimable_bytes': sum(i['bytes'] for i in items), 'protected': protected,
            'shared_free_bytes': shutil.disk_usage(c.state).free, 'minimum_staging_age_seconds': MIN_AGE}


def cleanup(engine, plan_id, item_ids=None):
    with engine.store.lock():
        plan = cleanup_plan(engine, True)
        require(HASH.fullmatch(plan_id or '') and plan['plan_id'] == plan_id,
                'storage_plan_changed', 'Storage or tasks changed; review a fresh cleanup plan')
        selected = set(item_ids or [i['id'] for i in plan['items']])
        require(selected and selected <= {i['id'] for i in plan['items']}, 'storage_selection', 'Select only entries in the current plan')
        # Check every export before the first unlink. Exported metadata stays in
        # storage/receipts and all persistent task history is retained.
        for item in plan['items']:
            if item['id'] in selected and item['kind'] == 'exported-backup':
                saved = next(receipt(engine.config, g) for g in groups(engine.config, context(engine)[2], records(engine.config))
                             if g['path'] == item['path'])
                require(saved and tree(Path(item['path']), True) == saved['inventory']['files'],
                        'storage_changed', 'Exported backup changed; no cleanup performed')
        removed = []
        for item in plan['items']:
            if item['id'] not in selected:
                continue
            p = plain(item['path'])
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            fsync_dir(p.parent)
            removed.append({'id': item['id'], 'bytes': item['bytes'], 'kind': item['kind']})
        return {'device_id': plan['device_id'], 'removed': removed,
                'removed_bytes': sum(i['bytes'] for i in removed),
                'shared_free_bytes': shutil.disk_usage(engine.config.state).free,
                'history_retained': True}


def stage(engine, size):
    require(isinstance(size, int) and 0 < size <= 2 * 1024**3, 'storage_size', 'Invalid upload size')
    with engine.store.lock():
        c, d, s = context(engine)
        from .bootstrap_space import prepare_cache
        prepare_cache(c, s)
        c.cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        free = shutil.disk_usage(c.cache).free
        require(free >= size + 64 * 1024**2, 'storage_space',
                'Upload cache lacks capacity; export backups and review shared-storage cleanup first',
                path=str(c.cache), required_bytes=size + 64 * 1024**2, free_bytes=free)
        path = c.cache / 'uploads' / str(uuid.uuid4())
        path.mkdir(parents=True, mode=0o700)
        return {'device_id': d['device_id'], 'directory': str(plain(path)), 'free_bytes': free,
                'required_bytes': size + 64 * 1024**2}


def stream_export(c, token, name, offset, source, output):
    """Use the existing authenticated serial frames for raw backup bytes."""
    import base64
    import json
    from .serial_stream import reply, MAX_CHUNK
    require(discover(c)['mode'] == 'rescue', 'storage_mode', 'Enter Rescue before export')
    path, item = export_file(c, token, name)
    require(0 <= offset <= item['bytes'], 'serial_offset', 'Export offset exceeds file')
    reply({'state': 'ready', 'offset': offset, 'size': item['bytes'], 'sha256': item['sha256']}, output)
    with path.open('rb') as stream:
        stream.seek(offset)
        while offset < item['bytes']:
            data = stream.read(min(MAX_CHUNK, item['bytes'] - offset))
            require(data, 'storage_changed', 'Backup was truncated during export')
            reply({'state': 'chunk', 'offset': offset, 'sha256': hashlib.sha256(data).hexdigest(),
                   'data': base64.b64encode(data).decode()}, output)
            ack = json.loads(source.readline(512))
            require(ack.get('operation') == 'ack' and ack.get('offset') == offset + len(data),
                    'serial_ack', 'Invalid export acknowledgment')
            offset += len(data)
    reply({'state': 'verified', 'offset': offset, 'sha256': item['sha256']}, output)
