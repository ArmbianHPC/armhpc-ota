# SPDX-License-Identifier: GPL-3.0-only
"""Keep registered framework resources paired with authenticated maintenance."""
from copy import deepcopy
from pathlib import Path
import os

from .errors import require
from .io import atomic_copy, atomic_json, inside, read_json, sha256

CATALOG = 'node-config/armhpc/state.json'
RESOURCES = 'node-config/armhpc/resources'


def checked_path(root, relative):
    root = Path(root)
    target = root / relative
    require(not any(p.is_symlink() for p in (target, *target.parents)
                    if p != root and p.is_relative_to(root)),
            'framework_state_path', 'Registered recovery resources cannot be symbolic links')
    require(all(p.stat().st_uid == os.geteuid() and not p.stat().st_mode & 0o022
                for p in target.parents if p.exists() and p.is_relative_to(root)),
            'framework_state_permissions', 'Recovery resource directories must be owned by root and not publicly writable')
    return inside(root, relative)


def private_file(path):
    require(path.is_file() and path.stat().st_uid == os.geteuid()
            and not path.stat().st_mode & 0o077,
            'framework_state_permissions', 'Recovery catalog and cache must be private files owned by root')


def verify_identity(storage, catalog, device):
    partition = storage['partitions']['data']
    identity = catalog.get('data', {})
    disk = next((d for d in device['blocks'] if d['path'] == partition['parent']), {})
    require(partition.get('uuid') and identity.get('uuid') == partition['uuid']
            and disk.get('tran') == 'sata'
            and any(disk.get(k) for k in ('serial', 'wwn'))
            and all(not identity.get(k) or identity[k] == disk.get(k) for k in ('serial', 'wwn')),
            'framework_state_identity', 'Registered resources belong to a different DATA disk')


def rebase(engine, storage, root, files, backup, rollback=False):
    """Caller holds the OTA writer lock and supplies files from a verified archive."""
    partition = storage['partitions'].get('data')
    if not partition:
        return {'changed': []}
    from .device import discover
    device = discover(engine.config)
    root, backup = Path(root), Path(backup)
    journal = backup / 'framework-catalog-update.json'
    with engine.backend.mount(partition, writable=True) as data:
        catalog_path = checked_path(data, CATALOG)
        if not catalog_path.exists():
            require(not journal.exists(), 'framework_state_changed', 'The saved recovery catalog is missing')
            return {'changed': []}
        private_file(catalog_path)
        catalog = read_json(catalog_path)
        require(catalog.get('schema_version') == 1 and isinstance(catalog.get('services'), dict),
                'framework_state_schema', 'Unsupported registered recovery catalog')
        verify_identity(storage, catalog, device)
        if rollback:
            if not journal.exists():
                return {'changed': []}
            saved = read_json(journal)
            before = backup / 'framework-catalog-before.json'
            require(saved.get('data') == catalog['data'] and before.is_file()
                    and sha256(before) == saved['before_sha256']
                    and sha256(catalog_path) in (saved['before_sha256'], saved['after_sha256']),
                    'framework_state_changed', 'Recovery catalog changed after maintenance; retain its history')
            atomic_copy(before, catalog_path, 0o600)
            return {'changed': saved['changes'], 'rolled_back': True}

        sources = {name: source for name, source in files.items()
                   if Path(name).parts[:3] == ('usr', 'lib', 'armhpc')
                   and len(Path(name).parts) == 4 and Path(name).suffix == '.py'}
        updated = deepcopy(catalog)
        changes, replacements = [], {}
        for unit, service in updated['services'].items():
            require(isinstance(service, dict) and isinstance(service.get('files'), list),
                    'framework_state_schema', 'Invalid registered service resource list')
            for item in service['files']:
                require(isinstance(item, dict) and isinstance(item.get('path'), str),
                        'framework_state_schema', 'Invalid registered resource')
                name = item['path']
                if name not in sources:
                    continue
                require(item.get('kind') is None and isinstance(item.get('sha256'), str)
                        and len(item['sha256']) == 64 and all(c in '0123456789abcdef' for c in item['sha256'])
                        and isinstance(item.get('mode'), int),
                        'framework_state_schema', 'Framework code must be a regular registered resource')
                source = sources[name]
                destination = checked_path(root, name)
                checksum = sha256(source)
                require(destination.is_file() and destination.stat().st_uid == os.geteuid()
                        and destination.stat().st_mode & 0o7777 == 0o644
                        and not os.listxattr(destination) and sha256(destination) == checksum,
                        'framework_state_hash', 'Installed framework code differs from the authenticated payload', file=name)
                if item['sha256'] == checksum and item['mode'] == 0o644:
                    continue
                old_cache = checked_path(data, RESOURCES + '/' + item['sha256'])
                private_file(old_cache)
                require(sha256(old_cache) == item['sha256'],
                        'framework_state_hash', 'The previous registered framework resource is damaged', file=name)
                changes.append({'unit': unit, 'path': name, 'before_sha256': item['sha256'],
                                'after_sha256': checksum, 'before_mode': item['mode'], 'after_mode': 0o644})
                item.update(sha256=checksum, mode=0o644)
                replacements[checksum] = source

        if journal.exists():
            saved = read_json(journal)
            require(saved.get('data') == catalog['data']
                    and sha256(catalog_path) in (saved['before_sha256'], saved['after_sha256']),
                    'framework_state_changed', 'Recovery catalog changed during maintenance')
            if sha256(catalog_path) == saved['after_sha256']:
                return {'changed': saved['changes'], 'resumed': True}
        if not changes:
            return {'changed': []}
        for checksum, source in replacements.items():
            cache = checked_path(data, RESOURCES + '/' + checksum)
            if cache.exists():
                private_file(cache)
                require(sha256(cache) == checksum, 'framework_state_hash', 'Replacement recovery cache is damaged')
            else:
                atomic_copy(source, cache, 0o600)
        before = backup / 'framework-catalog-before.json'
        after = backup / 'framework-catalog-after.json'
        if not journal.exists():
            atomic_copy(catalog_path, before, 0o600)
            atomic_json(after, updated)
            atomic_json(journal, {'data': catalog['data'], 'before_sha256': sha256(before),
                                 'after_sha256': sha256(after), 'changes': changes})
        else:
            saved = read_json(journal)
            require(before.is_file() and sha256(before) == saved['before_sha256']
                    and after.is_file() and sha256(after) == saved['after_sha256']
                    and read_json(after) == updated,
                    'framework_state_changed', 'Saved framework catalog migration differs from this payload')
        atomic_copy(after, catalog_path, 0o600)
        return {'changed': changes}
