# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Signed, temporary SSH bridge for Rescue backup management.

Export inventories live on /run tmpfs until cleanup makes persistent space.
No installed files, boot entries, task records or rootfs images are changed.
"""
import os
from pathlib import Path
import stat
import uuid

from . import storage
from .device import run
from .errors import require
from .io import atomic_json, read_json


def dispatch(engine, request):
    c, d, _ = storage.context(engine, True)
    require(request.get('device_id') == d['device_id'], 'storage_binding', 'SSH bridge device identity differs')
    session = request.get('session_id', '')
    try:
        require(str(uuid.UUID(session)) == session, 'storage_session', 'Invalid backup session')
    except (ValueError, AttributeError):
        require(False, 'storage_session', 'Invalid backup session')
    parent = c.simulate / 'run/storage-bridge' if c.simulate else Path('/run/armhpc-storage-bridge')
    if not c.simulate:
        require(os.geteuid() == 0, 'storage_privilege', 'Run the backup bridge as root or through sudo')
        require(run('findmnt', '-n', '-o', 'FSTYPE', '-T', '/run') == 'tmpfs', 'storage_memory', '/run must be tmpfs')
    parent.mkdir(mode=0o700, parents=bool(c.simulate), exist_ok=True)
    storage.plain(parent)
    require(parent.is_dir() and stat.S_IMODE(parent.stat().st_mode) == 0o700,
            'storage_session', 'Backup bridge directory must be private')
    base = parent / session
    base.mkdir(mode=0o700, exist_ok=True)
    storage.plain(base)
    require(stat.S_IMODE(base.stat().st_mode) == 0o700 and
            (bool(c.simulate) or base.stat().st_uid == 0), 'storage_session', 'Invalid bridge session owner or permissions')
    binding = base / 'session.json'
    expected = {'device_id': d['device_id'], 'session_id': session}
    if binding.exists():
        require(read_json(storage.plain(binding)) == expected, 'storage_binding', 'Backup session belongs to another device')
    else:
        atomic_json(binding, expected)
    original = storage.ledger
    storage.ledger = lambda _c: base
    try:
        args = request.get('arguments')
        require(isinstance(args, list) and 1 <= len(args) <= 10003 and all(isinstance(x, str) for x in args),
                'storage_arguments', 'Invalid backup operation arguments')
        operation = args[0]
        if operation == 'status' and len(args) == 1:
            result = storage.status(engine)
        elif operation == 'export' and len(args) == 3 and args[1] == '--backup-id':
            result = storage.export(engine, args[2])
        elif operation == 'acknowledge' and len(args) == 5 and args[1] == '--inventory-sha256' and args[3] == '--archive-sha256':
            result = storage.acknowledge(engine, args[2], args[4])
        elif operation == 'plan' and len(args) == 1:
            result = storage.cleanup_plan(engine)
        elif operation == 'cleanup':
            require(request.get('yes') is True and len(args) >= 5 and args[1] == '--plan-id' and
                    len(args[3:]) % 2 == 0 and all(args[n] == '--item' for n in range(3, len(args), 2)),
                    'storage_selection', 'Confirm the exact previewed cleanup items')
            result = storage.cleanup(engine, args[2], args[4::2])
            # Cleanup has already completed. A failed audit copy must retain the
            # successful result so a lost reply cannot invite a fresh deletion.
            result['receipt_persistence_errors'] = []
            for p in (base / 'receipts').glob('*.json'):
                try:
                    atomic_json(c.state / 'storage/receipts' / p.name, read_json(storage.plain(p)))
                except OSError:
                    result['receipt_persistence_errors'].append(p.name)
        else:
            require(False, 'storage_arguments', 'Operation is not exposed by the backup bridge')
        result['bridge'] = {'signed': True, 'session_id': session, 'metadata_location': 'tmpfs', 'runtime_installed': False}
        return result
    finally:
        storage.ledger = original
