# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
from armhpc_ota import storage
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json, sha256, read_json
from support import fixture


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.c, _ = fixture(self.root, mode='rescue')
        self.e = Engine(self.c)
        self.cache = self.c.state / 'cache'
        self.cache.mkdir()
        self.id = str(uuid.uuid4())
        self.backup = self.cache / 'boot-backups' / self.id
        self.backup.mkdir(parents=True)
        (self.backup / 'BOOT-original.img').write_bytes(b'private boot bytes')
        (self.backup / 'entries').mkdir()
        (self.backup / 'entries/boot.scr').write_bytes(b'original boot script')
        self.task = {'task_id': self.id, 'device_id': 'device-001', 'stage': 'rolled-back',
                     'bundle': str(self.cache / 'boot-maintenance' / ('b' * 64) / 'bundle.tar.xz'),
                     'backups': {'BOOT-original.img': {'bytes': 18, 'sha256': sha256(self.backup / 'BOOT-original.img')}},
                     'entry_hashes': {'boot.scr': sha256(self.backup / 'entries/boot.scr')}}
        self.task['backups']['BOOT-original.img']['bytes'] = (self.backup / 'BOOT-original.img').stat().st_size
        atomic_json(self.c.state / 'boot-maintenance/task.json', self.task)
        self.group = storage.status(self.e)['backups'][0]['id']

    def tearDown(self):
        self.temp.cleanup()

    def aged(self, path):
        old = time.time() - 7200
        if path.is_dir():
            for item in path.rglob('*'):
                os.utime(item, (old, old), follow_symlinks=False)
        os.utime(path, (old, old), follow_symlinks=False)
        return path

    def test_export_is_original_bytes_and_does_not_create_an_archive(self):
        result = storage.export(self.e, self.group)
        inventory = result['inventory']
        self.assertEqual(storage.digest(inventory), result['inventory_sha256'])
        path, item = storage.export_file(self.c, result['inventory_sha256'], 'BOOT-original.img')
        self.assertEqual(b'private boot bytes', path.read_bytes())
        self.assertEqual(sha256(path), item['sha256'])
        self.assertEqual([], list((self.c.state / 'storage').rglob('*.zip')))
        self.assertFalse(storage.status(self.e)['backups'][0]['exported'])

    def test_acknowledged_completed_backup_can_be_removed_but_history_is_retained(self):
        before = storage.cleanup_plan(self.e)
        self.assertNotIn(str(self.backup), [i['path'] for i in before['items']])
        prepared = storage.export(self.e, self.group)
        storage.acknowledge(self.e, prepared['inventory_sha256'], 'c' * 64)
        plan = storage.cleanup_plan(self.e)
        self.assertIn(str(self.backup), [i['path'] for i in plan['items']])
        result = storage.cleanup(self.e, plan['plan_id'])
        self.assertTrue(result['history_retained'])
        self.assertFalse(self.backup.exists())
        self.assertEqual(self.task, read_json(self.c.state / 'boot-maintenance/task.json'))
        self.assertTrue((self.c.state / 'storage/receipts' / (self.group + '.json')).exists())
        self.assertEqual('DATA-MUST-NOT-CHANGE', (self.root / 'data/keep.txt').read_text())

    def test_failed_export_or_changed_backup_does_not_authorize_deletion(self):
        p = storage.export(self.e, self.group)
        (self.backup / 'BOOT-original.img').write_bytes(b'changed')
        with self.assertRaises(OTAError):
            storage.acknowledge(self.e, p['inventory_sha256'], 'c' * 64)
        self.assertNotIn(str(self.backup), [i['path'] for i in storage.cleanup_plan(self.e)['items']])
        self.assertTrue(self.backup.exists())

    def test_export_rejects_backup_different_from_original_task_hash(self):
        (self.backup / 'BOOT-original.img').write_bytes(b'changed')
        with self.assertRaisesRegex(OTAError, 'differs'):
            storage.export(self.e, self.group)

    def test_current_tool_rollback_backup_is_kept_even_after_export(self):
        p = self.c.state / 'maintenance/backups' / self.id
        p.mkdir(parents=True)
        (p / 'old-agent.py').write_text('previous runtime')
        atomic_json(self.c.state / 'maintenance/task.json', {'task_id': self.id, 'stage': 'succeeded'})
        group = next(g for g in storage.status(self.e)['backups'] if g['kind'] == 'tools')
        prepared = storage.export(self.e, group['id'])
        storage.acknowledge(self.e, prepared['inventory_sha256'], 'c' * 64)
        self.assertNotIn(str(p), [i['path'] for i in storage.cleanup_plan(self.e)['items']])

    def test_unknown_historical_backup_is_exportable_but_not_removable(self):
        atomic_json(self.c.state / 'boot-maintenance/task.json', {**self.task, 'task_id': str(uuid.uuid4())})
        prepared = storage.export(self.e, self.group)
        storage.acknowledge(self.e, prepared['inventory_sha256'], 'c' * 64)
        self.assertNotIn(str(self.backup), [i['path'] for i in storage.cleanup_plan(self.e)['items']])

    def test_stale_download_and_upload_cleaning_retains_recent_and_unknown_files(self):
        old = self.cache / ('a' * 64)
        old.write_bytes(b'stale download')
        self.aged(old)
        recent = self.cache / ('d' * 64)
        recent.write_bytes(b'new download')
        unknown = self.cache / 'operator-file'
        unknown.write_bytes(b'must remain')
        p = self.root / 'tmp' / ('armhpc-ota-upload-' + 'a' * 32)
        p.mkdir(parents=True)
        (p / 'boot-update.tar.xz').write_bytes(b'old upload')
        self.aged(p)
        baseline = self.c.state / 'baselines/factory-rootfs'
        baseline.parent.mkdir(parents=True, exist_ok=True)
        baseline.write_text('must remain')
        plan = storage.cleanup_plan(self.e)
        self.assertEqual({str(old), str(p)}, {i['path'] for i in plan['items']})
        storage.cleanup(self.e, plan['plan_id'])
        self.assertTrue(recent.exists() and unknown.exists() and baseline.exists())
        self.assertFalse(old.exists() or p.exists())

    def test_bound_boot_payload_is_retained_but_unreferenced_staging_is_reclaimed(self):
        bound = Path(self.task['bundle']).parent
        bound.mkdir(parents=True)
        (bound / 'kernel').write_bytes(b'needed for rollback')
        loose = bound.parent / ('e' * 64)
        loose.mkdir()
        (loose / '.system-rootfs.partial').write_bytes(b'incomplete')
        self.aged(bound); self.aged(loose)
        plan = storage.cleanup_plan(self.e)
        self.assertEqual([str(loose)], [i['path'] for i in plan['items']])
        storage.cleanup(self.e, plan['plan_id'])
        self.assertTrue(bound.exists())

    def test_changed_plan_or_new_active_task_refuses_before_deletion(self):
        p = self.cache / ('a' * 64)
        p.write_bytes(b'old'); self.aged(p)
        plan = storage.cleanup_plan(self.e)
        p.write_bytes(b'changed'); self.aged(p)
        with self.assertRaisesRegex(OTAError, 'review'):
            storage.cleanup(self.e, plan['plan_id'])
        self.assertTrue(p.exists())
        plan = storage.cleanup_plan(self.e)
        atomic_json(self.c.state / 'boot-maintenance/task.json', {**self.task, 'stage': 'preparing'})
        with self.assertRaisesRegex(OTAError, 'BOOT task'):
            storage.cleanup(self.e, plan['plan_id'])
        self.assertTrue(p.exists())

    def test_recoverable_ota_and_incomplete_tools_block_cleanup(self):
        with patch.object(self.e.store, 'read', return_value={'stage': 'failed-recoverable'}):
            with self.assertRaisesRegex(OTAError, 'recover'):
                storage.cleanup_plan(self.e)
        atomic_json(self.c.state / 'maintenance/task.json', {'stage': 'incomplete'})
        with self.assertRaisesRegex(OTAError, 'tool maintenance'):
            storage.cleanup_plan(self.e)

    def test_symlinked_staging_is_kept_and_cannot_delete_external_files(self):
        outside = self.root / 'outside'
        outside.write_text('keep')
        link = self.cache / ('f' * 64)
        link.symlink_to(outside)
        plan = storage.cleanup_plan(self.e)
        self.assertEqual([], plan['items'])
        self.assertTrue(outside.exists())
        (self.backup / 'external').symlink_to(outside)
        with self.assertRaises(OTAError):
            storage.export(self.e, self.group)

    def test_acknowledgment_and_file_names_cannot_escape_export_scope(self):
        prepared = storage.export(self.e, self.group)
        for name in ('../control.json', '/etc/shadow', 'entries/../../identity.json'):
            with self.assertRaises(OTAError):
                storage.export_file(self.c, prepared['inventory_sha256'], name)
        with self.assertRaises(OTAError):
            storage.acknowledge(self.e, '../control', 'c' * 64)
        with self.assertRaises(OTAError):
            storage.acknowledge(self.e, prepared['inventory_sha256'], 'invalid')

    def test_upload_preflight_checks_capacity_and_creates_private_directory(self):
        with patch('armhpc_ota.bootstrap_space.prepare_cache') as cache:
            result = storage.stage(self.e, 100)
        cache.assert_called_once()
        p = Path(result['directory'])
        self.assertTrue(p.is_relative_to(self.c.cache))
        self.assertEqual(0o700, p.stat().st_mode & 0o777)
        with patch('armhpc_ota.storage.shutil.disk_usage', return_value=shutil_usage(0)):
            with self.assertRaises(OTAError) as caught:
                storage.stage(self.e, 100)
        self.assertEqual('storage_space', caught.exception.code)
        self.assertEqual(100 + 64 * 1024**2, caught.exception.details['required_bytes'])

    def test_system_can_report_storage_but_cannot_export_or_clean(self):
        p = self.root / 'device.json'
        value = read_json(p);value['mode'] = 'system';atomic_json(p, value)
        self.assertEqual('system', storage.status(self.e)['mode'])
        with self.assertRaises(OTAError):storage.export(self.e, self.group)
        with self.assertRaises(OTAError):storage.cleanup_plan(self.e)

    def test_serial_export_transfers_raw_bytes_without_device_compression(self):
        from armhpc_ota.serial_stream import PREFIX
        prepared = storage.export(self.e, self.group)
        size = (self.backup / 'BOOT-original.img').stat().st_size
        output = io.BytesIO()
        source = io.BytesIO(json.dumps({'operation':'ack', 'offset':size}).encode() + b'\n')
        storage.stream_export(self.c, prepared['inventory_sha256'], 'BOOT-original.img', 0, source, output)
        frames = [json.loads(line.removeprefix(PREFIX)) for line in output.getvalue().decode().splitlines()]
        import base64
        self.assertEqual(b'private boot bytes', base64.b64decode(frames[1]['data']))
        self.assertEqual('verified', frames[-1]['state'])


    def bridge(self, args, session=None, yes=False):
        from armhpc_ota.storage_bridge import dispatch
        return dispatch(self.e, {'session_id':session or self.id,'device_id':'device-001','arguments':args,'yes':yes})

    def test_zero_space_bridge_exports_to_ram_and_cleans_only_after_host_receipt(self):
        from armhpc_ota import storage_bridge
        original = atomic_json
        def no_shared_writes(path, value):
            if Path(path).is_relative_to(self.c.state):
                raise OSError(28, 'No space left on device')
            return original(path, value)
        before = {str(p.relative_to(self.c.state)):p.read_bytes() for p in self.c.state.rglob('*') if p.is_file()}
        with patch.object(storage, 'atomic_json', side_effect=no_shared_writes), patch.object(storage_bridge, 'atomic_json', side_effect=no_shared_writes):
            self.bridge(['status'])
            exported = self.bridge(['export','--backup-id',self.group])
            self.assertEqual('tmpfs', exported['bridge']['metadata_location'])
            self.assertFalse((self.c.state/'storage').exists())
            self.assertEqual(before, {str(p.relative_to(self.c.state)):p.read_bytes() for p in self.c.state.rglob('*') if p.is_file()})
            plan = self.bridge(['plan'])
            self.assertNotIn(str(self.backup), [i['path'] for i in plan['items']])
            self.bridge(['acknowledge','--inventory-sha256',exported['inventory_sha256'],'--archive-sha256','c'*64])
            plan = self.bridge(['plan']);item = next(i for i in plan['items'] if i['path']==str(self.backup))
            result = self.bridge(['cleanup','--plan-id',plan['plan_id'],'--item',item['id']],yes=True)
            self.assertGreater(result['removed_bytes'],0)
            self.assertEqual([self.group+'.json'], result['receipt_persistence_errors'])
        self.assertFalse(self.backup.exists())
        self.assertEqual(self.task,read_json(self.c.state/'boot-maintenance/task.json'))
        self.assertEqual(storage.ledger(self.c),self.c.state/'storage')

    def test_bridge_uses_private_session_and_refuses_cross_session_acknowledgment(self):
        exported=self.bridge(['export','--backup-id',self.group])
        with self.assertRaises((OSError,OTAError)):
            self.bridge(['acknowledge','--inventory-sha256',exported['inventory_sha256'],'--archive-sha256','c'*64],session=str(uuid.uuid4()))
        with self.assertRaises(OTAError):self.bridge(['export','--backup-id',self.group],session='../other')
        p=self.root/'run/storage-bridge'/self.id
        self.assertEqual(0o700,p.stat().st_mode&0o777)
        self.assertEqual('device-001',read_json(p/'session.json')['device_id'])

    def test_bridge_requires_explicit_selected_cleanup_and_retains_active_task(self):
        with self.assertRaises(OTAError):self.bridge(['cleanup','--plan-id','a'*64],yes=True)
        with self.assertRaises(OTAError):self.bridge(['cleanup','--plan-id','a'*64,'--item','b'*64])
        atomic_json(self.c.state/'boot-maintenance/task.json',{**self.task,'stage':'prepared'})
        with self.assertRaises(OTAError):self.bridge(['plan'])
        self.assertTrue(self.backup.is_dir())


def shutil_usage(free):
    from collections import namedtuple
    return namedtuple('usage', 'total used free')(1024**3, 0, free)
