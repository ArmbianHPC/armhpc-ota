# SPDX-License-Identifier: GPL-3.0-only
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from armhpc_ota.backend import Backend
from armhpc_ota.bootstrap import execute, preview
from armhpc_ota.boot import select, fallback
from armhpc_ota.device import discover
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json, read_json
from armhpc_ota.metadata import sign, anchor_digest
from support import fixture, release, boot_fixture


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.config, self.key = fixture(self.temp.name)
        self.engine = Engine(self.config)
        path, self.manifest = release(self.config, self.key)
        self.engine.manifest(location=str(path))

    def test_power_loss_in_write_resumes_from_rescue_without_booting_partial_system(self):
        boot_fixture(self.config, 'rescue', 'a')
        self.engine.apply(self.manifest, 'system')
        with patch.object(self.engine.backend, 'write_image', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.engine.worker()
        self.assertEqual('deploying-system', self.engine.store.read()['stage'])
        self.assertEqual('rescue', select(self.config)['target'])
        self.assertEqual('trial-system', Engine(self.config).worker()['stage'])

    def test_cancellation_during_download_is_processed_before_disk_writing(self):
        self.engine.apply(self.manifest)
        original = self.engine.transport.download
        requested = []
        def intercepted(*args, **kwargs):
            if not requested:
                requested.append(self.engine.cancel()['stage'])
            return original(*args, **kwargs)
        with patch.object(self.engine.transport, 'download', side_effect=intercepted):
            self.assertEqual('cancelled', self.engine.worker()['stage'])
        self.assertEqual(['cancel-requested'], requested)
        self.assertFalse(self.engine.store.read()['write_started'])

    def test_changed_partition_uuid_refused_before_write(self):
        self.engine.apply(self.manifest)
        device = discover(self.config)
        next(item for item in device['blocks'] if item.get('fixture_role') == 'system')['uuid'] = 'changed-disk'
        atomic_json(self.config.simulate / 'device.json', device)
        self.assertEqual('failed-recoverable', self.engine.worker()['stage'])
        self.assertFalse(self.engine.store.read()['write_started'])

    def test_partition_overlap_refused(self):
        device = discover(self.config)
        next(item for item in device['blocks'] if item.get('fixture_role') == 'rescue_b')['start'] = 2048
        atomic_json(self.config.simulate / 'device.json', device)
        with self.assertRaises(OTAError): self.engine.plan(self.manifest)

    def test_control_corruption_still_allows_verified_slot_local_fallback(self):
        self.engine.download(self.manifest, 'rescue')
        job = {'release': 'r2', 'manifest': self.manifest}
        partition = next(item for item in discover(self.config)['blocks'] if item.get('fixture_role') == 'rescue_b')
        self.engine.backend.boot_files(job, 'rescue', partition)
        (self.config.state / 'control.json').write_bytes(b'corrupt')
        copy = self.config.simulate / 'roots/rescue_b/usr/lib/armhpc-ota/boot'
        selected, files = fallback(copy / 'manifest.json', copy, self.config.trust, slot='b')
        self.assertEqual('b', selected['slot'])
        files['kernel'].write_bytes(b'corrupt')
        with self.assertRaises(OTAError): fallback(copy / 'manifest.json', copy, self.config.trust, slot='b')

    def test_crash_after_health_record_before_control_commit_is_reconciled(self):
        boot_fixture(self.config, 'rescue', 'a')
        self.engine.apply(self.manifest, 'system'); self.engine.worker(); select(self.config)
        job = self.engine.store.read(); self.engine.store.checkpoint(job, 'system-health-passed')
        self.assertEqual('system', select(self.config)['target'])
        boot_fixture(self.config, 'system', kernel='6.13.1-test')
        self.assertEqual('succeeded', self.engine.confirm()['stage'])

    def test_one_boot_rescue_request_returns_to_normal_afterwards(self):
        self.engine.request_rescue_boot()
        self.assertEqual('rescue', select(self.config)['target'])
        self.assertEqual('system', select(self.config)['target'])

    def test_initial_baseline_not_overwritten_by_later_confirmed_release(self):
        initial = {'release': 'r1', 'target': 'rescue'}
        atomic_json(self.config.state / 'baselines/initial.json', initial)
        boot_fixture(self.config, 'rescue', 'a')
        self.engine.apply(self.manifest, 'rescue'); self.engine.worker(); select(self.config)
        boot_fixture(self.config, 'rescue', 'b', '6.13.1-test'); self.engine.confirm()
        self.assertEqual(initial, read_json(self.config.state / 'baselines/initial.json'))
        self.assertEqual('r2', read_json(self.config.state / 'baselines/current-rescue.json')['release'])

    def test_bootstrap_is_idempotent_and_keeps_a_uuid(self):
        # Remove only the fixture partitions, then exercise append-only migration.
        device = discover(self.config)
        a_uuid = next(item['uuid'] for item in device['blocks'] if item.get('fixture_role') == 'rescue_a')
        device['blocks'] = [item for item in device['blocks'] if item.get('fixture_role') not in ('rescue_b', 'shared')]
        atomic_json(self.config.simulate / 'device.json', device)
        anchor_items = []
        for name in ('kernel', 'initramfs', 'dtb'):
            path = self.config.simulate / 'release' / ('anchor-' + name)
            path.write_bytes(('raw-' + name).encode())
            anchor_items.append({'id': name, 'url': path.as_uri(), 'size': path.stat().st_size,
                                 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        anchor = {'kind': 'anchor', 'board': 'wxy-oect-original', 'anchor_abi': 'armhpc-anchor-v1',
                  'anchor_sha256': anchor_digest(anchor_items), 'artifacts': anchor_items, 'trusted_key_ids': ['test']}
        path = self.config.simulate / 'release/anchor.json'; path.write_bytes(sign(anchor, self.key, 'test'))
        self.engine.download(self.manifest)
        self.assertTrue(execute(self.engine, self.manifest, str(path))['complete'])
        self.assertTrue(execute(self.engine, self.manifest, str(path))['already_initialized'])
        self.assertEqual(a_uuid, next(item['uuid'] for item in discover(self.config)['blocks'] if item.get('fixture_role') == 'rescue_a'))
        self.assertIn('admin:x:1000:1000:', (self.config.simulate / 'roots/rescue_b/etc/passwd').read_text())
        self.assertEqual('user-file', (self.config.simulate / 'roots/rescue_b/home/admin/keep.txt').read_text())
