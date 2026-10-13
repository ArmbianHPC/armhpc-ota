# SPDX-License-Identifier: GPL-3.0-only
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from armhpc_ota.boot import select, verify_boot
from armhpc_ota.device import discover, layout, ensure_unmounted
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json, read_json
from armhpc_ota.metadata import sign, verify, validate_manifest
from armhpc_ota import preserve
from support import fixture, release, boot_fixture


class EngineTests(unittest.TestCase):
    def test_wwn_change_is_refused_before_writing(self):
        device = read_json(self.config.simulate / 'device.json')
        disk = next(item for item in device['blocks'] if item.get('type') == 'disk' and item.get('tran') == 'sata')
        disk['wwn'] = '0x5000000000000001'
        atomic_json(self.config.simulate / 'device.json', device)
        job = self.engine.apply(self.manifest)
        disk['wwn'] = '0x5000000000000002'
        atomic_json(self.config.simulate / 'device.json', device)
        stored = self.engine.store.read(job['job_id'])
        with self.assertRaisesRegex(OTAError, 'Physical disk changed'):
            self.engine._recheck(stored)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config, self.key = fixture(self.temporary.name)
        self.engine = Engine(self.config)
        self.path, self.manifest = release(self.config, self.key)
        self.engine.manifest(location=str(self.path))

    def change_device(self, **updates):
        value = read_json(self.config.simulate / 'device.json')
        value.update(updates)
        atomic_json(self.config.simulate / 'device.json', value)

    def test_complete_all_preserves_user_data_and_trials_rescue_first(self):
        job = self.engine.apply(self.manifest)
        self.assertEqual('queued', job['stage'])
        self.assertEqual('awaiting-rescue', self.engine.worker()['stage'])
        boot_fixture(self.config, 'rescue', 'a', '6.12.111-old')
        self.assertEqual('trial-rescue', self.engine.worker()['stage'])
        chosen = select(self.config)
        self.assertEqual('b', chosen['slot']); verify_boot(self.config, chosen)
        boot_fixture(self.config, 'rescue', 'b', '6.13.1-test')
        self.assertEqual('ready', self.engine.confirm()['stage'])
        self.assertEqual('trial-system', self.engine.worker()['stage'])
        chosen = select(self.config); self.assertEqual('system', chosen['target'])
        boot_fixture(self.config, 'system', kernel='6.13.1-test')
        self.assertEqual('succeeded', self.engine.confirm()['stage'])
        self.assertEqual('DATA-MUST-NOT-CHANGE', (self.config.simulate / 'data/keep.txt').read_text())
        self.assertEqual('user-file', (self.config.simulate / 'roots/system/home/admin/keep.txt').read_text())
        self.assertFalse(self.engine.store.control()['system_blocked'])

    def test_failed_rescue_trial_falls_back_once_and_stays_rescue(self):
        boot_fixture(self.config, 'rescue', 'a')
        self.engine.apply(self.manifest, 'rescue'); self.engine.worker()
        self.assertEqual('b', select(self.config)['slot'])
        self.assertEqual('a', select(self.config)['slot'])
        self.assertEqual('failed-recoverable', self.engine.store.read()['stage'])
        self.assertEqual('a', select(self.config)['slot'])

    def test_failed_normal_trial_never_retries_half_updated_root(self):
        boot_fixture(self.config, 'rescue', 'a')
        self.engine.apply(self.manifest, 'system'); self.engine.worker()
        self.assertEqual('system', select(self.config)['target'])
        self.assertEqual('rescue', select(self.config)['target'])
        self.assertTrue(self.engine.store.control()['system_blocked'])
        self.assertEqual('rescue', select(self.config)['target'])

    def test_power_loss_during_normal_write_stays_confirmed_rescue(self):
        boot_fixture(self.config, 'rescue', 'a')
        self.change_device(fault='write-system')
        self.engine.apply(self.manifest, 'system')
        self.assertEqual('failed-recoverable', self.engine.worker()['stage'])
        self.assertEqual('rescue', select(self.config)['target'])

    def test_health_kernel_mismatch_is_not_confirmed(self):
        boot_fixture(self.config, 'rescue', 'a')
        self.engine.apply(self.manifest, 'system'); self.engine.worker(); select(self.config)
        boot_fixture(self.config, 'system', kernel='wrong-kernel')
        self.assertEqual('failed-recoverable', self.engine.confirm()['stage'])

    def test_cancel_before_write_and_refuse_after_write(self):
        self.engine.apply(self.manifest)
        self.assertEqual('cancelled', self.engine.cancel()['stage'])
        self.engine.apply(self.manifest, 'system'); self.engine.worker()
        boot_fixture(self.config, 'rescue', 'a'); self.engine.worker()
        with self.assertRaisesRegex(OTAError, 'cannot be cancelled'):
            self.engine.cancel()

    def test_only_one_persistent_task(self):
        self.engine.apply(self.manifest)
        with self.assertRaisesRegex(OTAError, 'active OTA job'):
            self.engine.apply(self.manifest)

    def test_disconnect_does_not_delete_queued_job(self):
        self.engine.apply(self.manifest)
        replacement = Engine(self.config)
        self.assertEqual('awaiting-rescue', replacement.worker()['stage'])

    def test_wrong_board_arch_layout_and_distro_refused(self):
        for field, bad in [('board', 'wrong-board'), ('architecture', 'armhf'), ('layout', 'wrong-layout')]:
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest); manifest[field] = bad
                with self.assertRaises(OTAError):
                    self.engine.plan(manifest)
        with self.assertRaises(OTAError):
            validate_manifest({**self.manifest, 'distribution': 'trixie'})

    def test_duplicate_label_refused(self):
        device = discover(self.config)
        node = copy.deepcopy(next(item for item in device['blocks'] if item.get('label') == 'OECT_ROOT'))
        node['path'] = '/dev/sdb1'; device['blocks'].append(node)
        atomic_json(self.config.simulate / 'device.json', device)
        with self.assertRaisesRegex(OTAError, 'Duplicate'):
            self.engine.plan(self.manifest)

    def test_protected_data_boot_shared_and_running_root_refused(self):
        device = discover(self.config)
        storage = layout(self.config, device, True)
        for role in ('data', 'boot', 'shared', 'system'):
            with self.subTest(role=role), self.assertRaises(OTAError):
                ensure_unmounted(self.config, device, storage['partitions'][role])

    def test_payload_too_large_refused_before_job_creation(self):
        self.manifest['artifacts'][0]['expanded_size'] = 65 * 1024**3
        with self.assertRaises(OTAError):
            self.engine.apply(self.manifest)
        self.assertIsNone(self.engine.store.read())

    def test_missing_gate_blocks_apply_but_status_and_plan_explain(self):
        self.change_device(simulated_gate=False)
        self.assertFalse(self.engine.status()['hardware_gate']['passed'])
        self.assertFalse(self.engine.plan(self.manifest)['write_allowed'])
        with self.assertRaises(OTAError):
            self.engine.apply(self.manifest)

    def test_corrupt_download_prevents_job(self):
        item = self.manifest['artifacts'][0]
        Path(item['url'].replace('file:///', '/', 1)).write_bytes(b'corrupt') if __import__('os').name != 'nt' else None
        item['sha256'] = '1' * 64
        # A persistent task exists, but no partition is ever written.
        self.path.write_bytes(sign(self.manifest, self.key, 'test'))
        (self.config.state / 'manifests/r2.json').write_bytes(self.path.read_bytes())
        self.engine.apply(self.manifest)
        self.assertEqual('failed-recoverable', self.engine.worker()['stage'])
        self.assertFalse(self.engine.store.read()['write_started'])

    def test_tampered_persistent_manifest_is_reverified(self):
        self.engine.apply(self.manifest)
        job = self.engine.store.read(); job['manifest']['release'] = 'tampered'
        self.engine.store.save(job)
        self.assertEqual('failed-recoverable', self.engine.worker()['stage'])

    def test_raw_initramfs_rejects_uimage_header(self):
        selected = select(self.config)
        reference = selected['boot']['initramfs']
        path = self.config.state / reference['path']
        path.write_bytes(bytes.fromhex('27051956') + b'broken')
        with self.assertRaises(OTAError):
            verify_boot(self.config, selected)

    def test_recovery_requires_rescue_and_explicit_compatible_version(self):
        with self.assertRaises(OTAError):
            self.engine.apply(self.manifest, 'system', recovery=True)
        control = self.engine.store.control(); control['highest_sequence'] = 9
        self.engine.store.write_control(control)
        boot_fixture(self.config, 'rescue', 'a')
        with self.assertRaises(OTAError):
            self.engine.plan(self.manifest, 'system')
        self.assertEqual('queued', self.engine.apply(self.manifest, 'system', recovery=True)['stage'])

    def test_public_json_does_not_expose_password_hashes(self):
        self.engine.apply(self.manifest); self.engine.worker()
        text = json.dumps(self.engine.status())
        self.assertNotIn('secret-test-hash', text); self.assertNotIn('admin-hash', text)

    def test_no_sata_rescue_only_supported(self):
        device = discover(self.config)
        device['blocks'] = [item for item in device['blocks'] if not item['path'].startswith('/dev/sd')]
        atomic_json(self.config.simulate / 'device.json', device)
        boot_fixture(self.config, 'rescue', 'a')
        self.assertEqual('queued', self.engine.apply(self.manifest, 'rescue')['stage'])
        self.assertEqual('trial-rescue', self.engine.worker()['stage'])

    def test_restore_conflicting_user_id_is_refused(self):
        root = self.config.simulate / 'roots/system'
        accounts = preserve.accounts(root)
        (root / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\nother:x:1000:1000::/:/bin/sh\n')
        with self.assertRaises(OTAError):
            preserve.validate_accounts(accounts, root)


if __name__ == '__main__':
    unittest.main()
