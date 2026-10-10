# SPDX-License-Identifier: GPL-3.0-only
import copy
import io
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch
from contextlib import redirect_stdout
from armhpc_ota.cli import main
from armhpc_ota.config import Config
from armhpc_ota.engine import Engine
from armhpc_ota.boot import select
from armhpc_ota.device import discover, layout
from armhpc_ota.deployment import ledger
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json, read_json
from armhpc_ota import preserve
from armhpc_ota.store import Store
from support import fixture, release, boot_fixture


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config, self.key = fixture(self.temp.name)
        self.engine = Engine(self.config)
        path, self.manifest = release(self.config, self.key)
        self.engine.manifest(location=str(path))
        boot_fixture(self.config, 'rescue', 'a')

    def corrupt_filesystem(self, role):
        device = discover(self.config)
        node = next(node for node in device['blocks'] if node.get('fixture_role') == role)
        node.update(label=None, uuid=None, fstype=None)
        atomic_json(self.config.simulate / 'device.json', device)

    def interrupt(self, role, exception=KeyboardInterrupt):
        target = 'system' if role == 'system' else 'rescue'
        self.engine.apply(self.manifest, target)
        def failed(*args, **kwargs):
            self.corrupt_filesystem(role)
            raise exception('interrupted filesystem stream')
        with patch.object(self.engine.backend, 'write_image', side_effect=failed):
            if exception is KeyboardInterrupt:
                with self.assertRaises(KeyboardInterrupt):
                    self.engine.worker()
            else:
                self.assertEqual('failed-recoverable', self.engine.worker()['stage'])

    def test_interrupted_superblock_is_found_by_durable_guid_intent(self):
        original = layout(self.config, discover(self.config), True)['partitions']['system']['uuid']
        self.interrupt('system')
        self.assertEqual('rescue', select(self.config)['target'])
        restored = layout(self.config, discover(self.config), True)['partitions']['system']
        self.assertEqual(original, restored['uuid'])
        self.assertEqual('trial-system', Engine(self.config).worker()['stage'])
        self.assertEqual({}, ledger(self.config)['targets'])

    def test_changed_disk_is_not_adopted_by_write_intent(self):
        self.interrupt('system')
        device = discover(self.config)
        next(node for node in device['blocks'] if node['path'] == '/dev/sda')['serial'] = 'a-replacement-disk'
        atomic_json(self.config.simulate / 'device.json', device)
        self.assertEqual('failed-recoverable', Engine(self.config).worker()['stage'])
        self.assertEqual('target_changed', self.engine.store.read()['error']['code'])

    def test_protected_data_label_cannot_be_reclassified_as_system(self):
        self.interrupt('system')
        device = discover(self.config)
        next(node for node in device['blocks'] if node.get('fixture_role') == 'system')['label'] = 'OECT_DATA'
        atomic_json(self.config.simulate / 'device.json', device)
        with self.assertRaises(OTAError):
            self.engine.plan(self.manifest, 'system', True)

    def test_missing_guid_cannot_be_recovered_using_a_disk_path_alone(self):
        self.interrupt('system')
        device = discover(self.config)
        next(node for node in device['blocks'] if node.get('fixture_role') == 'system')['partuuid'] = 'different-guid'
        atomic_json(self.config.simulate / 'device.json', device)
        self.assertEqual('failed-recoverable', self.engine.worker()['stage'])

    def test_unknown_unlabelled_root_without_write_intent_is_refused(self):
        self.corrupt_filesystem('system')
        with self.assertRaises(OTAError):
            self.engine.plan(self.manifest, 'system', True)

    def test_failed_deployment_reuses_prewrite_user_backup(self):
        self.interrupt('system', OSError)
        old = self.engine.store.read()['snapshot']
        # The on-disk root is now corrupt, so a fresh root snapshot is unavailable.
        job = self.engine.apply(self.manifest, 'system', True)
        self.assertEqual(old, job['snapshot'])
        self.assertEqual('trial-system', self.engine.worker()['stage'])
        self.assertEqual('user-file', (self.config.simulate / 'roots/system/home/admin/keep.txt').read_text())
        self.assertEqual('DATA-MUST-NOT-CHANGE', (self.config.simulate / 'data/keep.txt').read_text())

    def test_missing_preserved_resources_refused_before_new_recovery_job(self):
        self.interrupt('system', OSError)
        old = self.engine.store.read()
        (Path(old['snapshot']) / 'selected.tar').write_bytes(b'corrupt')
        with self.assertRaises(OTAError):
            self.engine.apply(self.manifest, 'system', True)
        self.assertEqual(old['job_id'], self.engine.store.read()['job_id'])

    def test_trial_job_written_before_control_switch_is_resumed(self):
        self.engine.apply(self.manifest, 'system')
        original = self.engine.store.write_control
        def interrupted(control):
            if control.get('trial'):
                raise KeyboardInterrupt()
            return original(control)
        with patch.object(self.engine.store, 'write_control', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.engine.worker()
        self.assertEqual('trial-system', self.engine.store.read()['stage'])
        self.assertIsNone(self.engine.store.control()['trial'])
        self.assertEqual('trial-system', self.engine.confirm()['stage'])
        self.assertEqual('trial-system', self.engine.worker()['stage'])
        self.assertEqual('system', select(self.config)['target'])

    def baseline(self):
        path = self.config.simulate / 'release/r1.manifest.json'
        manifest = self.engine.manifest(location=str(path))
        self.engine.download(manifest)
        for target in ('system', 'rescue'):
            self.engine.backend.baseline({'release': 'r1', 'manifest': manifest}, target)
        return manifest

    def test_initial_and_current_baseline_resolve_without_an_index(self):
        self.baseline()
        with patch.object(self.engine.transport, 'metadata', side_effect=AssertionError('network was contacted')):
            self.assertEqual('r1', self.engine.manifest('initial', target='system', recovery=True)['release'])
            self.assertEqual('r1', self.engine.manifest('current', target='all', recovery=True)['release'])
        self.assertEqual(['rescue', 'system'], read_json(self.config.state / 'baselines/initial.json')['targets'])

    def test_missing_cache_is_repopulated_from_signed_offline_baseline(self):
        manifest = self.baseline()
        for path in self.config.cache.iterdir():
            if path.is_file():
                path.unlink()
        with patch.object(self.engine.transport, 'open', side_effect=AssertionError('network was contacted')):
            self.assertTrue(self.engine.download(manifest)['verified'])

    def test_corrupt_offline_baseline_is_rejected_without_network_fallback(self):
        manifest = self.baseline()
        item = manifest['artifacts'][0]
        (self.config.cache / item['sha256']).unlink()
        (self.config.state / 'baselines/releases/r1' / item['sha256']).write_bytes(b'corrupt')
        with self.assertRaises(OTAError):
            self.engine.download(manifest)

    def test_mixed_current_baselines_require_separate_targets(self):
        self.baseline()
        atomic_json(self.config.state / 'baselines/current-rescue.json', {'release': 'r2', 'target': 'rescue'})
        with self.assertRaises(OTAError):
            self.engine.manifest('current', target='all', recovery=True)

    def test_recovery_without_explicit_version_is_refused(self):
        with self.assertRaises(OTAError):
            self.engine.manifest(recovery=True)

    def test_cli_can_preview_local_initial_baseline(self):
        self.baseline()
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(['plan', '--release', 'initial', '--target', 'system', '--recovery',
                         '--simulate-root', self.temp.name, '--json'])
        self.assertEqual(0, code, output.getvalue())

    def test_k3s_data_bindings_and_enable_state_are_preserved(self):
        root = self.config.simulate / 'roots/system'
        (root / 'etc/fstab').write_text('/data/kubelet /var/lib/kubelet none bind 0 0\n'
                                        '/data/node-config/k3s/node /etc/rancher/node none bind 0 0\n')
        (root / 'etc/rancher/node').mkdir(parents=True)
        (root / 'etc/rancher/node/do-not-backup-data').write_text('DATA')
        wanted = root / 'etc/systemd/system/multi-user.target.wants'
        wanted.mkdir(parents=True)
        (wanted / 'k3s.service').symlink_to('../k3s.service')
        backup = self.config.cache / 'test-preserve'
        inventory = preserve.snapshot(root, backup, [], simulate=True)
        self.assertEqual(['k3s.service'], inventory['enabled_services'])
        self.assertEqual(2, len(inventory['data_bindings']))
        target = self.config.simulate / 'restored'
        (target / 'etc').mkdir(parents=True)
        for name in ('passwd', 'shadow', 'group', 'gshadow'):
            (target / 'etc' / name).write_text('')
        preserve.restore(backup, target)
        self.assertFalse((target / 'etc/rancher/node/do-not-backup-data').exists())
        self.assertIn('requires-mounts-for=/data', (target / 'etc/fstab').read_text())

    def test_external_binding_is_refused(self):
        root = self.config.simulate / 'roots/system'
        (root / 'etc/fstab').write_text('/dev/sdb1 /etc/rancher/node ext4 defaults 0 0\n')
        with self.assertRaises(OTAError):
            preserve.snapshot(root, self.config.cache / 'invalid-bind', [], simulate=True)

    def test_same_request_id_returns_the_existing_job_and_restarts_worker(self):
        request = str(uuid.uuid4())
        with patch.object(self.engine.backend, 'start_service') as service:
            first = self.engine.apply(self.manifest, 'system', request_id=request)
            second = self.engine.apply(self.manifest, 'system', request_id=request)
            self.assertEqual(2, service.call_count)
        self.assertEqual(request, first['job_id'])
        self.assertEqual(first['job_id'], second['job_id'])
        self.assertEqual(1, len(list((self.config.state / 'jobs').glob('*.json'))))

    def test_request_id_cannot_be_reused_for_another_target(self):
        request = str(uuid.uuid4())
        self.engine.apply(self.manifest, 'system', request_id=request)
        with self.assertRaises(OTAError):
            self.engine.apply(self.manifest, 'rescue', request_id=request)

    def test_cli_submission_retry_keeps_the_same_job_after_disconnect(self):
        request = str(uuid.uuid4())
        output = io.StringIO()
        arguments = ['apply', '--target', 'system', '--request-id', request, '--manifest',
                     str(self.config.simulate / 'release/r2.manifest.json'), '--simulate-root',
                     self.temp.name, '--json', '--yes']
        with redirect_stdout(output):
            self.assertEqual(0, main(arguments))
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, main(arguments))
        self.assertEqual(request, __import__('json').loads(output.getvalue())['data']['job_id'])

    def test_simulation_cannot_use_root_or_external_symlink_directories(self):
        with self.assertRaises(OTAError):
            Config.load(simulate=Path(self.temp.name).anchor)
        directory = self.config.simulate / 'unsafe-fixture'
        directory.mkdir()
        (directory / 'roots').symlink_to(self.config.simulate / 'roots', target_is_directory=True)
        with self.assertRaises(OTAError):
            Config.load(simulate=directory)

    def test_rescue_survives_missing_shared_mount_but_system_requires_shared(self):
        storage = layout(self.config, discover(self.config), True)
        for target in ('system', 'rescue'):
            root = self.config.simulate / ('mount-config-' + target)
            (root / 'etc').mkdir(parents=True)
            (root / 'etc/fstab').write_text('')
            self.engine.backend.configure_shared_mount(root, storage, target,
                                                      storage['partitions']['rescue_a'] if target == 'rescue' else None)
            line = next(line for line in (root / 'etc/fstab').read_text().splitlines()
                        if '/var/lib/armhpc/ota' in line)
            self.assertEqual(target == 'rescue', 'nofail' in line)

    def test_cached_named_manifest_can_resubmit_without_a_live_index(self):
        with patch.object(self.engine.transport, 'metadata', side_effect=AssertionError('network was contacted')):
            self.assertEqual('r2', self.engine.manifest('r2')['release'])

    def test_global_writer_lock_survives_state_mount_path_changes(self):
        lock = self.config.simulate / 'runtime/global.lock'
        first = Store(self.config.state, lock)
        second = Store(self.config.simulate / 'another-mounted-state', lock)
        with first.lock(), self.assertRaises(OTAError):
            with second.lock():
                self.fail('second writer admitted')
