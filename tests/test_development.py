# SPDX-License-Identifier: GPL-3.0-only
import shutil
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from armhpc_ota.device import check_gate, discover, layout
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json
from support import fixture, release, boot_fixture


class DevelopmentAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.config, self.key = fixture(self.temp.name)
        self.config.hardware_policy = 'development'
        self.engine = Engine(self.config)
        path, self.manifest = release(self.config, self.key)
        self.engine.manifest(location=str(path))
        device = discover(self.config); device['simulated_gate'] = False
        atomic_json(self.config.simulate / 'device.json', device)

    def test_write_authorization_never_claims_hardware_acceptance(self):
        gate = check_gate(self.config, discover(self.config))
        self.assertFalse(gate['passed'])
        self.assertFalse(gate['hardware_verified'])
        self.assertTrue(gate['write_allowed'])
        self.assertEqual('development', gate['policy'])
        self.assertTrue(self.engine.status()['write_authorized'])

    def test_development_enables_apply_without_fabricating_a_certificate(self):
        self.assertFalse((self.config.state / 'hardware-gate.json').exists())
        self.assertTrue(self.engine.plan(self.manifest)['write_allowed'])
        self.assertEqual('queued', self.engine.apply(self.manifest)['stage'])
        self.assertEqual('awaiting-rescue', self.engine.worker()['stage'])

    def test_default_verified_policy_still_refuses_unaccepted_hardware(self):
        self.config.hardware_policy = 'verified'
        self.assertFalse(self.engine.plan(self.manifest)['write_allowed'])
        with self.assertRaises(OTAError):
            self.engine.apply(self.manifest)

    def test_other_architecture_cannot_reuse_oect_development_authorization(self):
        device = discover(self.config); device['architecture'] = 'armhf'
        with self.assertRaises(OTAError):
            check_gate(self.config, device)

    def test_mounted_running_root_still_cannot_be_written(self):
        self.engine.apply(self.manifest, 'system'); self.engine.worker()
        # Deliberately leave the SATA root active but lie about the environment marker.
        device = discover(self.config); device['mode'] = 'rescue'
        atomic_json(self.config.simulate / 'device.json', device)
        self.assertEqual('failed-recoverable', self.engine.worker()['stage'])
        self.assertFalse(self.engine.store.read()['write_started'])

    def test_development_setting_is_preserved_in_installed_roots(self):
        storage = layout(self.config, discover(self.config), True)
        root = self.config.simulate / 'new-config'
        (root / 'etc').mkdir(parents=True)
        self.engine.backend.configure_shared_mount(root, storage, 'system')
        from armhpc_ota.io import read_json
        self.assertEqual('development', read_json(root / 'etc/armhpc/ota.json')['hardware_policy'])

    def test_bundled_assets_are_verified_and_reused_without_network(self):
        item = self.manifest['artifacts'][0]
        self.config.bootstrap_assets.mkdir()
        source = self.config.simulate / 'release' / ('r2-' + item['role'])
        bundled = self.config.bootstrap_assets / item['sha256']
        shutil.copy2(source, bundled)
        self.engine.prime_bootstrap_asset(item)
        self.assertEqual(bundled.stat().st_ino, (self.config.cache / item['sha256']).stat().st_ino)
        with patch.object(self.engine.transport, 'open', side_effect=AssertionError('network used')):
            self.assertTrue(self.engine.transport.download(item, self.config.cache).is_file())

    def test_corrupt_bundled_assets_do_not_gain_trust_from_development_policy(self):
        item = self.manifest['artifacts'][0]
        self.config.bootstrap_assets.mkdir()
        (self.config.bootstrap_assets / item['sha256']).write_bytes(b'corrupt')
        with self.assertRaises(OTAError):
            self.engine.prime_bootstrap_asset(item)
