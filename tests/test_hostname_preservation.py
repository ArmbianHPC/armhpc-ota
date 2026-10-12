# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Normal-system hostname/config preservation through update and recovery."""
import json
from pathlib import Path
import tempfile
import unittest
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from armhpc_ota import preserve
from armhpc_ota.io import atomic_json
from support import fixture, release, boot_fixture


class HostnamePreservationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.config, self.key = fixture(temp.name)
        self.engine = Engine(self.config)
        self.location, self.manifest = release(self.config, self.key)
        self.engine.manifest(location=str(self.location))
        self.root = self.config.simulate / 'roots/system'
        (self.root / 'etc/hostname').write_text('cluster-node-07\n')
        (self.root / 'etc/hosts').write_text('127.0.1.1 cluster-node-07\n10.1.1.2 storage\n')
        network = self.root / 'etc/systemd/network'
        network.mkdir(parents=True)
        (network / '00-armhpc-eth0.network').write_text('[Network]\nAddress=192.168.1.9/24\n')

    def test_plan_advertises_hostname_only_for_system(self):
        for target in ('system', 'rescue', 'all'):
            plan = self.engine.plan(self.manifest, target)
            self.assertEqual('etc/hostname' in plan['preserve'], target != 'rescue')
            if target != 'rescue':
                self.assertIn('etc/hosts', plan['preserve_by_target']['system'])
            if target != 'system':
                self.assertNotIn('etc/hostname', plan['preserve_by_target']['rescue'])

    def test_system_update_preserves_hostname_hosts_and_network(self):
        job = self.engine.apply(self.manifest, 'system')
        self.assertEqual(self.engine.worker()['stage'], 'awaiting-rescue')
        boot_fixture(self.config, 'rescue', 'a')
        self.assertEqual(self.engine.worker()['stage'], 'trial-system')
        self.assertEqual((self.root / 'etc/hostname').read_text(), 'cluster-node-07\n')
        self.assertIn('10.1.1.2 storage', (self.root / 'etc/hosts').read_text())
        self.assertTrue((self.root / 'etc/systemd/network/00-armhpc-eth0.network').is_file())
        inventory = self.engine.store.read()['inventory']
        self.assertIn('etc/hostname', inventory['paths'])

    def test_failed_deployment_recovery_reuses_the_original_hostname_snapshot(self):
        boot_fixture(self.config, 'rescue', 'a')
        device = json.loads((self.config.simulate / 'device.json').read_text())
        device['fault'] = 'write-system'
        atomic_json(self.config.simulate / 'device.json', device)
        self.engine.apply(self.manifest, 'system')
        failed = self.engine.worker()
        self.assertEqual(failed['stage'], 'failed-recoverable')
        original = failed['snapshot']
        (self.root / 'etc/hostname').write_text('half-updated-wrong\n')
        device.pop('fault')
        atomic_json(self.config.simulate / 'device.json', device)
        recovered = self.engine.apply(self.manifest, 'system', recovery=True)
        self.assertEqual(recovered['snapshot'], original)
        self.assertEqual(self.engine.worker()['stage'], 'trial-system')
        self.assertEqual((self.root / 'etc/hostname').read_text(), 'cluster-node-07\n')

    def test_rescue_preservation_does_not_copy_its_hostname_or_hosts(self):
        root = self.config.simulate / 'roots/rescue_a'
        (root / 'etc/hostname').write_text('armhpc-rescue-abcd\n')
        (root / 'etc/hosts').write_text('127.0.1.1 armhpc-rescue-abcd\n')
        _, inventory = self.engine.backend.preserve({'job_id': 'rescue-only', 'manifest': self.manifest}, root, 'rescue')
        self.assertNotIn('etc/hostname', inventory['paths'])
        self.assertNotIn('etc/hosts', inventory['paths'])

    def test_pending_network_change_blocks_admission_and_offline_preservation(self):
        atomic_json(self.root / 'var/lib/armhpc/network-config/transaction.json', {'stage': 'pending'})
        with self.assertRaises(OTAError) as error:
            self.engine.apply(self.manifest, 'system')
        self.assertEqual(error.exception.code, 'network_pending')
        self.assertIsNone(self.engine.store.read())
        with self.assertRaises(OTAError):
            self.engine.backend.preserve({'job_id': 'pending-network', 'manifest': self.manifest}, self.root)


if __name__ == '__main__':
    unittest.main()
