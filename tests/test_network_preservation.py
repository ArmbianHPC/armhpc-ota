# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

from armhpc_ota import preserve
from armhpc_ota.boot import select
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json, read_json
from support import fixture, release, boot_fixture

FRAMEWORK = Path(__file__).resolve().parents[2] / 'armbian-hpc/components/common/rootfs-overlay/usr/lib/armhpc'


class NetworkPreservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config, key = fixture(self.temp.name)
        self.engine = Engine(self.config)
        path, self.manifest = release(self.config, key)
        self.engine.manifest(location=str(path))
        self.root = self.config.simulate / 'roots/system'
        self.rescue = self.config.simulate / 'roots/rescue_a'
        self.dhcp = '[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n'
        self.put(self.rescue, 'etc/systemd/network/10-rescue.network', self.dhcp)
        self.original_write = self.engine.backend.write_image

    @staticmethod
    def put(root, name, value):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        return path

    def managed_static(self):
        api = runpy.run_path(str(FRAMEWORK / 'network_config.py'))
        for directory in ('proc/sys/kernel/random', 'sys/class/net/eth0/device'):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / 'proc/sys/kernel/random/boot_id').write_text('before-upgrade')
        (self.root / 'sys/class/net/eth0/carrier').write_text('1')
        network = api['Network'](self.root)
        settings = api['settings']('eth0', address='192.168.100.20/24', gateway='192.168.100.1',
                                   dns=['192.168.100.1'], management=True, metric=100,
                                   management_target='192.168.100.101', route_table=100,
                                   source='192.168.100.20/32')
        pending = network.submit(settings)
        network.apply(pending['transaction_id'])
        network.confirm(pending['transaction_id'])
        return api, self.saved_files(self.root)

    @staticmethod
    def saved_files(root):
        paths = [*(root / 'etc/systemd/network').rglob('*'),
                 root / 'etc/armhpc/management-network.json',
                 root / 'var/lib/armhpc/network-config/transaction.json']
        return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in paths if p.is_file()}

    def image_with_dhcp(self, artifact, partition, progress=None):
        self.original_write(artifact, partition, progress)
        destination = self.config.simulate / 'roots' / partition['fixture_role']
        self.put(destination, 'etc/systemd/network/10-new-default.network', self.dhcp)

    def assert_static(self, saved):
        self.assertEqual(saved, self.saved_files(self.root))
        self.assertFalse((self.root / 'etc/systemd/network/10-new-default.network').exists())
        self.assertEqual(self.dhcp, (self.rescue / 'etc/systemd/network/10-rescue.network').read_text())
        self.assertEqual('DATA-MUST-NOT-CHANGE', (self.config.simulate / 'data/keep.txt').read_text())

    def test_all_upgrade_keeps_system_static_and_rescue_dhcp_separate(self):
        api, saved = self.managed_static()
        self.engine.apply(self.manifest, 'all')
        self.assertEqual('awaiting-rescue', self.engine.worker()['stage'])
        boot_fixture(self.config, 'rescue', 'a', '6.12.111-old')
        with patch.object(self.engine.backend, 'write_image', side_effect=self.image_with_dhcp):
            self.assertEqual('trial-rescue', self.engine.worker()['stage'])
            select(self.config)
            boot_fixture(self.config, 'rescue', 'b', '6.13.1-test')
            self.assertEqual('ready', self.engine.confirm()['stage'])
            self.assertEqual('trial-system', self.engine.worker()['stage'])
        select(self.config)
        boot_fixture(self.config, 'system', kernel='6.13.1-test')
        self.assertEqual('succeeded', self.engine.confirm()['stage'])
        (self.root / 'proc/sys/kernel/random').mkdir(parents=True, exist_ok=True)
        (self.root / 'proc/sys/kernel/random/boot_id').write_text('after-upgrade')
        api['Network'](self.root).recover_on_boot()
        self.assert_static(saved)
        self.assertEqual(self.dhcp, (self.config.simulate / 'roots/rescue_b/etc/systemd/network/10-rescue.network').read_text())

    def test_recovery_from_rescue_preserves_confirmed_static_gateway_dns_and_policy(self):
        _, saved = self.managed_static()
        boot_fixture(self.config, 'rescue', 'a')
        self.engine.apply(self.manifest, 'system', recovery=True)
        with patch.object(self.engine.backend, 'write_image', side_effect=self.image_with_dhcp):
            self.assertEqual('trial-system', self.engine.worker()['stage'])
        self.assert_static(saved)

    def test_manual_networkd_profile_is_not_shadowed_by_new_image_dhcp_defaults(self):
        path = self.put(self.root, 'etc/systemd/network/50-site.network',
                        '[Match]\nName=eth0\n\n[Network]\nAddress=192.168.100.20/24\nGateway=192.168.100.1\nDNS=192.168.100.1\n')
        saved = self.saved_files(self.root)
        boot_fixture(self.config, 'rescue', 'a')
        self.engine.apply(self.manifest, 'system')
        with patch.object(self.engine.backend, 'write_image', side_effect=self.image_with_dhcp):
            self.assertEqual('trial-system', self.engine.worker()['stage'])
        self.assert_static(saved)
        self.assertTrue(path.exists())

    def test_resume_after_root_write_uses_original_network_snapshot(self):
        _, saved = self.managed_static()
        boot_fixture(self.config, 'rescue', 'a')
        self.engine.apply(self.manifest, 'system')
        original_restore = self.engine.backend.restore
        with patch.object(self.engine.backend, 'write_image', side_effect=self.image_with_dhcp), \
             patch.object(self.engine.backend, 'restore', side_effect=KeyboardInterrupt('interrupted after write')):
            with self.assertRaises(KeyboardInterrupt):
                self.engine.worker()
        self.assertTrue((self.root / 'etc/systemd/network/10-new-default.network').is_file())
        with patch.object(self.engine.backend, 'restore', side_effect=original_restore):
            self.assertEqual('trial-system', self.engine.worker()['stage'])
        self.assert_static(saved)

    def test_unconfirmed_network_change_blocks_upgrade_before_writing(self):
        self.managed_static()
        transaction = self.root / 'var/lib/armhpc/network-config/transaction.json'
        row = read_json(transaction)
        row['stage'] = 'pending'
        atomic_json(transaction, row)
        with patch.object(self.engine.backend, 'write_image') as write:
            with self.assertRaisesRegex(OTAError, 'Confirm or roll back'):
                self.engine.apply(self.manifest, 'all')
            write.assert_not_called()

    def test_manual_dns_network_manager_and_netplan_resources_are_restored(self):
        files = {
            'etc/resolv.conf': 'nameserver 192.168.100.1\nsearch site.example\n',
            'etc/systemd/resolved.conf.d/site.conf': '[Resolve]\nDNS=192.168.100.1\n',
            'etc/NetworkManager/system-connections/site.nmconnection': '[ipv4]\nmethod=manual\naddress1=192.168.100.20/24,192.168.100.1\n',
            'etc/netplan/50-site.yaml': 'network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses: [192.168.100.20/24]\n',
            'etc/network/interfaces.d/site': 'iface eth0 inet static\n address 192.168.100.20/24\n',
        }
        for name, text in files.items():
            self.put(self.root, name, text)
        backup = self.config.cache / 'manual-network'
        preserve.snapshot(self.root, backup, [], simulate=True)
        destination = self.config.simulate / 'restored'
        (destination / 'etc').mkdir(parents=True)
        for name in ('passwd', 'shadow', 'group', 'gshadow'):
            (destination / 'etc' / name).write_text('')
        self.put(destination, 'etc/netplan/10-dhcp.yaml', 'network: {version: 2}\n')
        self.put(destination, 'etc/NetworkManager/system-connections/dhcp.nmconnection', '[ipv4]\nmethod=auto\n')
        preserve.restore(backup, destination)
        for name, text in files.items():
            self.assertEqual(text, (destination / name).read_text(), name)
        self.assertFalse((destination / 'etc/netplan/10-dhcp.yaml').exists())
        self.assertFalse((destination / 'etc/NetworkManager/system-connections/dhcp.nmconnection').exists())


    def restore_destination(self, backup):
        preserve.snapshot(self.root, backup, [], simulate=True)
        destination = self.config.simulate / 'network-restore'
        (destination / 'etc').mkdir(parents=True)
        for name in ('passwd', 'shadow', 'group', 'gshadow'):
            (destination / 'etc' / name).write_text('')
        return destination

    def test_new_image_defaults_remain_when_no_old_network_directory_exists(self):
        backup = self.config.cache / 'no-network-profile'
        destination = self.restore_destination(backup)
        default = self.put(destination, 'etc/systemd/network/10-dhcp.network', self.dhcp)
        preserve.restore(backup, destination)
        self.assertEqual(self.dhcp, default.read_text())

    def test_network_directory_symlink_does_not_delete_an_external_directory(self):
        self.put(self.root, 'etc/systemd/network/50-site.network', '[Network]\nAddress=192.168.100.20/24\n')
        backup = self.config.cache / 'network-link-boundary'
        destination = self.restore_destination(backup)
        external = self.config.simulate / 'outside-network'
        external.mkdir()
        marker = external / 'must-remain'
        marker.write_text('outside target root')
        (destination / 'etc/systemd').mkdir()
        (destination / 'etc/systemd/network').symlink_to(external, target_is_directory=True)
        preserve.restore(backup, destination)
        self.assertEqual('outside target root', marker.read_text())
        self.assertFalse((destination / 'etc/systemd/network').is_symlink())
        self.assertTrue((destination / 'etc/systemd/network/50-site.network').is_file())
