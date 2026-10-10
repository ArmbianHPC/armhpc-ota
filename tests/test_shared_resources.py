# SPDX-License-Identifier: GPL-3.0-only
"""Role isolation, signed resource checks and old-baseline retention."""
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from armhpc_ota import maintenance, shared_resources
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json
from armhpc_ota.lan_publish import tools_bundle
import test_lan


def add_resources(payload):
    rows = []
    for scope, name in [('common', 'clock_floor'), ('board', 'phy_leds'),
                        ('rescue', 'rescue_menu'), ('normal', 'kube_setup')]:
        source = payload / 'compat/framework' / scope / (name + '.py')
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('# signed ' + scope + '\n', encoding='utf-8')
        rows.append({'scope': scope, 'target': 'usr/lib/armhpc/' + name + '.py',
                     'source': source.relative_to(payload).as_posix(),
                     'sha256': hashlib.sha256(source.read_bytes()).hexdigest()})
    atomic_json(payload / 'compat/framework-files.json', {'protocol': 1, 'files': rows})
    return rows


class SharedResourcesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.payload = Path(self.tmp.name)
        self.rows = add_resources(self.payload)

    def test_roles_exclude_other_environment_commands(self):
        normal = shared_resources.files(self.payload, 'system')
        rescue = shared_resources.files(self.payload, 'rescue_b')
        self.assertIn('usr/lib/armhpc/kube_setup.py', normal)
        self.assertNotIn('usr/lib/armhpc/rescue_menu.py', normal)
        self.assertIn('usr/lib/armhpc/rescue_menu.py', rescue)
        self.assertNotIn('usr/lib/armhpc/kube_setup.py', rescue)
        self.assertIn('usr/lib/armhpc/phy_leds.py', normal)
        self.assertIn('usr/lib/armhpc/clock_floor.py', rescue)

    def test_damaged_resource_is_refused(self):
        (self.payload / self.rows[1]['source']).write_text('changed', encoding='utf-8')
        with self.assertRaises(OTAError):
            shared_resources.files(self.payload, 'system')

    def test_config_write_escape_and_duplicate_are_refused(self):
        for changes in ({'target': 'etc/shadow'}, {'source': '../outside'},
                        {'target': self.rows[0]['target']}):
            rows = json.loads(json.dumps(self.rows))
            rows[1].update(changes)
            atomic_json(self.payload / 'compat/framework-files.json', {'protocol': 1, 'files': rows})
            with self.subTest(changes=changes), self.assertRaises(OTAError):
                shared_resources.files(self.payload, 'rescue_a')

    def test_symlink_resource_is_refused(self):
        source = self.payload / self.rows[1]['source']
        destination = source.with_suffix('.saved')
        source.rename(destination)
        source.symlink_to(destination)
        with self.assertRaises(OTAError):
            shared_resources.files(self.payload, 'system')


class SharedMaintenanceTests(unittest.TestCase):
    def setUp(self):
        test_lan.MaintenanceTests.setUp(self)
        payload = self.root / 'pkg/armhpc-ota-0.3.0'
        add_resources(payload)
        runtime = self.root / 'with-shared.tar.xz'
        with tarfile.open(runtime, 'w:xz') as archive:
            for p in payload.rglob('*'):
                if p.is_file():
                    archive.add(p, arcname='armhpc-ota-0.3.0/' + p.relative_to(payload).as_posix())
        self.bundle = Path(tools_bundle(runtime, self.root / 'shared-published', self.key, 'test')['bundle'])

    def test_all_roots_and_old_baseline_keep_matching_role_code(self):
        maintenance.schedule(self.e, self.bundle)
        self.assertEqual('succeeded', maintenance.worker(self.e)['maintenance']['stage'])
        for role in ('rescue_a', 'rescue_b', 'system'):
            root = self.root / 'roots' / role
            name = 'kube_setup' if role == 'system' else 'rescue_menu'
            other = 'rescue_menu' if role == 'system' else 'kube_setup'
            p = root / 'usr/lib/armhpc' / (name + '.py')
            self.assertTrue(p.is_file())
            self.assertFalse((root / 'usr/lib/armhpc' / (other + '.py')).exists())
            if role.startswith('rescue'):
                marker = root / 'etc/armhpc/rescue-environment'
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.touch()
            p.write_text('# old baseline', encoding='utf-8')
            (root / 'usr/lib/armhpc-ota/armhpc_ota/__init__.py').write_text('__version__="0.2.0"\n', encoding='utf-8')
            maintenance.retain_installed_runtime(self.c, root)
            self.assertIn('signed', p.read_text(encoding='utf-8'))
        maintenance.schedule(self.e, rollback=True)
        self.assertEqual('rolled-back', maintenance.worker(self.e)['maintenance']['stage'])
        self.assertFalse((self.root / 'roots/system/usr/lib/armhpc/kube_setup.py').exists())

    def test_symlink_target_parent_never_writes_outside_root(self):
        root = self.root / 'roots/rescue_a'
        outside = self.root / 'outside'
        outside.mkdir()
        parent = root / 'usr/lib/armhpc'
        parent.parent.mkdir(parents=True, exist_ok=True)
        parent.symlink_to(outside, target_is_directory=True)
        maintenance.schedule(self.e, self.bundle)
        result = maintenance.worker(self.e)
        self.assertEqual('incomplete', result['maintenance']['stage'])
        self.assertEqual([], list(outside.iterdir()))


if __name__ == '__main__':
    unittest.main()
