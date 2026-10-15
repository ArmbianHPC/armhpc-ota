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
    for target in sorted(shared_resources.COMPLETION_TARGETS):
        source = payload / 'compat/framework/completion' / target
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('# signed completion resource\n', encoding='utf-8')
        rows.append({'scope': 'common', 'target': target, 'source': source.relative_to(payload).as_posix(),
                     'sha256': hashlib.sha256(source.read_bytes()).hexdigest()})
    atomic_json(payload / 'compat/framework-files.json', {'protocol': 1, 'files': rows})
    return rows


class SharedResourcesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.payload = Path(self.tmp.name)
        self.rows = add_resources(self.payload)

    def test_explicit_boards_select_matching_code_and_reject_collisions(self):
        rows=[row for row in self.rows if row['scope']!='board']
        for board in ('wxy-oect-original','wxy-oesp-v22'):
            source=self.payload/'compat/framework/boards'/board/'phy_leds.py'
            source.parent.mkdir(parents=True);source.write_text('# '+board+'\n')
            rows.append({'scope':'board','board':board,'target':'usr/lib/armhpc/phy_leds.py',
                         'source':source.relative_to(self.payload).as_posix(),
                         'sha256':hashlib.sha256(source.read_bytes()).hexdigest()})
        atomic_json(self.payload/'compat/framework-files.json',{'protocol':1,'files':rows})
        self.assertNotIn('usr/lib/armhpc/phy_leds.py',shared_resources.files(self.payload,'system'))
        for board in ('wxy-oect-original','wxy-oesp-v22'):
            chosen=shared_resources.files(self.payload,'system',board)
            self.assertIn(board,chosen['usr/lib/armhpc/phy_leds.py'].read_text())
        rows.append(dict(rows[-1]))
        atomic_json(self.payload/'compat/framework-files.json',{'protocol':1,'files':rows})
        with self.assertRaises(OTAError):shared_resources.files(self.payload,'system','wxy-oesp-v22')

    def test_roles_exclude_other_environment_commands(self):
        normal = shared_resources.files(self.payload, 'system')
        rescue = shared_resources.files(self.payload, 'rescue_b')
        self.assertIn('usr/lib/armhpc/kube_setup.py', normal)
        self.assertNotIn('usr/lib/armhpc/rescue_menu.py', normal)
        self.assertIn('usr/lib/armhpc/rescue_menu.py', rescue)
        self.assertNotIn('usr/lib/armhpc/kube_setup.py', rescue)
        self.assertIn('usr/lib/armhpc/phy_leds.py', normal)
        self.assertIn('usr/lib/armhpc/clock_floor.py', rescue)

    def test_shared_kernel_baseline_is_signed_and_common_to_all_roots(self):
        source=self.payload/'compat/framework/data/kernel-baseline.json';source.parent.mkdir(parents=True)
        source.write_text('{"schema_version":1,"requirements":{"CONFIG_CFS_BANDWIDTH":["y"]}}')
        rows=[*self.rows,{'scope':'common','target':'usr/lib/armhpc/kernel-baseline.json',
              'source':source.relative_to(self.payload).as_posix(),'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}]
        atomic_json(self.payload/'compat/framework-files.json',{'protocol':1,'files':rows})
        for role in ('system','rescue_a','rescue_b'):
            self.assertIn('usr/lib/armhpc/kernel-baseline.json',shared_resources.files(self.payload,role))
        rows[-1]['scope']='normal'
        atomic_json(self.payload/'compat/framework-files.json',{'protocol':1,'files':rows})
        with self.assertRaises(OTAError):shared_resources.files(self.payload,'system')

    def test_completion_resources_are_shared_and_have_exact_allowed_targets(self):
        for role in ('system', 'rescue_a', 'rescue_b'):
            selected = shared_resources.files(self.payload, role)
            self.assertTrue(shared_resources.COMPLETION_TARGETS.issubset(selected))
        for target in ('etc/profile.d/other.sh', 'usr/lib/armhpc/other.bash',
                       'usr/share/bash-completion/completions/other'):
            rows = json.loads(json.dumps(self.rows))
            rows[-1]['target'] = target
            atomic_json(self.payload / 'compat/framework-files.json', {'protocol': 1, 'files': rows})
            with self.subTest(target=target), self.assertRaises(OTAError):
                shared_resources.files(self.payload, 'system')

    def test_completion_hash_and_common_scope_are_required(self):
        rows = json.loads(json.dumps(self.rows))
        rows[-1]['scope'] = 'normal'
        atomic_json(self.payload / 'compat/framework-files.json', {'protocol': 1, 'files': rows})
        with self.assertRaises(OTAError):
            shared_resources.files(self.payload, 'system')
        atomic_json(self.payload / 'compat/framework-files.json', {'protocol': 1, 'files': self.rows})
        (self.payload / self.rows[-1]['source']).write_text('changed')
        with self.assertRaises(OTAError):
            shared_resources.files(self.payload, 'system')

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
            for target in shared_resources.COMPLETION_TARGETS:
                completion = root / target
                self.assertEqual(completion.read_text(), '# signed completion resource\n')
                completion.write_text('# old completion')
            if role.startswith('rescue'):
                marker = root / 'etc/armhpc/rescue-environment'
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.touch()
            p.write_text('# old baseline', encoding='utf-8')
            (root / 'usr/lib/armhpc-ota/armhpc_ota/__init__.py').write_text('__version__="0.2.0"\n', encoding='utf-8')
            maintenance.retain_installed_runtime(self.c, root)
            self.assertIn('signed', p.read_text(encoding='utf-8'))
            for target in shared_resources.COMPLETION_TARGETS:
                self.assertEqual((root / target).read_text(), '# signed completion resource\n')
        maintenance.schedule(self.e, rollback=True)
        self.assertEqual('rolled-back', maintenance.worker(self.e)['maintenance']['stage'])
        self.assertFalse((self.root / 'roots/system/usr/lib/armhpc/kube_setup.py').exists())
        for role in ('system', 'rescue_a', 'rescue_b'):
            for target in shared_resources.COMPLETION_TARGETS:
                self.assertFalse((self.root / 'roots' / role / target).exists())

    def test_existing_completion_content_and_mode_are_restored_on_rollback(self):
        for role in ('system', 'rescue_a', 'rescue_b'):
            path = self.root / 'roots' / role / 'etc/profile.d/armhpc-completion.sh'
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('previous completion\n')
            path.chmod(0o600)
        maintenance.schedule(self.e, self.bundle)
        self.assertEqual('succeeded', maintenance.worker(self.e)['maintenance']['stage'])
        maintenance.schedule(self.e, rollback=True)
        self.assertEqual('rolled-back', maintenance.worker(self.e)['maintenance']['stage'])
        for role in ('system', 'rescue_a', 'rescue_b'):
            path = self.root / 'roots' / role / 'etc/profile.d/armhpc-completion.sh'
            self.assertEqual(path.read_text(), 'previous completion\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

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
