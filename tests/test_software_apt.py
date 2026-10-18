# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

from armhpc_ota.backend import software_install_arguments, verify_software_plan
from armhpc_ota.errors import OTAError


@unittest.skipUnless(os.name == 'posix' and all(shutil.which(p) for p in
                    ('apt-get', 'dpkg-deb', 'dpkg-scanpackages')), 'Requires Debian APT tools')
class OfflineAptPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='armhpc-apt-')
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        for name in ('state/lists/partial', 'cache/archives/partial'):
            (self.root / name).mkdir(parents=True)
        (self.root / 'status').write_text('')
        self.options = ['-o', 'Debug::NoLocking=1', '-o', 'APT::Sandbox::User=root',
                        '-o', 'Dir::State=' + str(self.root / 'state'),
                        '-o', 'Dir::State::status=' + str(self.root / 'status'),
                        '-o', 'Dir::Cache=' + str(self.root / 'cache'),
                        '-o', 'Dir::Etc::sourcelist=' + str(self.root / 'sources.list'),
                        '-o', 'Dir::Etc::sourceparts=-', '-o', 'Dir::Etc::preferences=/dev/null',
                        '-o', 'Dir::Etc::preferencesparts=-']
        (self.root / 'sources.list').write_text('deb [trusted=yes] file:' + str(self.repo) + ' ./\n')
        self.core = self.package('armhpc-core', '1.0')
        self.extra = self.package('armhpc-recommendation', '1.0')
        self.main = self.package('armhpc-preserved', '1.0',
                                 'Depends: armhpc-core (>= 1.0)\nRecommends: armhpc-recommendation\n')
        self.package('armhpc-required', '1.0')
        self.required = self.package('armhpc-needs-dependency', '1.0', 'Depends: armhpc-required\n')
        index = self.run_command(['dpkg-scanpackages', '.', '/dev/null'], cwd=self.repo)
        (self.repo / 'Packages').write_text(index)
        self.run_command(['apt-get', *self.options, 'update'])

    def tearDown(self):
        self.temp.cleanup()

    def run_command(self, command, **kwargs):
        result = subprocess.run(command, text=True, capture_output=True, timeout=30,
                                env={**os.environ, 'LC_ALL': 'C.UTF-8'}, **kwargs)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def package(self, name, version, dependencies=''):
        tree = self.root / (name + '-source')
        (tree / 'DEBIAN').mkdir(parents=True)
        (tree / 'DEBIAN/control').write_text('Package: ' + name + '\nVersion: ' + version +
            '\nArchitecture: all\nMaintainer: ARMHPC\n' + dependencies + 'Description: isolated APT fixture\n')
        output = self.repo / (name + '_' + version + '_all.deb')
        self.run_command(['dpkg-deb', '--build', str(tree), str(output)])
        return str(output)

    def plan(self, packages, fixed=True):
        args = software_install_arguments(packages, simulate=True)
        if not fixed:
            args.remove('--no-install-recommends')
        return self.run_command([args[0], *self.options, *args[1:]])

    def test_recommendation_is_not_added_but_explicitly_preserved_one_is_restored(self):
        available = {('armhpc-preserved', '1.0'), ('armhpc-core', '1.0')}
        legacy = self.plan([self.main, self.core], fixed=False)
        self.assertIn('Inst armhpc-recommendation ', legacy)
        with self.assertRaises(OTAError):
            verify_software_plan(legacy, available)
        current = self.plan([self.main, self.core])
        self.assertNotIn('Inst armhpc-recommendation ', current)
        verify_software_plan(current, available)
        explicit = self.plan([self.main, self.core, self.extra])
        self.assertIn('Inst armhpc-recommendation ', explicit)
        verify_software_plan(explicit, available | {('armhpc-recommendation', '1.0')})

    def test_required_dependency_remains_an_exact_resource_requirement(self):
        plan = self.plan([self.required])
        self.assertIn('Inst armhpc-required ', plan)
        with self.assertRaises(OTAError) as error:
            verify_software_plan(plan, {('armhpc-needs-dependency', '1.0')})
        self.assertEqual(error.exception.details['missing_packages'],
                         [{'package': 'armhpc-required', 'version': '1.0'}])
