# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Check that Linux controller build inputs and shipped sources are identical."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/build-linux-cli.py'
spec = importlib.util.spec_from_file_location('linux_cli_packager', SCRIPT)
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


@unittest.skipUnless(shutil.which('git'), 'Git is required for committed-source fixtures')
class LinuxCliPackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.real_run = subprocess.run
        self.git('init', '--quiet')
        self.git('config', 'user.name', 'ARMHPC fixture')
        self.git('config', 'user.email', 'fixture@armhpc.invalid')
        self.git('config', 'core.autocrlf', 'false')
        files = {
            'VERSION': '1.0.1\n',
            'LICENSE': 'license fixture\n',
            'COPYRIGHT': 'copyright fixture\n',
            'THIRD-PARTY-NOTICES.md': 'dependency notice fixture\n',
            'LICENSES/GPL-3.0-only.txt': 'license fixture\n',
            'DEPENDENCIES.lock.json': '{}\n',
            'windows/ArmHpc.Ota.Cli/ArmHpc.Ota.Cli.csproj': '<Project/>\n',
            'windows/ArmHpc.Ota.Cli/Program.cs': 'committed program\n',
            'src/armhpc_ota/__init__.py': '__version__ = "1.0.1"\n',
            'tools/build-linux-cli.py': SCRIPT.read_text(encoding='utf-8'),
        }
        for name, content in files.items():
            self.write(name, content)
        self.commit()
        self.head = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        result = self.real_run(['git', '-C', str(self.repo), *args], text=True, capture_output=True, check=True)
        return result.stdout.strip()

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8', newline='\n')

    def commit(self):
        self.git('add', '-A')
        self.git('commit', '--quiet', '-m', 'Source fixture')

    def build(self, **kwargs):
        with patch.object(packager, '__file__', str(self.repo / 'tools/build-linux-cli.py')):
            return packager.build(self.root / 'package.tar.gz', self.root / 'work', **kwargs)

    def test_tracked_change_is_refused_before_any_build_output(self):
        self.write('VERSION', '1.0.2\n')
        with self.assertRaisesRegex(ValueError, 'clean committed checkout'):
            self.build()
        self.assertFalse((self.root / 'work').exists())
        self.assertFalse((self.root / 'package.tar.gz').exists())

    def test_staged_change_is_refused_before_any_build_output(self):
        self.write('VERSION', '1.0.2\n')
        self.git('add', 'VERSION')
        with self.assertRaisesRegex(ValueError, 'clean committed checkout'):
            self.build()
        self.assertFalse((self.root / 'work').exists())

    def test_untracked_source_is_refused_before_any_build_output(self):
        self.write('windows/ArmHpc.Ota.Cli/NewFeature.cs', 'new code\n')
        with self.assertRaisesRegex(ValueError, 'clean committed checkout'):
            self.build()
        self.assertFalse((self.root / 'work').exists())

    def test_a_different_committed_ref_is_refused(self):
        self.write('VERSION', '1.0.2\n')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'differs from HEAD'):
            self.build(source_ref=self.head)
        self.assertFalse((self.root / 'work').exists())

    def test_build_and_source_archive_stay_bound_when_live_head_changes(self):
        self.git('tag', 'v1.0.1')
        expected_program = (self.repo / 'windows/ArmHpc.Ota.Cli/Program.cs').read_bytes()
        expected_python = (self.repo / 'src/armhpc_ota/__init__.py').read_bytes()
        publishes = []

        def run(command, **kwargs):
            if command[0] != 'dotnet':
                return self.real_run(command, **kwargs)
            project = Path(command[2])
            checkout = self.root / 'work/source-tree'
            self.assertEqual(Path(kwargs['cwd']), checkout)
            self.assertTrue(project.is_relative_to(checkout))
            self.assertIn('-p:SourceRevisionId=' + self.head, command)
            self.assertEqual((project.parent / 'Program.cs').read_bytes(), expected_program)
            dest = Path(command[command.index('-o') + 1])
            dest.mkdir(parents=True)
            (dest / 'ARMHPC-OTA-CLI').write_bytes(hashlib.sha256(expected_program).digest())
            publishes.append(dest.name)
            if len(publishes) == 1:
                self.write('VERSION', '9.9.9\n')
                self.write('windows/ArmHpc.Ota.Cli/Program.cs', 'later program\n')
                self.write('src/armhpc_ota/__init__.py', '__version__ = "9.9.9"\n')
                self.commit()
            return subprocess.CompletedProcess(command, 0)

        with patch.object(packager.subprocess, 'run', side_effect=run):
            result = self.build(source_ref='v1.0.1')
        self.assertEqual(publishes, ['linux-x64', 'linux-arm64'])
        self.assertEqual(result['version'], '1.0.1')
        self.assertEqual(result['source_commit'], self.head)
        with tarfile.open(self.root / 'package.tar.gz', 'r:gz') as archive:
            prefix = 'armhpc-ota-cli-1.0.1/'
            source = archive.extractfile(prefix + 'source/armhpc-ota-source.tar').read()
            self.assertEqual(hashlib.sha256(source).hexdigest(), result['source_archive_sha256'])
            self.assertEqual(json.load(archive.extractfile(prefix + 'BUILD-INFO.json'))['source_commit'], self.head)
            for rid in publishes:
                self.assertEqual(archive.extractfile(prefix + 'runtimes/' + rid + '/publisher/Lib/armhpc_ota/__init__.py').read(), expected_python)
            with tarfile.open(fileobj=io.BytesIO(source), mode='r:') as corresponding:
                self.assertEqual(corresponding.extractfile('windows/ArmHpc.Ota.Cli/Program.cs').read(), expected_program)
                self.assertEqual(corresponding.extractfile('src/armhpc_ota/__init__.py').read(), expected_python)

    def test_source_snapshot_rejects_archive_traversal_and_links(self):
        for index, name in enumerate(('../outside', 'link')):
            with self.subTest(name=name):
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode='w') as archive:
                    item = tarfile.TarInfo(name)
                    if name == 'link':
                        item.type = tarfile.SYMTYPE
                        item.linkname = '../outside'
                        archive.addfile(item)
                    else:
                        item.size = 1
                        archive.addfile(item, io.BytesIO(b'x'))
                def export(command, **kwargs):
                    kwargs['stdout'].write(raw.getvalue())
                    return subprocess.CompletedProcess(command, 0)
                with patch.object(packager.subprocess, 'run', side_effect=export):
                    with self.assertRaisesRegex(ValueError, 'Unsafe file or link'):
                        packager.export_source(self.repo, self.head, self.root / f'unsafe-{index}.tar', self.root / f'unsafe-{index}')
                self.assertFalse((self.root / 'outside').exists())


if __name__ == '__main__':
    unittest.main()
