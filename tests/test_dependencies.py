# SPDX-License-Identifier: GPL-3.0-only
from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from armhpc_ota.bootstrap import execute
from armhpc_ota.dependencies import require_commands, RUNTIME_PACKAGES, SYSTEM_PATH
from armhpc_ota.device import run
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from support import fixture, release


class DependencyTests(unittest.TestCase):
    def test_missing_gdisk_is_reported_with_its_package_and_fixed_search_path(self):
        def which(name, path):
            self.assertEqual(SYSTEM_PATH, path)
            return None if name == 'sgdisk' else '/usr/bin/' + name
        with patch('armhpc_ota.dependencies.shutil.which', side_effect=which):
            with self.assertRaises(OTAError) as caught:
                require_commands()
        self.assertEqual('runtime_dependencies', caught.exception.code)
        self.assertEqual(['sgdisk'], caught.exception.details['missing'])
        self.assertEqual(['gdisk'], caught.exception.details['packages'])
        self.assertIn('gdisk', RUNTIME_PACKAGES)

    def test_missing_command_is_a_specific_cli_error(self):
        with patch('armhpc_ota.device.subprocess.run', side_effect=FileNotFoundError('sgdisk')):
            with self.assertRaises(OTAError) as caught:
                run('sgdisk', '--version')
        self.assertEqual('command_missing', caught.exception.code)
        self.assertEqual('gdisk', caught.exception.details['package'])

    def test_bootstrap_dependency_failure_precedes_journal_download_and_disk_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            config, key = fixture(directory, initialized=False, mode='rescue')
            engine = Engine(config)
            _, manifest = release(config, key)
            disk_fixture = config.simulate / 'device.json'
            disk_before = disk_fixture.read_bytes()
            config.simulate = None
            error = OTAError('runtime_dependencies', 'Missing sgdisk', missing=['sgdisk'], packages=['gdisk'])
            with patch('armhpc_ota.bootstrap.preview', return_value={'write_allowed': True}), \
                 patch('armhpc_ota.bootstrap.discover', return_value={'device_id': 'device-001'}), \
                 patch.object(engine.store, 'lock', return_value=nullcontext()), \
                 patch.object(engine.backend, 'require_runtime_resources', side_effect=error), \
                 patch.object(engine, 'download') as download, \
                 patch('armhpc_ota.bootstrap.run') as disk_command:
                with self.assertRaises(OTAError) as caught:
                    execute(engine, manifest, 'unused-anchor')
            self.assertEqual('runtime_dependencies', caught.exception.code)
            self.assertFalse((config.state / 'bootstrap.json').exists())
            self.assertEqual(disk_before, disk_fixture.read_bytes())
            download.assert_not_called()
            disk_command.assert_not_called()

    def test_missing_archive_tools_report_packages_before_device_operations(self):
        def which(name, path):
            return None if name in ('xz', 'gzip', 'cpio') else '/usr/bin/' + name
        with patch('armhpc_ota.dependencies.shutil.which', side_effect=which):
            with self.assertRaises(OTAError) as caught:
                require_commands()
        self.assertEqual(['cpio', 'gzip', 'xz-utils'], caught.exception.details['packages'])
        self.assertIn('xz-utils', RUNTIME_PACKAGES)
