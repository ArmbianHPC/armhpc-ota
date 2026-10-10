# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from armhpc_ota.bootstrap_space import prepare_cache, backup_prefix
from armhpc_ota.errors import OTAError


class BootstrapSpaceTests(unittest.TestCase):
    def test_custom_cache_is_not_replaced_or_mounted(self):
        config = SimpleNamespace(simulate=None, cache=Path('/mnt/external/cache'), state=Path('/state'))
        with patch('armhpc_ota.bootstrap_space.run') as command:
            prepare_cache(config, {'partitions': {'data': {'path': '/dev/sda2'}}})
        command.assert_not_called()
        self.assertEqual(Path('/mnt/external/cache'), config.cache)

    def test_no_sata_keeps_shared_or_legacy_cache(self):
        config = SimpleNamespace(simulate=None, cache=Path('/state/cache'), state=Path('/state'))
        with patch('armhpc_ota.bootstrap_space.run') as command:
            prepare_cache(config, {'partitions': {'data': None}})
        command.assert_not_called()

    def test_low_backup_space_refuses_without_reading_device(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'prefix.bin.zst'
            with patch('armhpc_ota.bootstrap_space.shutil.disk_usage', return_value=SimpleNamespace(free=0)):
                with self.assertRaises(OTAError) as caught:
                    backup_prefix('/dev/nonexistent-device', destination, 180 * 1024**2)
            self.assertEqual('bootstrap_backup_space', caught.exception.code)
            self.assertFalse(destination.exists())
