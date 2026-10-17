# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from armhpc_ota.boot_maintenance import prepare_boot_cache
from armhpc_ota.errors import OTAError


class BootCache(unittest.TestCase):
    def test_shared_cache_binding_is_not_relocated_when_sata_returns(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            (state/'cache').mkdir()
            config = SimpleNamespace(simulate=None, state=state, cache=Path('/data/armhpc-ota/cache'))
            task = {'bundle':str(state/'cache/boot-maintenance'/('a'*64)/'bundle.tar.xz'), 'bundle_sha256':'a'*64}
            with patch('armhpc_ota.bootstrap_space.prepare_cache') as prepare:
                prepare_boot_cache(config, {'partitions':{'data':{'path':'/dev/fixture'}}}, task)
            prepare.assert_not_called()
            self.assertEqual(state/'cache', config.cache)

    def test_data_cache_requires_the_bound_disk_before_any_lookup(self):
        config = SimpleNamespace(simulate=None, state=Path('/state'), cache=Path('/state/cache'))
        task = {'bundle':'/data/armhpc-ota/cache/boot-maintenance/'+('a'*64)+'/bundle.tar.xz', 'bundle_sha256':'a'*64}
        with patch('armhpc_ota.bootstrap_space.prepare_cache') as prepare:
            with self.assertRaises(OTAError) as caught:
                prepare_boot_cache(config, {'partitions':{'data':None}}, task)
        self.assertEqual('boot_cache_unavailable', caught.exception.code)
        prepare.assert_not_called()

    def test_data_cache_mount_is_prepared_before_rebinding(self):
        config = SimpleNamespace(simulate=None, state=Path('/state'), cache=Path('/state/cache'))
        task = {'bundle':'/data/armhpc-ota/cache/boot-maintenance/'+('a'*64)+'/bundle.tar.xz', 'bundle_sha256':'a'*64}
        with patch('armhpc_ota.bootstrap_space.prepare_cache') as prepare, \
             patch.object(Path,'is_mount',return_value=True), patch.object(Path,'is_dir',return_value=True):
            prepare_boot_cache(config, {'partitions':{'data':{'path':'/dev/fixture'}}}, task)
        prepare.assert_called_once()
        self.assertEqual(Path('/data/armhpc-ota/cache'), config.cache)

    def test_saved_cache_path_cannot_escape_the_binding(self):
        config = SimpleNamespace(simulate=None, state=Path('/state'), cache=Path('/state/cache'))
        for file in ('/other/cache/boot-maintenance/'+('a'*64)+'/bundle.tar.xz',
                     '/state/cache/../other/boot-maintenance/'+('a'*64)+'/bundle.tar.xz'):
            with self.assertRaises(OTAError):
                prepare_boot_cache(config, {'partitions':{'data':None}}, {'bundle':file,'bundle_sha256':'a'*64})


if __name__ == '__main__':
    unittest.main()
