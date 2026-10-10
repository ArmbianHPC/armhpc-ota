# SPDX-License-Identifier: GPL-3.0-only
import hashlib
from pathlib import Path
import tempfile
import unittest
from armhpc_ota.backend import _staged_debs
from armhpc_ota.errors import OTAError


class StagedPackagesTests(unittest.TestCase):
    def test_only_new_verified_archives_are_removed_after_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'root';resources=Path(directory)/'resources';resources.mkdir()
            data=b'verified package';(resources/'new.deb').write_bytes(data)
            cache=root/'var/cache/apt/archives';cache.mkdir(parents=True)
            (cache/'keep.deb').write_bytes(data)
            packages=[{'file':name,'sha256':hashlib.sha256(data).hexdigest()} for name in ('new.deb','keep.deb')]
            (resources/'keep.deb').write_bytes(data)
            with _staged_debs(root,resources,packages) as args:
                self.assertEqual(['/var/cache/apt/archives/new.deb','/var/cache/apt/archives/keep.deb'],args)
                self.assertTrue((cache/'new.deb').is_file())
            self.assertFalse((cache/'new.deb').exists())
            self.assertEqual(data,(cache/'keep.deb').read_bytes())

    def test_wrong_resource_hash_is_refused_before_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'root';resources=Path(directory)/'resources';resources.mkdir()
            (resources/'package.deb').write_bytes(b'wrong data')
            with self.assertRaises(OTAError):
                with _staged_debs(root,resources,[{'file':'package.deb','sha256':'0'*64}]):pass
            self.assertFalse((root/'var/cache/apt/archives/package.deb').exists())

    def test_conflicting_existing_cache_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'root';resources=Path(directory)/'resources';resources.mkdir()
            data=b'new';(resources/'package.deb').write_bytes(data)
            cache=root/'var/cache/apt/archives';cache.mkdir(parents=True);(cache/'package.deb').write_bytes(b'old')
            with self.assertRaises(OTAError):
                with _staged_debs(root,resources,[{'file':'package.deb','sha256':hashlib.sha256(data).hexdigest()}]):pass
            self.assertEqual(b'old',(cache/'package.deb').read_bytes())
