# SPDX-License-Identifier: GPL-3.0-only
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from armhpc_ota.backend import Backend
from armhpc_ota.config import Config
from armhpc_ota.errors import OTAError


class InitramfsLinkTests(unittest.TestCase):
    def prepare(self,directory):
        root=Path(directory)
        cache=root/'cache';cache.mkdir()
        source=root/'boot-initramfs';source.write_bytes(b'signed raw initramfs fixture')
        digest=hashlib.sha256(source.read_bytes()).hexdigest()
        (cache/digest).symlink_to(source)
        config=Config(cache=cache)
        job={'target':'rescue','manifest':{'artifacts':[{'role':'rescue-initramfs','sha256':digest}]}}
        return Backend(config),job,source

    def test_bookworm_extractor_receives_verified_regular_file_instead_of_cache_link(self):
        with tempfile.TemporaryDirectory() as directory:
            backend,job,source=self.prepare(directory)
            def extract(command,path,destination):
                self.assertEqual('unmkinitramfs',command)
                self.assertFalse(Path(path).is_symlink(),'Bookworm zstd skips symbolic link inputs')
                self.assertEqual(source.resolve(),path)
                selector=Path(destination)/'scripts/local-top/armhpc-root-select'
                selector.parent.mkdir(parents=True)
                selector.write_text('armhpc.target=system|armhpc.target=rescue')
            with patch.object(backend,'verify_resources'),patch('armhpc_ota.backend.run',side_effect=extract) as command:
                backend.validate_payloads(job)
            self.assertEqual(1,command.call_count)

    def test_changed_link_target_still_fails_hash_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            backend,job,source=self.prepare(directory)
            source.write_bytes(b'changed archive')
            with patch.object(backend,'verify_resources'),patch('armhpc_ota.backend.run') as command:
                with self.assertRaises(OTAError) as caught:backend.validate_payloads(job)
            self.assertEqual('boot_hash',caught.exception.code)
            command.assert_not_called()
