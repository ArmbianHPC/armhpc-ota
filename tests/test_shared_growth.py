# SPDX-License-Identifier: GPL-3.0-only
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from armhpc_ota.errors import OTAError


class SharedGrowth(unittest.TestCase):
    def setUp(self):
        import armhpc_ota
        self.repository = Path(armhpc_ota.__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location('shared_growth_selector', self.repository / 'boot/squashfs-boot.py')
        self.selector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.selector)
        self.header = ('Filesystem state: clean\nBlock count: 1469435\nBlock size: 4096\n'
                       'Last mount time: Tue Oct 13 00:00:12 2026\n'
                       'Last checked: Thu Oct  8 08:35:49 2026\n')
        self.calls = []
        self.mounted = ''

    def command(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == 'tune2fs':
            return self.header
        if args[0] == 'findmnt':
            return self.mounted
        if args[0] in ('e2fsck', 'resize2fs'):
            return ''
        self.fail('Unexpected command: ' + repr(args))

    def grow(self, size=6018809344):
        with patch.object(self.selector, 'capacity', return_value=size), \
             patch.object(self.selector, 'run', side_effect=self.command):
            return self.selector.resize_shared_filesystem('/dev/fixture')

    def test_full_clean_filesystem_skips_clock_sensitive_resize(self):
        self.assertFalse(self.grow())
        self.assertEqual(['tune2fs'], [args[0] for args in self.calls])

    def test_interrupted_growth_checks_and_resizes_remaining_filesystem(self):
        self.header = self.header.replace('1469435', '262144')
        self.assertTrue(self.grow())
        self.assertEqual(['tune2fs', 'findmnt', 'e2fsck', 'resize2fs'], [a[0] for a in self.calls])

    def test_full_but_erroneous_filesystem_is_checked_without_resizing(self):
        self.header = self.header.replace('state: clean', 'state: clean with errors')
        self.assertTrue(self.grow())
        self.assertEqual(['tune2fs', 'findmnt', 'e2fsck'], [a[0] for a in self.calls])

    def test_oversized_filesystem_is_never_shrunk(self):
        with self.assertRaises(OTAError) as caught:
            self.grow(4096)
        self.assertEqual('shared_filesystem', caught.exception.code)
        self.assertEqual(['tune2fs'], [a[0] for a in self.calls])

    def test_missing_geometry_is_refused_before_writes(self):
        self.header = 'Filesystem state: clean\n'
        with self.assertRaises(OTAError):
            self.grow()
        self.assertEqual(['tune2fs'], [a[0] for a in self.calls])

    def test_mounted_filesystem_is_not_checked_or_resized(self):
        self.header = self.header.replace('1469435', '262144')
        self.mounted = '/var/lib/armhpc/ota'
        with self.assertRaises(OTAError) as caught:
            self.grow()
        self.assertEqual('shared_mounted', caught.exception.code)
        self.assertEqual(['tune2fs', 'findmnt'], [a[0] for a in self.calls])

    def test_resize_failure_remains_an_error(self):
        self.header = self.header.replace('1469435', '262144')
        original = self.command
        def command(*args, **kwargs):
            if args[0] == 'resize2fs':
                raise OTAError('command_failed', 'Resize refused')
            return original(*args, **kwargs)
        with patch.object(self.selector, 'capacity', return_value=6018809344), \
             patch.object(self.selector, 'run', side_effect=command):
            with self.assertRaises(OTAError):
                self.selector.resize_shared_filesystem('/dev/fixture')

    @unittest.skipUnless(all(shutil.which(x) for x in ('mke2fs', 'debugfs', 'resize2fs', 'tune2fs')), 'e2fsprogs unavailable')
    def test_real_ext4_with_future_mount_time_needs_no_resize(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / 'shared.ext4'
            with image.open('wb') as stream:
                stream.truncate(32 * 1024**2)
            env = {**os.environ, 'LC_ALL': 'C'}
            subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096', str(image)],
                           check=True, capture_output=True, env=env)
            for field, value in (('lastcheck', '1791448549'), ('mtime', '1791849612')):
                subprocess.run(['debugfs', '-w', '-R', 'set_super_value ' + field + ' ' + value, str(image)],
                               check=True, capture_output=True, env=env)
            refused = subprocess.run(['resize2fs', str(image)], capture_output=True, text=True, env=env)
            self.assertNotEqual(0, refused.returncode)
            self.assertIn("Please run 'e2fsck -f", refused.stderr)
            with patch.object(self.selector, 'capacity', return_value=image.stat().st_size):
                self.assertFalse(self.selector.resize_shared_filesystem(str(image)))


    def test_unreadable_mount_timestamp_is_refused_before_fsck(self):
        self.header = self.header.replace('1469435', '262144').replace('Tue Oct 13 00:00:12 2026', 'invalid')
        with self.assertRaises(OTAError) as caught:
            self.grow()
        self.assertEqual('shared_clock', caught.exception.code)
        self.assertEqual(['tune2fs', 'findmnt'], [a[0] for a in self.calls])

    @unittest.skipUnless(all(shutil.which(x) for x in ('mke2fs', 'debugfs', 'e2fsck', 'resize2fs', 'tune2fs')), 'e2fsprogs unavailable')
    def test_real_growth_with_unset_system_clock_uses_metadata_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / 'shared.ext4'
            with image.open('wb') as stream:
                stream.truncate(16 * 1024**2)
            env = {**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'}
            subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096', str(image)],
                           check=True, capture_output=True, env=env)
            for field, value in (('lastcheck', '1791448549'), ('mtime', '1791849612'), ('wtime', '1791849612')):
                subprocess.run(['debugfs', '-w', '-R', 'set_super_value ' + field + ' ' + value, str(image)],
                               check=True, capture_output=True, env=env)
            with image.open('r+b') as stream:
                stream.truncate(32 * 1024**2)
            with patch.object(self.selector, 'capacity', return_value=image.stat().st_size), \
                 patch.object(self.selector.time, 'time', return_value=1):
                self.assertTrue(self.selector.resize_shared_filesystem(str(image)))
            fields = dict(line.split(':', 1) for line in subprocess.check_output(
                ['tune2fs', '-l', str(image)], text=True, env=env).splitlines() if ':' in line)
            self.assertEqual(image.stat().st_size, int(fields['Block count']) * int(fields['Block size']))
            self.assertEqual('clean', fields['Filesystem state'].strip())


if __name__ == '__main__':
    unittest.main()
