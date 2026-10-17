# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the initramfs root selector before its systemd handoff."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class InitramfsBootAdmission(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        repository = Path(__file__).resolve().parents[1]
        if not (repository / 'boot/squashfs-boot.py').is_file():
            import armhpc_ota
            repository = Path(armhpc_ota.__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location('initramfs_boot_admission', repository / 'boot/squashfs-boot.py')
        self.selector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.selector)
        self.base = self.root / 'run/armhpc-ota'
        self.state = self.base / 'shared'
        self.lower = self.base / 'lower'
        self.merged = self.root / 'merged'
        self.request = '4b81e2ee-aa9d-4ac7-8c7d-80f215421960'
        self.release = 'oect-bookworm-1.2.1-fixture'
        self.board = {'id': 'wxy-oect-original', 'layout': 'oect-squashfs-ab-v2',
                      'boot_fstype': 'ext4', 'labels': {'boot': 'BOOT', 'shared': 'SHARED',
                      'rescue_a': 'RESCUE_A', 'rescue_b': 'RESCUE_B', 'system': 'SYSTEM'}}
        self.config = SimpleNamespace(board=lambda: self.board, trust=self.root / 'trust')
        self.boot_files = {}
        for name in ('kernel', 'dtb', 'initramfs'):
            target = self.lower / 'usr/lib/armhpc-ota/boot' / name
            self.write(target, ('paired-' + name).encode())
            self.boot_files[name] = {'sha256': self.digest(target)}
        self.candidate = {'release': self.release, **copy.deepcopy(self.boot_files)}
        self.task = {'task_id': self.request, 'stage': 'awaiting-firmware',
                     'purpose': 'firmware-update', 'release': self.release,
                     'inactive_slot': 'a', 'candidate_boot': self.candidate}
        self.bundle = {'release': self.release, 'board': self.board['id'], 'files': copy.deepcopy(self.boot_files)}
        self.manifest = {'board': self.board['id'], 'layout': self.board['layout'], 'release': self.release,
                         'artifacts': [{'role': 'rescue-' + n, **v} for n, v in self.boot_files.items()] +
                                      [{'role': 'rescue-rootfs', 'sha256': 'a' * 64}]}
        self.write(self.state / 'control.json', {'device_id': 'fixture-device'})
        self.write(self.state / 'boot-maintenance/releases' / self.release / 'manifest.json', b'signed-fixture')
        self.write(self.lower / 'etc/armhpc/release.json',
                   {'release': self.release, 'target': 'rescue', 'kernel': '6.12.111-fixture'})
        (self.lower / 'lib/modules/6.12.111-fixture').mkdir(parents=True)
        self.write(self.merged / 'etc/armhpc/ota.json', {})
        self.write(self.root / 'proc/cmdline', ('armhpc.boot-maintenance=' + self.request + ' armhpc.watchdog=1').encode())
        self.write(self.root / 'proc/sys/kernel/random/boot_id', b'fixture-boot-id')
        self.write(self.root / 'etc/armhpc/anchor-kernel-sha256', self.boot_files['kernel']['sha256'].encode())
        self.write(self.root / 'etc/armhpc/anchor-dtb-sha256', self.boot_files['dtb']['sha256'].encode())
        (self.root / 'etc/armhpc/rescue-defaults').mkdir()
        generation = self.selector.generation(self.state, 'a', self.release)
        self.write(generation / 'ready.json', {'root_sha256': 'a' * 64})
        self.record = self.root / 'run/armhpc/ota-boot.json'
        self.record.parent.mkdir(parents=True, exist_ok=True)
        self.overlays = []

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def mapped_path(self, value):
        value = str(value)
        if value.startswith(('/proc/', '/etc/armhpc/', '/run/armhpc', '/run/armhpc-')):
            return self.root / value.lstrip('/')
        return Path(value)

    def mount(self, device, destination, kind, writable=False):
        destination.mkdir(parents=True, exist_ok=True)

    def command(self, *args, **kwargs):
        if args[0] == 'blkid':
            return 'fixture-partuuid'
        if args[:3] == ('mount', '-t', 'overlay'):
            self.overlays.append(args[4])
            return ''
        if args[:3] == ('mount', '-o', 'bind'):
            return ''
        self.fail('Unexpected command: ' + repr(args))

    def boot(self):
        self.write(self.state / 'boot-maintenance/task.json', self.task)
        selector = self.selector
        with patch.object(selector, 'BASE', self.base), \
             patch.object(selector, 'BOOT_RECORD', self.record), \
             patch.object(selector, 'Path', side_effect=self.mapped_path), \
             patch.object(selector.Config, 'load', return_value=self.config), \
             patch.object(selector, 'partition', side_effect=lambda label, *a, **k: '/dev/' + label), \
             patch.object(selector, 'mount', side_effect=self.mount), \
             patch.object(selector, 'capacity', return_value=512 * 1024**2), \
             patch.object(selector, 'identity', return_value='fixture-device'), \
             patch.object(selector, 'verify', return_value=self.bundle), \
             patch.object(selector, 'verify_boot', return_value={}), \
             patch.object(selector, 'read_trailer', return_value=(self.manifest, b'signed-slot')), \
             patch.object(selector, 'run', side_effect=self.command):
            selector.main(self.merged)
        return json.loads(self.record.read_text())

    def test_firmware_candidate_uses_persistent_overlay(self):
        record = self.boot()
        self.assertTrue(record['shared_ready'])
        self.assertFalse(record['fallback'])
        self.assertEqual('a', record['slot'])
        self.assertEqual(self.request, record['boot_maintenance'])
        self.assertNotIn('/emergency/', self.overlays[0])
        self.assertFalse((self.record.parent / 'boot-errors.log').exists())

    def test_watchdog_candidate_retains_existing_admission(self):
        self.task.update(purpose='watchdog-diagnostic', stage='awaiting-watchdog')
        self.assertTrue(self.boot()['shared_ready'])

    def test_completed_candidate_is_not_readmitted(self):
        self.task['stage'] = 'committed'
        self.assertFalse(self.boot()['shared_ready'])
        self.assertIn('Candidate is not admitted', (self.record.parent / 'boot-errors.log').read_text())

    def test_wrong_task_id_is_not_admitted(self):
        self.task['task_id'] = '00000000-0000-0000-0000-000000000000'
        self.assertFalse(self.boot()['shared_ready'])

    def test_firmware_stage_requires_firmware_purpose(self):
        self.task['purpose'] = 'watchdog-diagnostic'
        self.assertFalse(self.boot()['shared_ready'])

    def test_changed_signed_dtb_is_not_admitted(self):
        self.bundle['files']['dtb']['sha256'] = 'b' * 64
        self.assertFalse(self.boot()['shared_ready'])
        self.assertIn('Candidate selection differs', (self.record.parent / 'boot-errors.log').read_text())


if __name__ == '__main__':
    unittest.main()
