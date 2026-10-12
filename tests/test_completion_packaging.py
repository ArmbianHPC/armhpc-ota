# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Validate completion resources included by the runtime packager."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

from armhpc_ota.shared_resources import COMPLETION_TARGETS

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('completion_packager', ROOT / 'tools/package-runtime.py')
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class CompletionPackagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('GPL-2.0-only', 'GPL-3.0-only'):
            path = self.root / 'LICENSES' / (name + '.txt')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('license fixture\n')

    def install(self):
        for name in COMPLETION_TARGETS:
            path = self.root / 'components/common/rootfs-overlay' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('# completion resource\n')

    def test_all_completion_resources_are_in_the_signed_inventory(self):
        self.install()
        rows = packager.framework_files(self.root)
        selected = {item['target']: (source, item) for source, item in rows}
        self.assertTrue(COMPLETION_TARGETS.issubset(selected))
        for target in COMPLETION_TARGETS:
            source, item = selected[target]
            self.assertEqual(item['scope'], 'common')
            self.assertEqual(item['sha256'], packager.digest(source))
            self.assertTrue(item['source'].startswith('compat/framework/completion/'))

    def test_old_framework_without_completion_remains_compatible(self):
        rows = packager.framework_files(self.root)
        self.assertFalse(COMPLETION_TARGETS.intersection(item['target'] for source, item in rows))

    def test_partial_or_symlinked_completion_set_is_rejected(self):
        self.install()
        path = self.root / 'components/common/rootfs-overlay/etc/profile.d/armhpc-completion.sh'
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'Missing or unsafe completion'):
            packager.framework_files(self.root)
        path.symlink_to(self.root / 'LICENSES/GPL-2.0-only.txt')
        with self.assertRaisesRegex(ValueError, 'Missing or unsafe completion'):
            packager.framework_files(self.root)


if __name__ == '__main__':
    unittest.main()
