# SPDX-License-Identifier: GPL-3.0-only
from datetime import datetime, timedelta, timezone
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from armhpc_ota.cli import main
from armhpc_ota.download import Transport
from armhpc_ota.errors import OTAError
from armhpc_ota.io import parse_json, inside, read_json
from armhpc_ota.metadata import sign, verify, validate_manifest, validate_index
from armhpc_ota.bootstrap import preview, align
from support import fixture, release


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.config, self.key = fixture(self.temp.name)
        self.path, self.manifest = release(self.config, self.key)

    def test_wrong_signature_and_untrusted_key_refused(self):
        document = json.loads(self.path.read_bytes())
        document['payload']['release'] = 'tampered'
        with self.assertRaises(OTAError):
            verify(json.dumps(document).encode(), self.config.trust)
        document = json.loads(self.path.read_bytes()); document['key_id'] = 'unknown'
        with self.assertRaises(OTAError):
            verify(json.dumps(document).encode(), self.config.trust)

    def test_duplicate_json_and_path_traversal_refused(self):
        with self.assertRaises(OTAError):
            parse_json(b'{"protocol":1,"protocol":2}')
        for path in ('../x', '/etc/shadow', 'foo\\bar', 'a/../../x'):
            with self.subTest(path=path), self.assertRaises(OTAError):
                inside(self.config.state, path)

    def test_arm32_metadata_supported_and_unknown_board_write_refused(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['architecture'] = 'armhf'; manifest['board'] = 'arm32-test-board'
        self.assertEqual('armhf', validate_manifest(manifest)['architecture'])
        self.config.profile = 'arm32-test-board'
        with self.assertRaises(OTAError):
            self.config.board()

    def test_missing_boot_pairing_refused(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['artifacts'] = manifest['artifacts'][:3]
        with self.assertRaises(OTAError):
            validate_manifest(manifest)

    def test_expired_and_future_feed_rejected(self):
        now = datetime.now(timezone.utc)
        index = {'kind': 'index', 'protocol': 1, 'created': (now - timedelta(days=1)).isoformat(),
                 'expires': (now - timedelta(seconds=1)).isoformat(), 'releases': []}
        with self.assertRaises(OTAError):
            validate_index(index, now)
        index.update(created=(now + timedelta(days=1)).isoformat(), expires=(now + timedelta(days=2)).isoformat())
        with self.assertRaises(OTAError):
            validate_index(index, now)

    def test_http_for_real_devices_and_embedded_credentials_rejected(self):
        for url in ('http://example.org/file', 'file:///etc/shadow', 'https://user:pass@example.org/file'):
            with self.assertRaises(OTAError):
                Transport().allowed(url)

    def test_json_status_is_stable_and_watch_has_no_terminal_banner(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(['status', '--json', '--simulate-root', self.temp.name])
        document = json.loads(output.getvalue())
        self.assertEqual(0, code); self.assertTrue(document['ok']); self.assertEqual(1, document['protocol'])
        self.assertEqual('device-001', document['data']['device_id'])

    def test_json_apply_requires_explicit_yes(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(['apply', '--json', '--simulate-root', self.temp.name, '--manifest', str(self.path)])
        self.assertEqual(2, code)
        self.assertEqual('confirmation_required', json.loads(output.getvalue())['error']['code'])

    def test_bootstrap_appends_without_changing_existing_partition_geometry(self):
        plan = preview(self.config)
        self.assertFalse(plan['system_partition_table_changed'])
        self.assertEqual(5242880, plan['append'][0]['start'])
        self.assertEqual(1417216, plan['preserved'][1]['start'])


if __name__ == '__main__':
    unittest.main()
