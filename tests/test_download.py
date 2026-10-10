# SPDX-License-Identifier: GPL-3.0-only
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from armhpc_ota.download import Transport
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json

DATA = bytes(range(256)) * 5000


class Handler(BaseHTTPRequestHandler):
    requests = []
    mode = 'range'
    def log_message(self, *args):
        pass
    def do_GET(self):
        type(self).requests.append(dict(self.headers))
        offset = int(self.headers.get('Range', 'bytes=0-')[6:-1]) if self.mode != 'ignore' else 0
        self.send_response(206 if offset else 200)
        if offset:
            self.send_header('Content-Range', f'bytes {offset if self.mode != "bad-range" else offset + 1}-{len(DATA)-1}/{len(DATA)}')
        self.send_header('ETag', '"test-v1"')
        self.end_headers()
        try:
            self.wfile.write(DATA[offset:])
        except (BrokenPipeError, ConnectionResetError):
            pass  # A rejected range intentionally closes the local test connection.


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        Handler.requests = []; Handler.mode = 'range'
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.server.server_close); self.addCleanup(self.server.shutdown)
        self.item = {'id': 'payload', 'sha256': hashlib.sha256(DATA).hexdigest(), 'size': len(DATA),
                     'url': f'http://127.0.0.1:{self.server.server_port}/payload'}

    def test_resume_uses_range_and_etag_then_verifies_hash(self):
        cache = Path(self.temp.name)
        (cache / (self.item['sha256'] + '.part')).write_bytes(DATA[:2048])
        atomic_json(cache / (self.item['sha256'] + '.resume.json'), {'etag': '"test-v1"'})
        result = Transport(local=True).download(self.item, cache)
        self.assertEqual(DATA, result.read_bytes())
        self.assertEqual('bytes=2048-', Handler.requests[-1]['Range'])
        self.assertEqual('"test-v1"', Handler.requests[-1]['If-Range'])

    def test_server_ignoring_range_restarts_instead_of_appending(self):
        Handler.mode = 'ignore'
        cache = Path(self.temp.name)
        (cache / (self.item['sha256'] + '.part')).write_bytes(DATA[:2048])
        self.assertEqual(DATA, Transport(local=True).download(self.item, cache).read_bytes())

    def test_inconsistent_range_is_rejected(self):
        Handler.mode = 'bad-range'
        cache = Path(self.temp.name)
        (cache / (self.item['sha256'] + '.part')).write_bytes(DATA[:2048])
        with self.assertRaises(OTAError):
            Transport(local=True).download(self.item, cache)

    def test_cache_corruption_is_not_treated_as_verified(self):
        cache = Path(self.temp.name)
        (cache / self.item['sha256']).write_bytes(b'bad')
        self.assertEqual(DATA, Transport(local=True).download(self.item, cache).read_bytes())

    def test_complete_partial_can_commit_without_network(self):
        cache = Path(self.temp.name)
        (cache / (self.item['sha256'] + '.part')).write_bytes(DATA)
        self.item['url'] = 'https://invalid.invalid/payload'
        self.assertEqual(DATA, Transport(local=True).download(self.item, cache).read_bytes())
