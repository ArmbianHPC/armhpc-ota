# SPDX-License-Identifier: GPL-3.0-only
import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from armhpc_ota.engine import Engine
from armhpc_ota import watchdog
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json,read_json
from support import fixture

class WatchdogSafety(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);self.config,self.key=fixture(self.root,mode='rescue');self.engine=Engine(self.config)
    def tearDown(self):self.t.cleanup()
    def test_status_never_opens_watchdog(self):
        with patch.object(watchdog.os,'open',side_effect=AssertionError('Device opened')):
            self.assertFalse(watchdog.status(self.engine)['hardware_verified'])
    def test_mounted_data_refused(self):
        d=read_json(self.root/'device.json');next(x for x in d['blocks'] if x.get('fixture_role')=='data')['mountpoints']=['/data'];atomic_json(self.root/'device.json',d)
        with self.assertRaises(OTAError):watchdog.prepare(self.engine)
    def test_active_task_refused(self):
        self.engine.store.read=lambda:{'stage':'deploying-system'}
        with self.assertRaises(OTAError):watchdog.prepare(self.engine)
    def test_explicit_power_confirmation_required(self):
        r=watchdog.prepare(self.engine)
        with self.assertRaises(OTAError):watchdog.test(self.engine,r['test_id'],False)
