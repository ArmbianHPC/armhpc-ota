# SPDX-License-Identifier: GPL-3.0-only
import tempfile
import unittest
from armhpc_ota.boot import select
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from support import fixture, boot_fixture


class BootSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.config, _ = fixture(self.temp.name)
        self.engine = Engine(self.config)
        control = self.engine.store.control(); control['monitor_confirmed_boots'] = True
        self.engine.store.write_control(control)

    def test_regular_normal_early_failure_also_falls_back_to_rescue(self):
        self.assertEqual('system', select(self.config)['target'])
        self.assertEqual('rescue', select(self.config)['target'])
        self.assertTrue(self.engine.store.control()['system_blocked'])

    def test_regular_healthy_boot_is_acknowledged(self):
        select(self.config)
        self.engine.confirm()
        self.assertFalse(self.engine.store.control()['boot_attempt']['pending'])
        self.assertEqual('system', select(self.config)['target'])

    def test_regular_rescue_failure_marks_slot_for_independent_fallback(self):
        self.engine.request_rescue_boot()
        self.assertEqual('rescue', select(self.config)['target'])
        with self.assertRaises(OTAError): select(self.config)
        self.assertIn('a', self.engine.store.control()['bad_slots'])
