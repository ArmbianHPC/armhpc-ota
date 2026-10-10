# SPDX-License-Identifier: GPL-3.0-only
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from armhpc_ota.engine import Engine
from armhpc_ota import watchdog
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json,read_json
from support import fixture


class Watchdog034(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.c,self.key=fixture(self.root,mode='rescue');self.e=Engine(self.c)
    def tearDown(self):self.temp.cleanup()
    def test_completed_history_and_running_rescue_accept_one_shot(self):
        self.e.store.read=lambda:{'stage':'succeeded'}
        before=self.e.store.control();r=watchdog.prepare(self.e)
        self.assertEqual(self.e.store.control()['next'],{'target':'rescue','slot':'a','trial':False})
        watchdog.test(self.e,r['test_id'],True)
        with self.assertRaisesRegex(OTAError,'submitted'):watchdog.test(self.e,r['test_id'],True)
        result=watchdog.report(self.e,r['test_id'],manual=True)
        self.assertFalse(result['test']['internal_watchdog_passed'])
        self.assertEqual(self.e.store.control()['next'],before['next'])
    def test_active_ota_and_maintenance_refused(self):
        self.e.store.read=lambda:{'stage':'deploying-system'}
        with self.assertRaises(OTAError):watchdog.prepare(self.e)
        self.e.store.read=lambda:None
        atomic_json(self.c.state/'maintenance/task.json',{'stage':'installing'})
        with self.assertRaises(OTAError):watchdog.prepare(self.e)
    def test_mounted_data_and_changed_sata_refused(self):
        d=read_json(self.root/'device.json');next(x for x in d['blocks'] if x.get('fixture_role')=='data')['mountpoints']=['/data'];atomic_json(self.root/'device.json',d)
        with self.assertRaisesRegex(OTAError,'Unmount'):watchdog.prepare(self.e)
        next(x for x in d['blocks'] if x.get('fixture_role')=='data')['mountpoints']=[];atomic_json(self.root/'device.json',d)
        r=watchdog.prepare(self.e);d['blocks']=[x for x in d['blocks'] if not x['path'].startswith('/dev/sda')];atomic_json(self.root/'device.json',d)
        with self.assertRaisesRegex(OTAError,'SATA changed'):watchdog.test(self.e,r['test_id'],True)
    def test_physical_confirmation_and_fixture_cannot_pass_hardware(self):
        r=watchdog.prepare(self.e)
        with self.assertRaises(OTAError):watchdog.test(self.e,r['test_id'],False)
        watchdog.test(self.e,r['test_id'],True)
        with self.assertRaisesRegex(OTAError,'real Rescue'):watchdog.report(self.e,r['test_id'],confirmed=True)
    def test_no_effect_from_status_and_unshared_diagnostics(self):
        with patch.object(watchdog.os,'open',side_effect=AssertionError('No watchdog opens')):
            self.assertFalse(watchdog.status(self.e)['hardware_verified'])
        from armhpc_ota.diagnostics import shared_verified
        self.assertFalse(shared_verified(self.c))
    def test_candidate_health_gate_and_matching_slot(self):
        ctl=self.e.store.control()
        task={'stage':'awaiting-watchdog','ordinary_boot_healthy':False,'inactive_slot':'b','candidate_boot':ctl['confirmed']['rescue']['boot']}
        atomic_json(self.c.state/'boot-maintenance/task.json',task)
        with self.assertRaisesRegex(OTAError,'ordinary boot'):watchdog.prepare(self.e)
        task['ordinary_boot_healthy']=True;atomic_json(self.c.state/'boot-maintenance/task.json',task)
        d=read_json(self.root/'device.json');d['root']='/dev/mmcblk0p3';atomic_json(self.root/'device.json',d)
        self.assertEqual(watchdog.prepare(self.e)['slot'],'b')


if __name__=='__main__':unittest.main()
