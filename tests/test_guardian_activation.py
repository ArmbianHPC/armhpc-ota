# SPDX-License-Identifier: GPL-3.0-only
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from armhpc_ota import guardian_activation as g, watchdog
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json, read_json
from armhpc_ota.engine import Engine
from support import fixture


class GuardianActivation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.test = {'test_id': '538069a3-569c-47c2-a032-666a945d15c7', 'before_boot_id': 'fixture-boot',
                     'slot': 'a', 'boot': {'release': 'r13'}}
        self.context = {'target': 'rescue', 'slot': 'a', 'release': 'r13', 'shared_ready': True}
        self.keeper = {'owner': '0.3.4', 'boot_id': 'fixture-boot', 'pid': 321, 'armed_test': ''}
        self.active=False;self.socket=False;self.network=True;self.starts=0;self.busy=[];self.start_failure=False
        self.patches=[]
        for name in ('OWNER','REQUIRED','HEALTHY','CONTEXT','PROOF'):
            self.patch(name,self.root/name)
        self.patch('SOCKET',SimpleNamespace(is_socket=lambda:self.socket,
                   stat=lambda:SimpleNamespace(st_uid=0,st_mode=0o140600)))
        self.patch('run',self.run_command);self.patch('read',self.read);self.patch('holders',lambda:self.busy)
        self.patches.append(patch.object(g.os,'geteuid',return_value=0));self.patches[-1].start()
        atomic_json(g.CONTEXT,self.context)
    def patch(self,name,value):
        p=patch.object(g,name,value);p.start();self.patches.append(p)
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def read(self,path):
        if str(path).endswith('/state'):return 'active' if self.active else 'inactive'
        if str(path).endswith('/carrier'):return '1' if self.network else '0'
        if str(path)=='/proc/cmdline':return 'armhpc.anchor=1'
        return None
    def run_command(self,*args):
        if args[:2]==('systemctl','show'):
            return {'rc':0,'output':'LoadState=loaded\nActiveState='+('active' if self.active else 'inactive')+
                    '\nConditionResult='+('yes' if self.active else 'no')+'\nMainPID='+('321' if self.active else '0')+'\nResult=success'}
        if args[:2]==('systemctl','is-active'):return {'rc':0,'output':'active' if self.network else 'inactive'}
        if args[:2]==('systemctl','start'):
            self.starts+=1
            if self.start_failure:return {'rc':1,'output':'fixture start failure'}
            self.assertTrue(g.HEALTHY.exists());self.assertTrue(g.REQUIRED.exists())
            self.active=True;self.socket=True;atomic_json(g.OWNER,self.keeper)
            return {'rc':0,'output':''}
        if args[0]=='ip':return {'rc':0,'output':json.dumps([{'addr_info':[{'family':'inet','local':'192.168.1.10'}]}])}
        raise AssertionError(args)
    def test_ordinary_boot_status_is_readonly_and_explains_missing_guardian(self):
        result=g.snapshot('fixture-boot')
        self.assertEqual(result['readiness_hint'],'ordinary_boot_requires_explicit_prepare')
        self.assertFalse(result['guardian_compatible']);self.assertEqual(self.starts,0)
        self.assertFalse(g.REQUIRED.exists());self.assertFalse(g.HEALTHY.exists())
    def test_ordinary_confirmed_rescue_starts_once_after_current_health(self):
        first=g.ensure(self.test);second=g.ensure(self.test)
        self.assertTrue(first['started_for_test']);self.assertFalse(second['started_for_test'])
        self.assertEqual(self.starts,1);self.assertEqual(read_json(g.PROOF)['boot_id'],'fixture-boot')
        self.assertTrue(g.snapshot('fixture-boot')['guardian_compatible'])
    def test_network_failure_does_not_arm_or_fabricate_health(self):
        self.network=False
        with self.assertRaisesRegex(OTAError,'link, IPv4'):g.ensure(self.test)
        self.assertEqual(self.starts,0);self.assertFalse(g.HEALTHY.exists());self.assertFalse(g.REQUIRED.exists())
    def test_wrong_context_does_not_arm(self):
        self.context['slot']='b';atomic_json(g.CONTEXT,self.context)
        with self.assertRaisesRegex(OTAError,'context differs'):g.ensure(self.test)
        self.assertEqual(self.starts,0)
    def test_other_fd_owner_is_never_restarted(self):
        self.busy=[{'pid':999,'fd':'4'}]
        with self.assertRaisesRegex(OTAError,'Another process'):g.ensure(self.test)
        self.assertEqual(self.starts,0);self.assertFalse(g.HEALTHY.exists())
    def test_incompatible_active_guardian_is_never_killed(self):
        self.active=True;self.socket=True;self.keeper['owner']='old';atomic_json(g.OWNER,self.keeper)
        with self.assertRaisesRegex(OTAError,'Another process'):g.ensure(self.test)
        self.assertEqual(self.starts,0)
    def test_guardian_with_consumed_request_requires_original_report(self):
        self.active=True;self.socket=True;self.keeper['armed_test']=self.test['test_id'];atomic_json(g.OWNER,self.keeper)
        with self.assertRaisesRegex(OTAError,'already accepted'):g.ensure(self.test)
        self.assertEqual(self.starts,0)
    def test_start_failure_preserves_diagnostic_markers_and_never_claims_ready(self):
        self.start_failure=True
        with self.assertRaisesRegex(OTAError,'refused to start'):g.ensure(self.test)
        self.assertTrue(g.HEALTHY.exists());self.assertTrue(g.REQUIRED.exists())
        self.assertFalse(g.snapshot('fixture-boot')['guardian_compatible'])
    def test_prepare_transaction_protects_rescue_before_arm_and_can_cancel_failed_prepare(self):
        (self.root/'device').mkdir()
        c,key=fixture(self.root/'device',mode='rescue');e=Engine(c)
        d=read_json(c.simulate/'device.json')
        from armhpc_ota.device import discover,layout
        device=discover(c);storage=layout(c,device,initialized=True);before=e.store.control()
        old_sim=c.simulate;c.simulate=None
        def fail(prepared):
            ctl=e.store.control();self.assertTrue(ctl['system_blocked'])
            self.assertEqual(ctl['next']['target'],'rescue')
            self.assertEqual(watchdog.record(c)['stage'],'preparing')
            raise OTAError('fixture_start','simulated arm interruption')
        try:
            with patch.object(watchdog,'discover',return_value=device),patch.object(watchdog,'layout',return_value=storage),\
                 patch.object(e,'_require_shared_mount'),patch.object(e.clock,'flush'),\
                 patch.object(watchdog,'boot_id',return_value='fixture-boot'),\
                 patch.object(watchdog,'read',return_value='Synopsys DesignWare Watchdog'),\
                 patch.object(watchdog,'command',return_value={'rc':0,'output':'0'}),\
                 patch.object(watchdog.os,'sync'),patch.object(g,'ensure',side_effect=fail):
                with self.assertRaisesRegex(OTAError,'Guardian preparation failed'):watchdog.prepare(e)
                saved=watchdog.record(c);self.assertEqual(saved['stage'],'prepare-failed')
                self.assertTrue(e.store.control()['system_blocked'])
                closed=watchdog.report(e,saved['test_id'],cancel=True)
                self.assertEqual(closed['test']['stage'],'cancelled')
                self.assertEqual(e.store.control()['next'],before['next'])
                self.assertEqual(e.store.control()['system_blocked'],before.get('system_blocked',False))
        finally:c.simulate=old_sim


if __name__=='__main__':unittest.main()
