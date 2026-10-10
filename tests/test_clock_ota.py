# SPDX-License-Identifier: GPL-3.0-only
import hashlib
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from armhpc_ota.clock import Clock
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json, read_json
from armhpc_ota import maintenance
from armhpc_ota.lan_publish import tools_bundle
from support import fixture, release, boot_fixture
import test_lan


class ClockOTATests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.c,self.key=fixture(self.temp.name,mode='rescue');self.e=Engine(self.c)
        p,self.manifest=release(self.c,self.key);self.e.manifest(location=str(p))

    def state(self,quality,**extra):
        atomic_json(self.c.simulate/'clock.json',{'quality':quality,'ntp_synchronised':quality=='synchronised',
                    'valid_anchor':quality in ('estimated','synchronised'),'source':'fixture',**extra})

    def test_estimated_time_allows_signed_local_upgrade_and_is_visible_in_events(self):
        self.state('estimated');job=self.e.apply(self.manifest,'system');self.e.worker()
        self.assertEqual('estimated',job['events'][0]['clock']['quality'])
        self.assertEqual('estimated',self.e.status()['clock']['quality'])
        self.assertEqual('before-writing',read_json(self.c.simulate/'last-clock-flush.json')['reason'])

    def test_invalid_time_blocks_before_task_creation_or_disk_write(self):
        self.state('invalid');self.assertFalse(self.e.plan(self.manifest)['write_allowed'])
        with self.assertRaises(OTAError) as caught:self.e.apply(self.manifest)
        self.assertEqual('clock_state_invalid',caught.exception.code);self.assertIsNone(self.e.store.read())

    def test_unsynchronised_time_blocks_index_fetch_not_local_manifest(self):
        self.state('estimated')
        with patch.object(self.e.transport,'metadata') as network:
            with self.assertRaises(OTAError) as caught:self.e.check()
        self.assertEqual('clock_unsynchronised',caught.exception.code);network.assert_not_called()
        self.assertTrue(self.e.plan(self.manifest,'rescue')['write_allowed'])

    def test_checkpoint_failure_stops_before_writing(self):
        self.e.apply(self.manifest,'system');self.state('estimated',persist_failure=True)
        before=(self.c.simulate/'data/keep.txt').read_bytes()
        with patch.object(self.e.backend,'write_image') as write:
            result=self.e.worker()
        write.assert_not_called();self.assertFalse(result['write_started'])
        self.assertEqual('clock_persist_failed',result['error']['code'])
        self.assertEqual(before,(self.c.simulate/'data/keep.txt').read_bytes())

    def test_reboot_checkpoint_failure_never_calls_systemctl(self):
        self.c.simulate=None;self.c.reboot=True
        with patch('armhpc_ota.clock.Clock.flush',side_effect=OTAError('clock_persist_failed','disk full')),patch('armhpc_ota.backend.run') as command:
            with self.assertRaises(OTAError):self.e.backend.request_reboot()
        command.assert_not_called()

    def test_ntp_correction_keeps_real_timestamp_and_sequence(self):
        job=self.e.apply(self.manifest,'system');self.state('synchronised',correction={'id':'back','direction':'backward','delta_seconds':-100})
        with patch('armhpc_ota.store.now',return_value='2000-01-01T00:00:00+00:00'):
            self.e.store.save(job,message='corrected')
        self.assertEqual('2000-01-01T00:00:00+00:00',job['updated'])
        self.assertEqual([1,2],[e['sequence'] for e in job['events']]);self.assertEqual('backward',job['events'][-1]['clock']['correction']['direction'])

    def test_chrony_configuration_survives_system_replacement(self):
        root=self.c.simulate/'roots/system';p=root/'etc/chrony/sources.d/lan.sources';p.parent.mkdir(parents=True);p.write_text('server 192.168.100.1 iburst\n')
        self.e.apply(self.manifest,'system');self.e.worker()
        self.assertEqual('server 192.168.100.1 iburst\n',p.read_text())

    def test_existing_request_id_not_recreated_after_clock_changes(self):
        import uuid
        request=str(uuid.uuid4());first=self.e.apply(self.manifest,'system',request_id=request)
        self.state('invalid');second=self.e.apply(self.manifest,'system',request_id=request)
        self.assertEqual(first['job_id'],second['job_id']);self.assertEqual(1,len(second['events']))


class ClockMaintenanceTests(unittest.TestCase):
    def setUp(self):
        test_lan.MaintenanceTests.setUp(self)
        payload=self.root/'pkg/armhpc-ota-0.3.0'
        (payload/'src/armhpc_ota/__init__.py').write_text('__version__="0.3.2"\n')
        service=payload/'compat/clock-services';service.mkdir(parents=True)
        (payload/'compat/clock_floor.py').write_text('# clock revision fixture\n')
        for name in ('armhpc-clock-floor.service','armhpc-clock-checkpoint.service','armhpc-clock-checkpoint.timer','armhpc-clock-shutdown.service','firstboot-clock.conf'):
            (service/name).write_text('[Unit]\nDescription=clock fixture '+name+'\n')
        runtime=self.root/'new-runtime.tar.xz'
        with tarfile.open(runtime,'w:xz') as archive:
            for p in payload.rglob('*'):
                if p.is_file():archive.add(p,arcname='armhpc-ota-0.3.2/'+p.relative_to(payload).as_posix())
        self.bundle=Path(tools_bundle(runtime,self.root/'new-published',self.key,'test')['bundle'])

    def test_clock_files_and_enable_links_all_three_roots(self):
        before=hashlib.sha256((self.root/'data/keep.txt').read_bytes()).hexdigest()
        maintenance.schedule(self.e,self.bundle);result=maintenance.worker(self.e)
        self.assertEqual('succeeded',result['maintenance']['stage'])
        for role in ('system','rescue_a','rescue_b'):
            root=self.root/'roots'/role
            self.assertTrue((root/'etc/systemd/system/armhpc-clock-checkpoint.timer').is_file())
            self.assertTrue((root/'etc/systemd/system/multi-user.target.wants/armhpc-clock-shutdown.service').is_symlink())
        self.assertEqual(before,hashlib.sha256((self.root/'data/keep.txt').read_bytes()).hexdigest())

    def test_enable_links_restored_exactly_on_rollback(self):
        p=self.root/'roots/system/etc/systemd/system/timers.target.wants/armhpc-clock-checkpoint.timer';p.parent.mkdir(parents=True)
        p.symlink_to('/original/custom-timer')
        maintenance.schedule(self.e,self.bundle);maintenance.worker(self.e)
        maintenance.schedule(self.e,rollback=True);result=maintenance.worker(self.e)
        self.assertEqual('rolled-back',result['maintenance']['stage']);self.assertEqual('/original/custom-timer',str(p.readlink()))
        self.assertFalse((self.root/'roots/rescue_a/etc/systemd/system/multi-user.target.wants/armhpc-clock-shutdown.service').exists())

    def test_interruption_resume_includes_clock_units(self):
        maintenance.schedule(self.e,self.bundle);original=maintenance.backup_and_install
        def interrupted(*args):
            if args[2]=='rescue_b':raise OSError('interrupted')
            return original(*args)
        with patch.object(maintenance,'backup_and_install',side_effect=interrupted):self.assertEqual('incomplete',maintenance.worker(self.e)['maintenance']['stage'])
        maintenance.schedule(self.e,self.bundle);self.assertEqual('succeeded',maintenance.worker(self.e)['maintenance']['stage'])

    def test_old_baseline_restores_latest_clock_runtime_and_timer(self):
        maintenance.schedule(self.e,self.bundle);maintenance.worker(self.e)
        root=self.root/'roots/system';p=root/'usr/lib/armhpc-ota/armhpc_ota/__init__.py';p.write_text('__version__="0.2.0"\n')
        (root/'etc/systemd/system/armhpc-clock-checkpoint.timer').unlink()
        maintenance.retain_installed_runtime(self.c,root)
        self.assertIn('0.3.2',p.read_text());self.assertTrue((root/'etc/systemd/system/armhpc-clock-checkpoint.timer').is_file())


class ClockServiceRollbackTests(unittest.TestCase):
    def test_interrupted_rollback_can_resume_after_shutdown_unit_was_removed(self):
        from types import SimpleNamespace
        from armhpc_ota import clock_resources
        def command(arguments,**kwargs):
            return SimpleNamespace(returncode=0,stdout='not-found' if arguments[-1]=='armhpc-clock-shutdown.service' else 'loaded')
        with patch.object(clock_resources.subprocess,'run',side_effect=command) as run:
            clock_resources.prepare_rollback(SimpleNamespace(simulate=None),Path('/'))
        commands=[call.args[0] for call in run.call_args_list]
        self.assertIn(['systemctl','stop','armhpc-clock-checkpoint.service'],commands)
        self.assertNotIn(['systemctl','stop','armhpc-clock-shutdown.service'],commands)

    def test_failed_shutdown_checkpoint_does_not_block_rollback_of_stopped_service(self):
        from types import SimpleNamespace
        from armhpc_ota import clock_resources
        def command(arguments,**kwargs):
            return SimpleNamespace(returncode=1 if 'stop' in arguments else 0,stdout='failed' if '--property=ActiveState' in arguments else 'loaded')
        with patch.object(clock_resources.subprocess,'run',side_effect=command):clock_resources.stop_loaded('armhpc-clock-shutdown.service')

    def test_absent_old_shutdown_unit_is_not_stopped_after_rollback(self):
        from types import SimpleNamespace
        from armhpc_ota import clock_resources
        with tempfile.TemporaryDirectory() as name:
            backup=Path(name);atomic_json(backup/'clock-active.json',{'armhpc-clock-floor.service':True,'armhpc-clock-checkpoint.timer':True,'armhpc-clock-shutdown.service':False})
            def command(arguments,**kwargs):
                return SimpleNamespace(returncode=0,stdout='not-found' if 'show' in arguments else '')
            with patch.object(clock_resources.subprocess,'run',side_effect=command) as run:
                clock_resources.activate(SimpleNamespace(simulate=None),backup,True)
            commands=[call.args[0] for call in run.call_args_list]
            self.assertIn(['systemctl','restart','armhpc-clock-floor.service'],commands)
            self.assertNotIn(['systemctl','stop','armhpc-clock-shutdown.service'],commands)


if __name__=='__main__':unittest.main()
