# SPDX-License-Identifier: GPL-3.0-only
import unittest
import io
import json
import tarfile
import uuid
from unittest import mock
from types import SimpleNamespace
from pathlib import Path
from armhpc_ota import boot_maintenance as boot
from armhpc_ota.errors import OTAError
from armhpc_ota.io import read_json
from armhpc_ota.metadata import sign
from support import boot_fixture
import test_oesp_boot_maintenance as fixtures


class FirmwareUpdate(unittest.TestCase):
    setUp=fixtures.OespBootMaintenance.setUp
    tearDown=fixtures.OespBootMaintenance.tearDown
    paired_bundle=fixtures.OespBootMaintenance.paired_bundle

    def test_signed_firmware_boot_uses_normal_health_and_retains_hardware_status(self):
        task_id=str(uuid.uuid4())
        task=boot.apply(self.e,self.paired_bundle('firmware-update'),task_id)['task']
        self.assertEqual(task['purpose'],'firmware-update')
        self.assertEqual(task['stage'],'backup-ready')
        task=boot.apply(self.e,request_id=task_id,exported=task['backups']['BOOT-rescue.img.xz']['sha256'])['task']
        self.assertEqual(task['stage'],'awaiting-firmware')
        with self.assertRaises(OTAError):boot.apply(self.e,request_id=task_id,commit=True)
        boot_fixture(self.c,'rescue',task['inactive_slot'],kernel='6.12.111-old')
        self.e.confirm()
        task=boot.record(self.c)
        self.assertEqual(task['stage'],'updating-system')
        job_id=task['system_job_id']
        self.e.worker()
        boot_fixture(self.c,'system',kernel='6.12.111-old')
        self.assertEqual(self.e.confirm()['stage'],'succeeded')
        task=boot.record(self.c)
        self.assertEqual(task['stage'],'committed')
        self.assertEqual(task['system_job_id'],job_id)
        self.assertFalse(task['internal_watchdog_passed'])
        self.assertFalse(task['firmware_boot_verified'])
        self.assertEqual((self.r/'data/keep.txt').read_text(),'DATA-MUST-NOT-CHANGE')

    def test_task_journal_cannot_change_a_diagnostic_signature_into_firmware_acceptance(self):
        task_id=str(uuid.uuid4())
        task=boot.apply(self.e,self.paired_bundle(),task_id)['task']
        task=boot.apply(self.e,request_id=task_id,exported=task['backups']['BOOT-rescue.img.xz']['sha256'])['task']
        task.update(purpose='firmware-update',ordinary_boot_healthy=True,firmware_boot_healthy=True)
        boot.save(self.c,task)
        boot_fixture(self.c,'rescue',task['inactive_slot'],kernel='6.12.111-old')
        with self.assertRaises(OTAError) as error:boot.apply(self.e,request_id=task_id,commit=True)
        self.assertEqual(error.exception.code,'boot_purpose')

    def test_firmware_update_rejects_agent_older_than_1_2_1(self):
        bundle = self.paired_bundle('firmware-update')
        with tarfile.open(bundle, 'r:xz') as archive:
            files = {item.name: archive.extractfile(item).read() for item in archive}
        envelope = json.loads(files['manifest.json'])
        self.assertEqual(envelope['payload']['minimum_agent'], '1.2.1')
        envelope['payload']['minimum_agent'] = '1.2.0'
        files['manifest.json'] = sign(envelope['payload'], self.key, 'test')
        changed = self.r / 'old-firmware-agent.tar.xz'
        with tarfile.open(changed, 'w:xz') as archive:
            for name, raw in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        with self.assertRaises(OTAError) as error:
            boot.plan(self.e, changed)
        self.assertEqual(error.exception.code, 'boot_agent')

    def test_semantic_minimum_agent_comparison(self):
        self.assertLess(boot.version_tuple('1.2.1'),boot.version_tuple('1.2.10'))
        with self.assertRaises(OTAError):boot.version_tuple('1.3')


class RestoredServiceHealth(unittest.TestCase):
    def test_completed_oneshot_requires_real_execution_and_active_timers(self):
        from armhpc_ota.node_runtime import firmware_health
        unit={'Type':'oneshot','Result':'success','ExecMainStatus':'0','ExecMainStartTimestampMonotonic':'123',
              'ActiveState':'inactive'}
        state={'installed':{'ready':True},'desired':{'owned.service':{'enabled':True},'owned.timer':{'enabled':True}},
               'running':{'owned.service':unit,'owned.timer':{'ActiveState':'active'}}}
        libraries={'node_state':SimpleNamespace(kernel_status=lambda:{'ready':True},status=lambda:state),
                   'network_ready':SimpleNamespace(inspect=lambda value:{'ready':True},policy=lambda:{})}
        with mock.patch.dict('sys.modules',libraries),mock.patch('armhpc_ota.node_runtime.Path.is_file',return_value=False):
            firmware_health('system')
            unit['ExecMainStartTimestampMonotonic']='0'
            with self.assertRaises(OTAError):firmware_health('system')
            unit['ExecMainStartTimestampMonotonic']='123'
            state['running']['owned.timer']['ActiveState']='failed'
            with self.assertRaises(OTAError):firmware_health('system')


if __name__=='__main__':unittest.main()
