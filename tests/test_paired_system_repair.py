# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
import unittest
from unittest import mock
import uuid
from armhpc_ota import boot_maintenance as boot,maintenance
from armhpc_ota.errors import OTAError
from armhpc_ota.io import read_json,sha256
from support import boot_fixture
from test_oesp_boot_maintenance import OespBootMaintenance


class PairedSystemRepair(unittest.TestCase):
    setUp=OespBootMaintenance.setUp
    tearDown=OespBootMaintenance.tearDown
    paired_bundle=OespBootMaintenance.paired_bundle

    def paused(self):
        task_id=str(uuid.uuid4())
        task=boot.apply(self.e,self.paired_bundle('firmware-update'),task_id)['task']
        task=boot.apply(self.e,request_id=task_id,exported=task['backups']['BOOT-rescue.img.xz']['sha256'])['task']
        boot_fixture(self.c,'rescue',task['inactive_slot'],kernel='6.12.111-old')
        self.e.confirm();self.e.worker()
        boot_fixture(self.c,'system',kernel='6.12.111-old')
        with mock.patch.object(self.e.backend,'health',side_effect=OTAError('health_node_runtime','CRI probe timed out')):
            self.e.confirm()
        boot_fixture(self.c,'rescue',task['inactive_slot'],kernel='6.12.111-old')
        task=boot.record(self.c)
        self.assertEqual(self.e.store.read()['stage'],'failed-recoverable')
        return task

    def test_same_job_retrials_without_rootfs_rewrite_and_commits_after_health(self):
        task=self.paused();job_id=task['system_job_id']
        before_data=(self.r/'data/keep.txt').read_bytes()
        before_boot={p.name:sha256(p) for p in (self.r/'roots/boot').rglob('*') if p.is_file()}
        self.assertEqual(boot.paused_system_binding(self.e)['system_job_id'],job_id)
        boot.resume_system(self.e,task['task_id'])
        job=self.e.store.read();self.assertEqual(job['job_id'],job_id);self.assertEqual(job['stage'],'ready')
        self.assertEqual(job['trial_failures'][0]['error']['code'],'health_node_runtime')
        with mock.patch.object(self.e.backend,'write_image',side_effect=AssertionError('No rootfs rewrite')):
            self.e.worker()
        self.assertEqual(self.e.store.read()['stage'],'trial-system')
        boot_fixture(self.c,'system',kernel='6.12.111-old');self.e.confirm()
        self.assertEqual(self.e.store.read()['stage'],'succeeded')
        self.assertEqual(boot.record(self.c)['stage'],'committed')
        self.assertEqual((self.r/'data/keep.txt').read_bytes(),before_data)
        self.assertEqual({p.name:sha256(p) for p in (self.r/'roots/boot').rglob('*') if p.is_file()},before_boot)

    def test_wrong_id_and_changed_signed_bundle_cannot_resume(self):
        task=self.paused();before=read_json(self.e.store.job_path(task['system_job_id']))
        with self.assertRaises(OTAError):boot.resume_system(self.e,str(uuid.uuid4()))
        Path(task['bundle']).write_bytes(b'changed')
        with self.assertRaises(OTAError):boot.resume_system(self.e,task['task_id'])
        self.assertEqual(read_json(self.e.store.job_path(task['system_job_id'])),before)

    def test_incomplete_write_nonhealth_failure_and_wrong_slot_remain_blocked(self):
        task=self.paused();job=self.e.store.read()
        for change in ({'checkpoints':[]},{'error':{'code':'payload_hash'}},{'stage':'trial-system'}):
            changed={**job,**change};self.e.store.save(changed)
            with self.assertRaises(OTAError):boot.paused_system_binding(self.e)
            self.e.store.save(job)
        boot_fixture(self.c,'rescue',task['original_slot'],kernel='6.12.111-old')
        with self.assertRaises(OTAError):boot.paused_system_binding(self.e)

    def test_pending_boot_and_revoked_signer_cannot_admit_repair(self):
        task=self.paused();control=self.e.store.control()
        for changed in ({'boot_attempt':{'pending':True}},{'anchor_key_ids':[]}):
            self.e.store.write_control({**control,**changed})
            with self.assertRaises(OTAError):boot.paused_system_binding(self.e)
            self.e.store.write_control(control)

    def test_signed_userland_maintenance_keeps_failed_firmware_binding(self):
        task=self.paused();job_before=self.e.store.read();control_before=self.e.store.control()
        bundle=self.r/'tools.tar.xz';bundle.write_bytes(b'authenticated by the isolated prepare unit')
        payload=self.r/'tools';payload.mkdir()
        manifest={'version':'1.2.3','revision':'r9','display_version':'1.2.3-r9','artifact':{'sha256':'0'*64}}
        with mock.patch.object(maintenance,'prepare',return_value=(manifest,payload)):
            maintenance.schedule(self.e,bundle,request_id=str(uuid.uuid4()))
        record=maintenance.record(self.c)
        self.assertEqual(record['repair_boot_task']['task_id'],task['task_id'])
        self.assertEqual(record['repair_boot_task']['system_job_id'],task['system_job_id'])
        self.assertEqual(self.e.store.read(),job_before);self.assertEqual(self.e.store.control(),control_before)


if __name__=='__main__':unittest.main()
