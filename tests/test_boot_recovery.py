# SPDX-License-Identifier: GPL-3.0-only
import uuid
from unittest.mock import patch
from armhpc_ota import boot_maintenance as boot,boot_recovery
from armhpc_ota.errors import OTAError
from armhpc_ota.io import read_json,atomic_json,sha256
from test_oesp_boot_maintenance import OespBootMaintenance


class BootRecovery(OespBootMaintenance):
    def prepared(self):
        task_id=str(uuid.uuid4())
        task=boot.apply(self.e,self.bundle,task_id)['task']
        image=__import__('pathlib').Path(task['backups']['BOOT-rescue.img']['path'])
        with image.open('r+b') as stream:stream.truncate(task['boot']['sectors']*512)
        task['backups']['BOOT-rescue.img'].update(bytes=image.stat().st_size,sha256=sha256(image));boot.save(self.c,task)
        return task_id,task

    def test_restore_preview_and_same_partition_readback_leave_data_and_identity(self):
        task_id,task=self.prepared()
        preview=boot_recovery.restore(self.e,task_id)
        self.assertFalse((self.r/'restored-BOOT.img').exists())
        self.assertEqual(preview['boot']['sectors'],1048576)
        result=boot_recovery.restore(self.e,task_id,True)
        self.assertEqual(result['stage'],'restored-awaiting-rollback')
        self.assertFalse(result['hardware_verified'])
        self.assertEqual(sha256(self.r/'restored-BOOT.img'),task['backups']['BOOT-rescue.img']['sha256'])
        self.assertEqual((self.r/'data/keep.txt').read_text(),'DATA-MUST-NOT-CHANGE')
        boot.rollback(self.e,task_id)
        self.assertEqual(boot.record(self.c)['stage'],'rolled-back')

    def test_binding_hash_cid_root_and_geometry_fail_before_write(self):
        task_id,task=self.prepared()
        for change in ({'device_id':'0'*64},{'emmc_cid_sha256':'0'*64},
                       {'boot':{**task['boot'],'start_lba':task['boot']['start_lba']+1}}):
            with self.subTest(change=change):
                boot.save(self.c,{**task,**change})
                with self.assertRaises(OTAError):boot_recovery.restore(self.e,task_id,True)
                self.assertFalse((self.r/'restored-BOOT.img').exists())
        boot.save(self.c,task)
        original=read_json(self.r/'device.json');altered={**original,'root':'/dev/sda1','mode':'system'}
        atomic_json(self.r/'device.json',altered)
        with self.assertRaises(OTAError):boot_recovery.restore(self.e,task_id,True)
        atomic_json(self.r/'device.json',original)
        with open(task['backups']['BOOT-rescue.img']['path'],'ab') as stream:stream.write(b'changed')
        with self.assertRaises(OTAError):boot_recovery.restore(self.e,task_id,True)
        self.assertFalse((self.r/'restored-BOOT.img').exists())

    def test_failed_write_preserves_task_and_retry_uses_original_image(self):
        task_id,task=self.prepared()
        with patch('armhpc_ota.boot_maintenance.stream_copy',side_effect=OSError('power loss')):
            with self.assertRaises(OSError):boot_recovery.restore(self.e,task_id,True)
        self.assertEqual(boot.record(self.c)['recovery_restore']['stage'],'writing')
        self.assertEqual(boot.record(self.c)['task_id'],task_id)
        self.assertEqual(boot_recovery.restore(self.e,task_id,True)['stage'],'restored-awaiting-rollback')
