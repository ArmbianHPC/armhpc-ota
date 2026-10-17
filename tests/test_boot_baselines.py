# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
import io
import json
from pathlib import Path
import shutil
import tarfile
import unittest
import uuid
from armhpc_ota import boot_maintenance as boot, boot_recovery
from armhpc_ota.errors import OTAError
from armhpc_ota.io import sha256
from armhpc_ota.metadata import sign
from test_oesp_boot_maintenance import OespBootMaintenance


class RecoveryBaselines(unittest.TestCase):
    setUp=OespBootMaintenance.setUp
    tearDown=OespBootMaintenance.tearDown
    paired_bundle=OespBootMaintenance.paired_bundle

    def package(self):
        bundle=self.paired_bundle('firmware-update')
        with tarfile.open(bundle,'r:xz') as archive:
            value=json.loads(archive.extractfile('manifest.json').read())['payload']
        return bundle,value

    def current_baseline(self, manifest):
        control=self.e.store.control()
        current=dict(control['confirmed']['rescue']['boot'])
        for kind in ('kernel','dtb','initramfs'):
            path=self.c.state/'kernels/current/rescue'/kind
            path.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(self.r/'release'/('paired-next-rescue-'+kind),path)
            current[kind]={'path':path.relative_to(self.c.state).as_posix(),'sha256':sha256(path)}
        current.update(release='current',kernel_release=manifest['kernel_release'])
        control['confirmed']['rescue']['boot']=current
        self.e.store.write_control(control)
        return current

    def test_legacy_baseline_keeps_its_signed_recovery_initramfs(self):
        bundle,_=self.package()
        self.assertEqual('recovery-initramfs',boot.plan(self.e,bundle)['recovery_initramfs'])
        task=boot.apply(self.e,bundle,str(uuid.uuid4()))['task']
        self.assertEqual(self.recovery.read_bytes(),(self.r/'recovery-boot/armhpc-recovery/initramfs').read_bytes())
        self.assertEqual(task['recovery']['files']['initramfs']['sha256'],sha256(self.recovery))

    def test_current_baseline_uses_the_signed_candidate_recovery_and_can_roll_back(self):
        bundle,manifest=self.package();self.current_baseline(manifest)
        self.assertEqual('initramfs',boot.plan(self.e,bundle)['recovery_initramfs'])
        before=(self.r/'data/keep.txt').read_bytes()
        task=boot.apply(self.e,bundle,str(uuid.uuid4()))['task']
        candidate=self.r/'release/paired-next-rescue-initramfs'
        self.assertEqual(candidate.read_bytes(),(self.r/'recovery-boot/armhpc-recovery/initramfs').read_bytes())
        self.assertEqual(task['recovery']['files']['initramfs']['sha256'],sha256(candidate))
        image=Path(task['backups']['BOOT-rescue.img']['path'])
        with image.open('r+b') as stream:stream.truncate(task['boot']['sectors']*512)
        task['backups']['BOOT-rescue.img'].update(bytes=image.stat().st_size,sha256=sha256(image));boot.save(self.c,task)
        self.assertEqual(task['task_id'],boot_recovery.restore(self.e,task['task_id'])['task_id'])
        boot.rollback(self.e,task['task_id'])
        self.assertEqual('rolled-back',boot.record(self.c)['stage'])
        self.assertEqual(before,(self.r/'data/keep.txt').read_bytes())

    def test_unknown_baseline_remains_rejected_before_boot_or_task_write(self):
        bundle,manifest=self.package();self.current_baseline(manifest)
        control=self.e.store.control();control['confirmed']['rescue']['boot']['dtb']['sha256']='f'*64
        self.e.store.write_control(control)
        entries={p: p.read_bytes() for p in (self.r/'roots/boot').rglob('*') if p.is_file()}
        with self.assertRaises(OTAError) as caught:boot.apply(self.e,bundle,str(uuid.uuid4()))
        self.assertEqual('boot_baseline',caught.exception.code)
        self.assertIsNone(boot.record(self.c))
        self.assertTrue(all(p.read_bytes()==data for p,data in entries.items()))

    def test_signed_variant_cannot_redirect_to_an_unpaired_or_arbitrary_file(self):
        bundle,manifest=self.package()
        for changes in ({'initramfs':'system-rootfs'},{'dtb_sha256':'f'*64}):
            value={**manifest,'recovery_variants':[{**manifest['recovery_variants'][0],**changes}]}
            with self.subTest(changes=changes),self.assertRaises(OTAError) as caught:
                boot.select_recovery_initramfs(value,self.old)
            self.assertEqual('boot_recovery_variants',caught.exception.code)

    def test_legacy_signed_packages_do_not_gain_an_unsigned_new_baseline(self):
        bundle,manifest=self.package();current=self.current_baseline(manifest)
        manifest.pop('recovery_variants')
        with self.assertRaises(OTAError) as caught:boot.select_recovery_initramfs(manifest,current)
        self.assertEqual('boot_baseline',caught.exception.code)

    def test_changed_recovery_choice_is_refused_before_backup_write(self):
        bundle,manifest=self.package();self.current_baseline(manifest)
        preview=boot.plan(self.e,bundle)
        task={**preview,'task_id':str(uuid.uuid4()),'original_boot':self.e.store.control()['confirmed']['rescue']['boot'],
              'recovery_initramfs':'recovery-initramfs'}
        _,_,base,_=boot.validate_bundle(self.e,bundle)
        with self.assertRaises(OTAError) as caught:boot.backup(self.e,{},task,base)
        self.assertEqual('boot_recovery_binding',caught.exception.code)
        self.assertFalse((self.c.cache/'boot-backups'/task['task_id']).exists())
