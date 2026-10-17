# SPDX-License-Identifier: GPL-3.0-only
import hashlib
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch
from armhpc_ota import boot_maintenance as boot
from armhpc_ota.boot_publish import build
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json,read_json,sha256
from armhpc_ota.metadata import sign
from support import fixture,release


class Boot034(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.r=Path(self.tmp.name)
        self.c,self.key=fixture(self.r,mode='rescue');self.c.storage_layout='oect-squashfs-ab-v2';self.e=Engine(self.c)
        b=self.c.board();d=read_json(self.r/'device.json')
        for n in d['blocks']:
            role=n.get('fixture_role')
            if role in ('rescue_a','rescue_b'):
                n.update(fstype='squashfs',uuid=None,size=b['rescue_a_sectors']*512,partlabel=n['label'],start=b['rescue_a_start'] if role=='rescue_a' else b['rescue_b_start'])
            elif role=='shared':n.update(start=b['shared_start'],size=(15269854-b['shared_start']+1)*512)
        atomic_json(self.r/'device.json',d)
        ctl=self.e.store.control();ctl.update(anchor_key_ids=['test'],anchor_abi=b['anchor_abi']);self.e.store.write_control(ctl)
        bootdir=self.r/'roots/boot'
        for rel in ('boot.scr','boot.cmd','extlinux/extlinux.conf','armbianEnv.txt'):
            p=bootdir/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('known-good '+rel)
        self.manifest_path,m=release(self.c,self.key,'diagnostic-1',2,kernel='6.12.111-old')
        m.update(layout=b['layout'],anchor_abi=b['anchor_abi'],minimum_agent='0.3.4')
        m['artifacts']=[a for a in m['artifacts'] if a['role'].startswith('rescue-')]
        self.files={}
        for a in m['artifacts']:
            name=a['role'][7:];p=self.r/'release'/('diagnostic-1-rescue-'+name);self.files[name]=p
            if name=='rootfs':
                with p.open('wb') as f:f.write(b'hsqs');f.truncate(16*1024**2)
                digest=sha256(p);a.update(encoding='squashfs',filesystem='squashfs',size=p.stat().st_size,expanded_size=p.stat().st_size,sha256=digest,expanded_sha256=digest)
        self.manifest_path.write_bytes(sign(m,self.key,'test'));self.recovery=self.r/'recovery-initrd';self.recovery.write_bytes(b'raw-initrd-fixture')
        old=ctl['confirmed']['rescue']['boot'];self.old=old
        self.bundle=self.r/'candidate.tar.xz'
        build(self.manifest_path,self.files['rootfs'],self.files['kernel'],self.files['dtb'],self.files['initramfs'],self.recovery,
              self.bundle,self.key,'test',self.c.trust,1,self.c.state/old['kernel']['path'],self.c.state/old['dtb']['path'])
    def tearDown(self):self.tmp.cleanup()
    def test_private_backup_export_gate_and_geometry(self):
        p=boot.plan(self.e,self.bundle);self.assertEqual(p['boot']['start_lba'],368640);self.assertEqual(p['boot']['sectors'],1048576)
        id=str(uuid.uuid4());r=boot.apply(self.e,self.bundle,id)['task'];self.assertEqual(r['stage'],'backup-ready')
        self.assertIn('SIMULATED',Path(r['backups']['BOOT-original.img']['path']).read_text())
        with self.assertRaisesRegex(OTAError,'Export/verify'):boot.apply(self.e,request_id=id,exported='0'*64)
        self.assertEqual((self.r/'roots/boot/boot.scr').read_text(),'known-good boot.scr')
    def test_signature_payload_and_release_reuse_reject(self):
        boot.validate_bundle(self.e,self.bundle)
        previous=(self.c.state/'boot-maintenance/releases/diagnostic-1/manifest.json');previous.write_bytes(b'changed')
        with self.assertRaisesRegex(OTAError,'immutable'):boot.validate_bundle(self.e,self.bundle)
        self.files['dtb'].write_bytes(b'different')
        with self.assertRaises(OTAError):build(self.manifest_path,self.files['rootfs'],self.files['kernel'],self.files['dtb'],self.files['initramfs'],self.recovery,
            self.r/'different.tar.xz',self.key,'test',self.c.trust,2,self.c.state/self.old['kernel']['path'],self.c.state/self.old['dtb']['path'])
    def test_rollback_does_not_restore_identity_time_or_data(self):
        id=str(uuid.uuid4());r=boot.apply(self.e,self.bundle,id)['task']
        atomic_json(self.c.state/'clock/resume-time.json',{'epoch':123456789});atomic_json(self.c.state/'identity.json',{'device_id':'device-001'})
        (self.r/'roots/boot/boot.scr').write_text('candidate')
        boot.rollback(self.e,id)
        self.assertEqual((self.r/'roots/boot/boot.scr').read_text(),'known-good boot.scr')
        self.assertEqual(read_json(self.c.state/'clock/resume-time.json')['epoch'],123456789)
        self.assertEqual((self.r/'data/keep.txt').read_text(),'DATA-MUST-NOT-CHANGE')
    def test_changed_backup_cannot_overwrite_boot(self):
        id=str(uuid.uuid4());r=boot.apply(self.e,self.bundle,id)['task']
        p=Path(r['backups']['BOOT-original.img']['path']).parent/'entries/boot.scr';p.write_text('corrupt')
        with self.assertRaisesRegex(OTAError,'entry changed'):boot.rollback(self.e,id)
        self.assertEqual((self.r/'roots/boot/boot.scr').read_text(),'known-good boot.scr')
        self.assertEqual(boot.record(self.c)['stage'], 'backup-ready')

    def test_missing_backup_preserves_task_stage_and_boot_entries(self):
        id=str(uuid.uuid4());r=boot.apply(self.e,self.bundle,id)['task']
        entry=Path(r['backups']['BOOT-original.img']['path']).parent/'entries/boot.scr'
        entry.unlink()
        with self.assertRaisesRegex(OTAError,'unavailable'):
            boot.rollback(self.e,id)
        self.assertEqual(boot.record(self.c)['stage'], 'backup-ready')
        self.assertEqual((self.r/'roots/boot/boot.scr').read_text(),'known-good boot.scr')

    def test_active_root_and_board_mismatch_gate(self):
        d=read_json(self.r/'device.json');d['mode']='system';d['root']='/dev/sda1';atomic_json(self.r/'device.json',d)
        with self.assertRaisesRegex(OTAError,'confirmed Rescue'):boot.apply(self.e,self.bundle,str(uuid.uuid4()))
    def test_interrupted_slot_keeps_original_boot_and_explicit_resume(self):
        id=str(uuid.uuid4());r=boot.apply(self.e,self.bundle,id)['task']
        d=read_json(self.r/'device.json');d['fault']='write-rescue_b';atomic_json(self.r/'device.json',d)
        with self.assertRaisesRegex(OTAError,'interruption'):boot.apply(self.e,request_id=id,exported=r['backups']['BOOT-rescue.img.xz']['sha256'])
        self.assertEqual(boot.record(self.c)['stage'],'failed-needs-recovery')
        self.assertEqual((self.r/'roots/boot/boot.scr').read_text(),'known-good boot.scr')
        self.assertEqual(self.e.store.control()['confirmed']['rescue']['slot'],'a')
        # A boot-service retry cannot write again without an explicit apply.
        self.assertEqual(boot.worker(self.e)['task']['stage'],'failed-needs-recovery')
        d.pop('fault');atomic_json(self.r/'device.json',d)
        result=boot.apply(self.e,request_id=id)
        self.assertEqual(result['task']['stage'],'awaiting-watchdog')
        self.assertEqual(self.e.store.control()['confirmed']['rescue']['slot'],'a')

    def test_interrupted_entry_switch_can_roll_back_both_paths(self):
        id=str(uuid.uuid4());r=boot.apply(self.e,self.bundle,id)['task']
        original=boot.install_entries
        def fail(c,root,directory,arguments):
            (root/'boot.scr').write_text('incomplete candidate entry')
            raise OSError('simulated switch interruption')
        with patch.object(boot,'install_entries',side_effect=fail):
            with self.assertRaisesRegex(OSError,'interruption'):boot.apply(self.e,request_id=id,exported=r['backups']['BOOT-rescue.img.xz']['sha256'])
        self.assertEqual(boot.record(self.c)['stage'],'failed-needs-recovery')
        boot.rollback(self.e,id)
        self.assertEqual((self.r/'roots/boot/boot.scr').read_text(),'known-good boot.scr')
        self.assertEqual((self.r/'roots/boot/extlinux/extlinux.conf').read_text(),'known-good extlinux/extlinux.conf')
        self.assertEqual((self.r/'data/keep.txt').read_text(),'DATA-MUST-NOT-CHANGE')

    def test_both_entry_types_select_same_pair(self):
        ext,script=boot.entry_files('/armhpc-maintenance/candidate','armhpc.boot-maintenance=task')
        for file in ('kernel','dtb','initramfs'):
            self.assertIn(('/armhpc-maintenance/candidate/'+file).encode(),ext);self.assertIn(('/armhpc-maintenance/candidate/'+file).encode(),script)
        self.assertIn(b'armhpc.boot-maintenance=task',ext);self.assertIn(b'armhpc.boot-maintenance=task',script)

if __name__=='__main__':unittest.main()
