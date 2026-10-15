# SPDX-License-Identifier: GPL-3.0-only
import struct
import unittest
import uuid
import zlib
import hashlib
from pathlib import Path
from armhpc_ota import boot_maintenance as boot, boot_platform, guardian_activation, watchdog
from armhpc_ota.boot_publish import build
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json, read_json
from armhpc_ota.metadata import sign
from test_boot_034 import Boot034
from support import release,boot_fixture


class OespBootMaintenance(unittest.TestCase):
    def setUp(self):
        Boot034.setUp(self)
        self.c.profile='wxy-oesp-v22'
        self.c.storage_layout='oesp-mbr-squashfs-ab-v1'
        board=self.c.board()
        device=read_json(self.r/'device.json')
        device['board']=board['id']
        for item in device['blocks']:
            if item.get('tran')=='sata':
                item['serial']='fixture-sata-device'
            role=item.get('fixture_role')
            if role:
                item['label']=board['labels'][role]
            if role=='boot':
                item.update(fstype='vfat',start=board['boot_start'])
            elif role in ('rescue_a','rescue_b'):
                item['start']=board[role+'_start']
            elif role=='shared':
                item.update(start=board['shared_start'],size=(15269854-board['shared_start'])*512)
        atomic_json(self.r/'device.json',device)
        control=self.e.store.control()
        control['anchor_abi']=board['anchor_abi']
        self.e.store.write_control(control)
        old=read_json(self.c.state/'manifests/r1.json')['payload']
        old.update(board=board['id'],layout=board['layout'],anchor_abi=board['anchor_abi'])
        (self.c.state/'manifests/r1.json').write_bytes(sign(old,self.key,'test'))
        candidate=read_json(self.manifest_path)['payload']
        candidate.update(board=board['id'],layout=board['layout'],anchor_abi=board['anchor_abi'],minimum_agent='1.1.1')
        self.manifest_path.write_bytes(sign(candidate,self.key,'test'))
        self.bundle.unlink()
        build(self.manifest_path,self.files['rootfs'],self.files['kernel'],self.files['dtb'],self.files['initramfs'],self.recovery,
              self.bundle,self.key,'test',self.c.trust,1,self.c.state/self.old['kernel']['path'],self.c.state/self.old['dtb']['path'])
        for name in ('aml_autoscript','aml_autoscript.cmd'):
            (self.r/'roots/boot'/name).write_text('known-good '+name)

    def tearDown(self):
        Boot034.tearDown(self)

    def test_new_pair_can_stage_with_export_and_roll_back_all_vendor_entries(self):
        preview=boot.plan(self.e,self.bundle)
        self.assertEqual(preview['boot']['start_lba'],204800)
        task_id=str(uuid.uuid4())
        result=boot.apply(self.e,self.bundle,task_id)['task']
        self.assertEqual(result['stage'],'backup-ready')
        self.assertEqual(len(result['entry_hashes']),6)
        result=boot.apply(self.e,request_id=task_id,exported=result['backups']['BOOT-rescue.img.xz']['sha256'])['task']
        self.assertEqual(result['stage'],'awaiting-watchdog')
        folder=self.r/'roots/boot/armhpc-maintenance/diagnostic-1'
        wrapped=(folder/'initramfs.uboot').read_bytes()
        self.assertEqual(wrapped[64:],self.files['initramfs'].read_bytes())
        self.assertEqual(struct.unpack_from('>I',wrapped)[0],0x27051956)
        cmd=(self.r/'roots/boot/boot.cmd').read_text()
        self.assertIn('0x08080000',cmd)
        self.assertIn('fatload',cmd)
        self.assertIn('console=ttyAML0,115200',cmd)
        self.assertIn('meson_gxbb_wdt.nowayout=1',cmd)
        self.assertNotIn('console=ttyS2',cmd)
        self.assertEqual(self.e.store.control()['confirmed']['rescue']['slot'],'a')
        boot.rollback(self.e,task_id)
        for name in boot_platform.entry_names(self.c.board()):
            self.assertEqual((self.r/'roots/boot'/name).read_text(),'known-good '+name)
        self.assertEqual((self.r/'data/keep.txt').read_text(),'DATA-MUST-NOT-CHANGE')

    def test_changed_vendor_backup_prevents_rollback(self):
        task_id=str(uuid.uuid4())
        result=boot.apply(self.e,self.bundle,task_id)['task']
        entries=Path(result['backups']['BOOT-original.img']['path']).parent/'entries'
        (entries/'aml_autoscript').write_text('tampered')
        with self.assertRaises(OTAError):
            boot.rollback(self.e,task_id)
        self.assertEqual((self.r/'roots/boot/boot.scr').read_text(),'known-good boot.scr')

    def test_oesp_watchdog_prepare_preserves_real_acceptance_requirement(self):
        prepared=watchdog.prepare(self.e)
        self.assertEqual(prepared['board'],'wxy-oesp-v22')
        self.assertEqual(prepared['management_interfaces'],['eth0','eth1'])
        self.assertFalse(prepared['hardware_verified'])
        watchdog.test(self.e,prepared['test_id'],True)
        with self.assertRaises(OTAError):
            watchdog.report(self.e,prepared['test_id'],confirmed=True)

    def paired_bundle(self):
        manifest_path,manifest=release(self.c,self.key,'paired-next',3,kernel='6.12.111-old')
        board=self.c.board()
        manifest.update(board=board['id'],layout=board['layout'],anchor_abi=board['anchor_abi'],minimum_agent='1.1.1')
        for artifact in manifest['artifacts']:
            role=artifact['role']
            path=self.r/'release'/('paired-next-'+role)
            if role=='rescue-rootfs':
                with path.open('wb') as stream:stream.write(b'hsqs');stream.truncate(16*1024**2)
                digest=hashlib.sha256(path.read_bytes()).hexdigest()
                artifact.update(encoding='squashfs',filesystem='squashfs',size=path.stat().st_size,
                                expanded_size=path.stat().st_size,sha256=digest,expanded_sha256=digest)
            elif role.startswith('system-') and role!='system-rootfs':
                path.write_bytes((self.r/'release'/('paired-next-rescue-'+role[7:])).read_bytes())
                artifact.update(size=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        manifest_path.write_bytes(sign(manifest,self.key,'test'))
        bundle=self.r/'paired-next.tar.xz'
        files=self.r/'release'
        build(manifest_path,files/'paired-next-rescue-rootfs',files/'paired-next-rescue-kernel',
              files/'paired-next-rescue-dtb',files/'paired-next-rescue-initramfs',self.recovery,
              bundle,self.key,'test',self.c.trust,2,self.c.state/self.old['kernel']['path'],
              self.c.state/self.old['dtb']['path'],system_rootfs=files/'paired-next-system-rootfs')
        return bundle

    def enter_paired_system_phase(self):
        task_id=str(uuid.uuid4())
        task=boot.apply(self.e,self.paired_bundle(),task_id)['task']
        task=boot.apply(self.e,request_id=task_id,exported=task['backups']['BOOT-rescue.img.xz']['sha256'])['task']
        boot_fixture(self.c,'rescue',task['inactive_slot'],kernel='6.12.111-old')
        task.update(stage='preparing-system',watchdog_checks_completed=True)
        boot.save(self.c,task)
        from armhpc_ota.device import layout,discover
        return boot.begin_paired_system(self.e,task,layout(self.c,discover(self.c),initialized=True))['task']

    def test_paired_system_reuses_engine_and_requires_health_before_commit(self):
        task=self.enter_paired_system_phase()
        self.assertEqual(task['stage'],'updating-system')
        self.assertEqual(self.e.store.control()['confirmed']['rescue']['slot'],'b')
        self.assertTrue(self.e.store.control()['system_blocked'])
        self.assertEqual(self.e.store.read()['job_id'],task['system_job_id'])
        job=self.e.worker()
        self.assertEqual(job['stage'],'trial-system')
        self.assertEqual(boot.record(self.c)['stage'],'updating-system')
        boot_fixture(self.c,'system',kernel='6.12.111-old')
        confirmed=self.e.confirm()
        self.assertEqual(confirmed['stage'],'succeeded')
        self.assertEqual(boot.record(self.c)['stage'],'committed')
        self.assertFalse(boot.record(self.c)['internal_watchdog_passed'])
        self.assertFalse(self.e.store.control()['system_blocked'])
        self.assertEqual((self.r/'data/keep.txt').read_text(),'DATA-MUST-NOT-CHANGE')

    def test_interrupted_paired_write_does_not_allow_original_system_to_boot_after_rollback(self):
        task=self.enter_paired_system_phase()
        device=read_json(self.r/'device.json');device['fault']='write-system'
        atomic_json(self.r/'device.json',device)
        job=self.e.worker()
        self.assertEqual(job['stage'],'failed-recoverable')
        self.assertTrue(job['write_started'])
        self.assertIsNone(self.e.store.control()['trial'])
        boot.rollback(self.e,task['task_id'])
        self.assertTrue(self.e.store.control()['system_blocked'])
        self.assertEqual(self.e.store.control()['next']['target'],'rescue')
        self.assertEqual((self.r/'data/keep.txt').read_text(),'DATA-MUST-NOT-CHANGE')


def test_native_script_and_ramdisk_crc_envelopes():
    for data,kind in [(boot_platform.script_image(b'echo entry\n'),6),(boot_platform.ramdisk(b'raw initramfs'),3)]:
        fields=boot_platform.HEADER.unpack_from(data)
        header=bytearray(data[:64]);struct.pack_into('>I',header,4,0)
        assert fields[0]==0x27051956 and fields[1]==zlib.crc32(header)
        assert fields[3]==len(data)-64 and fields[6]==zlib.crc32(data[64:])
        assert fields[7:11]==(5,2,kind,0)


def test_second_management_interface_can_supply_guardian_readiness():
    def command(*arguments):
        interface=arguments[-1]
        return {'rc':0,'output':'[{"addr_info":[{"family":"inet"}]}]' if interface=='eth1' else '[{"addr_info":[]}]'}
    result=guardian_activation.network_ready(['eth0','eth1'],command,lambda path:'1')
    assert result['interface']=='eth1'
    assert guardian_activation.network_ready(['eth0'],command,lambda path:'1') is None
