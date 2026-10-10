# SPDX-License-Identifier: GPL-3.0-only
import copy
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
import uuid
from unittest.mock import patch
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json, read_json
from armhpc_ota.local_package import inspect
from armhpc_ota.metadata import sign
from armhpc_ota.receive import receive
from support import fixture, release, boot_fixture


class PushTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.config,self.key=fixture(self.tmp.name)
        self.engine=Engine(self.config)
        self.path,self.manifest=release(self.config,self.key)
        # Signed artifact URLs may belong to a retired publisher IP. Push never uses them.
        self.files={a['sha256']:Path(a['url'].removeprefix('file://')).read_bytes() for a in self.manifest['artifacts']}
        for a in self.manifest['artifacts']:a['url']='http://192.168.99.250:28780/blobs/'+a['sha256']
        self.path.write_bytes(sign(self.manifest,self.key,'test'))
        self.request=str(uuid.uuid4())
        self.network=patch.object(self.engine.transport,'download',side_effect=AssertionError('push contacted artifact URL'))
        self.network.start();self.addCleanup(self.network.stop)
        self.meta=patch.object(self.engine.transport,'metadata',side_effect=AssertionError('push contacted update source'))
        self.meta.start();self.addCleanup(self.meta.stop)

    def prepare(self,target='all',request=None):
        return receive(self.engine,str(self.path),target,request or self.request)

    def stage(self,target='all'):
        p=self.prepare(target)
        for a in p['artifacts']:
            if not a['complete']:Path(a['path']).write_bytes(self.files[a['sha256']])
        return receive(self.engine,str(self.path),target,self.request,'commit')

    def test_full_all_push_preserves_data_and_never_fetches_urls(self):
        self.assertTrue(self.stage()['complete'])
        job=self.engine.apply(self.manifest,local_only=True,request_id=self.request)
        self.assertTrue(read_json(self.engine.store.job_path(job['job_id']))['local_only'])
        self.assertEqual('awaiting-rescue',self.engine.worker()['stage'])
        boot_fixture(self.config,'rescue','a','6.12.111-old')
        self.assertEqual('trial-rescue',self.engine.worker()['stage'])
        from armhpc_ota.boot import select
        self.assertEqual('b',select(self.config)['slot'])
        boot_fixture(self.config,'rescue','b','6.13.1-test')
        self.assertEqual('ready',self.engine.confirm()['stage'])
        self.assertEqual('trial-system',self.engine.worker()['stage'])
        self.assertEqual('system',select(self.config)['target'])
        boot_fixture(self.config,'system',kernel='6.13.1-test')
        self.assertEqual('succeeded',self.engine.confirm()['stage'])
        self.assertEqual('DATA-MUST-NOT-CHANGE',(self.config.simulate/'data/keep.txt').read_text())
        self.assertEqual('user-file',(self.config.simulate/'roots/system/home/admin/keep.txt').read_text())

    def test_partial_resume_retains_offset_and_commits_same_request(self):
        p=self.prepare('rescue');item=p['artifacts'][0]
        Path(item['path']).write_bytes(self.files[item['sha256']][:17])
        resumed=self.prepare('rescue');self.assertEqual(17,resumed['artifacts'][0]['offset'])
        for a in resumed['artifacts']:
            with Path(a['path']).open('ab') as stream:stream.write(self.files[a['sha256']][a['offset']:])
        self.assertTrue(receive(self.engine,str(self.path),'rescue',self.request,'commit')['complete'])
        self.assertTrue(self.prepare('rescue')['complete'])

    def test_shared_kernel_payloads_are_sent_once(self):
        for suffix in ('kernel','dtb','initramfs'):
            source=next(a for a in self.manifest['artifacts'] if a['role']=='system-'+suffix)
            other=next(a for a in self.manifest['artifacts'] if a['role']=='rescue-'+suffix)
            for k in ('sha256','size','url'):other[k]=source[k]
        self.path.write_bytes(sign(self.manifest,self.key,'test'))
        self.assertEqual(5,len(self.prepare()['artifacts']))
        self.assertTrue(self.stage()['complete'])

    def test_wrong_full_payload_is_reset_for_reupload(self):
        item=self.prepare()['artifacts'][0]
        Path(item['path']).write_bytes(b'?'*item['size'])
        with self.assertRaisesRegex(OTAError,'signed size/hash'):receive(self.engine,str(self.path),'all',self.request,'commit')
        self.assertEqual(0,self.prepare()['artifacts'][0]['offset'])
        self.assertFalse((self.config.cache/item['sha256']).exists())

    def test_missing_payload_refused_without_creating_job(self):
        self.engine.manifest(location=str(self.path))
        with self.assertRaisesRegex(OTAError,'Upload and verify'):self.engine.apply(self.manifest,local_only=True)
        self.assertIsNone(self.engine.store.read())

    def test_cache_damage_after_submit_fails_before_write_without_download(self):
        self.stage();job=self.engine.apply(self.manifest,local_only=True)
        (self.config.cache/self.manifest['artifacts'][0]['sha256']).write_bytes(b'broken')
        result=self.engine.worker()
        self.assertEqual('failed-recoverable',result['stage']);self.assertFalse(result['write_started'])
        self.assertEqual('push_payload_missing',result['error']['code'])

    def test_request_cannot_change_target_or_transfer_mode(self):
        self.stage('rescue')
        with self.assertRaisesRegex(OTAError,'another device/package'):self.prepare('all')
        job=self.engine.apply(self.manifest,'rescue',request_id=self.request,local_only=True)
        self.assertEqual(job['job_id'],self.engine.apply(self.manifest,'rescue',request_id=self.request,local_only=True)['job_id'])
        with self.assertRaisesRegex(OTAError,'different device'):self.engine.apply(self.manifest,'rescue',request_id=self.request)

    def test_rejects_signature_board_space_and_active_job_before_upload(self):
        raw=self.path.read_bytes();doc=json.loads(raw);doc['signature']='A'*88;self.path.write_text(json.dumps(doc))
        with self.assertRaises(OTAError):self.prepare()
        self.path.write_bytes(raw)
        bad=copy.deepcopy(self.manifest);bad['board']='other-board';bad['release']='bad-board';self.path.write_bytes(sign(bad,self.key,'test'))
        with self.assertRaises(OTAError):self.prepare()
        self.path.write_bytes(raw)
        with patch('armhpc_ota.engine.shutil.disk_usage',return_value=shutil._ntuple_diskusage(1,1,0)):
            with self.assertRaisesRegex(OTAError,'space'):self.prepare()
        self.stage();self.engine.apply(self.manifest,local_only=True)
        with self.assertRaisesRegex(OTAError,'active OTA task'):self.prepare()

    def test_symlink_staging_rejected(self):
        item=self.prepare()['artifacts'][0];p=Path(item['path']);p.symlink_to(self.path)
        with self.assertRaisesRegex(OTAError,'symbolic link'):self.prepare()

    def test_rescue_push_works_without_sata(self):
        value=read_json(self.config.simulate/'device.json')
        value['blocks']=[x for x in value['blocks'] if not x['path'].startswith('/dev/sd')]
        atomic_json(self.config.simulate/'device.json',value);boot_fixture(self.config,'rescue','a')
        self.stage('rescue')
        self.engine.apply(self.manifest,'rescue',local_only=True)
        self.assertEqual('trial-rescue',self.engine.worker()['stage'])


class LocalPackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);(self.root/'device').mkdir();self.config,self.key=fixture(self.root/'device')
        self.path,self.manifest=release(self.config,self.key)
        self.bundle=self.root/'bundle';(self.bundle/'blobs').mkdir(parents=True)
        for a in self.manifest['artifacts']:
            shutil.copyfile(Path(a['url'].removeprefix('file://')),self.bundle/'blobs'/a['sha256'])
            a['url']='http://192.168.88.88:8080/blobs/'+a['sha256']
        self.path.write_bytes(sign(self.manifest,self.key,'test'))
        dest=self.bundle/'releases/r2/manifest.json';dest.parent.mkdir(parents=True);shutil.copyfile(self.path,dest)

    def test_archive_and_directory_ignore_publisher_ip(self):
        plain=inspect(self.bundle,self.root/'unpacked');self.assertEqual('r2',plain['release'])
        archive=self.root/'package.tar.xz'
        with tarfile.open(archive,'w:xz') as t:
            for p in self.bundle.rglob('*'):
                if p.is_file():t.add(p,arcname=p.relative_to(self.bundle).as_posix())
        self.assertEqual(plain['manifest_sha256'],inspect(archive,self.root/'unpacked')['manifest_sha256'])
        self.assertEqual(plain['manifest_sha256'],inspect(archive,self.root/'unpacked')['manifest_sha256'])

    def test_corrupt_payload_rejected(self):
        (self.bundle/'blobs'/self.manifest['artifacts'][0]['sha256']).write_bytes(b'broken')
        with self.assertRaisesRegex(OTAError,'Local payload'):inspect(self.bundle,self.root/'unpacked')

    def test_traversal_links_and_duplicates_rejected(self):
        for kind in ('traversal','symlink','duplicate'):
            with self.subTest(kind=kind):
                archive=self.root/(kind+'.tar.xz')
                with tarfile.open(archive,'w:xz') as t:
                    m=tarfile.TarInfo('../escaped' if kind=='traversal' else 'file')
                    if kind=='symlink':m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd'
                    else:m.size=1
                    t.addfile(m,None if kind=='symlink' else io.BytesIO(b'a'))
                    if kind=='duplicate':t.addfile(m,io.BytesIO(b'a'))
                with self.assertRaises(OTAError):inspect(archive,self.root/'unpacked')
        self.assertFalse((self.root/'escaped').exists())


if __name__=='__main__':unittest.main()
