# SPDX-License-Identifier: GPL-3.0-only
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from armhpc_ota.config import Config
from armhpc_ota.device import layout, ensure_unmounted
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json
from armhpc_ota.metadata import validate_manifest, sign
from armhpc_ota.squashfs import TRAILER_BYTES, read_trailer, write_trailer, generation
from support import fixture, release


class SquashTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.config,self.key=fixture(self.root)
        self.config.storage_layout='oect-squashfs-ab-v2'
        self.board=self.config.board()
        d=json.loads((self.root/'device.json').read_text())
        for n in d['blocks']:
            role=n.get('fixture_role')
            if role in ('rescue_a','rescue_b'):
                n.update(fstype='squashfs',uuid=None,size=self.board['rescue_a_sectors']*512,partlabel=n['label'])
                n['start']=self.board['rescue_a_start'] if role=='rescue_a' else self.board['rescue_b_start']
            elif role=='shared':n.update(start=self.board['shared_start'],size=(15269854-self.board['shared_start']+1)*512)
        atomic_json(self.root/'device.json',d);self.device=d
        _,self.manifest=release(self.config,self.key)
        self.manifest.update(layout=self.board['layout'],anchor_abi=self.board['anchor_abi'],minimum_agent='0.2.0')
        a=next(x for x in self.manifest['artifacts'] if x['role']=='rescue-rootfs')
        self.image=self.root/'slot.bin';size=16*1024**2
        with self.image.open('wb') as f:f.truncate(size+TRAILER_BYTES)
        header=bytearray(96);header[:4]=b'hsqs';struct.pack_into('<I',header,12,1048576);struct.pack_into('<H',header,20,4)
        struct.pack_into('<HH',header,28,4,0);struct.pack_into('<Q',header,40,96)
        with self.image.open('r+b') as f:f.write(header)
        with self.image.open('rb') as f:digest=hashlib.sha256(f.read(size)).hexdigest()
        a.update(encoding='squashfs',filesystem='squashfs',size=size,expanded_size=size,sha256=digest,expanded_sha256=digest)
        self.signed=sign(self.manifest,self.key,'test')
    def tearDown(self):self.tmp.cleanup()
    def test_authenticated_slot_commit_and_invalidation(self):
        write_trailer(self.image,self.image.stat().st_size,self.signed)
        self.assertEqual(read_trailer(self.image,self.image.stat().st_size,self.config.trust)[0],self.manifest)
        write_trailer(self.image,self.image.stat().st_size)
        with self.assertRaisesRegex(OTAError,'committed'):read_trailer(self.image,self.image.stat().st_size,self.config.trust)
    def test_corrupted_root_rejected_even_with_valid_trailer(self):
        write_trailer(self.image,self.image.stat().st_size,self.signed)
        with self.image.open('r+b') as f:f.seek(4096);f.write(b'bad')
        with self.assertRaisesRegex(OTAError,'hash'):read_trailer(self.image,self.image.stat().st_size,self.config.trust)
    def test_wrong_layout_encoding_and_wrapped_image_rejected(self):
        validate_manifest(self.manifest)
        a=next(x for x in self.manifest['artifacts'] if x['role']=='rescue-rootfs')
        a['expanded_size']+=1
        with self.assertRaises(OTAError):validate_manifest(self.manifest)
        a['expanded_size']-=1;self.manifest['layout']='oect-ext4-ab-v1'
        with self.assertRaises(OTAError):validate_manifest(self.manifest)
    def test_squashfs_geometry_and_running_slot_guard(self):
        storage=layout(self.config,self.device,initialized=True)
        self.device['root']=storage['partitions']['rescue_a']['path']
        with self.assertRaises(OTAError):ensure_unmounted(self.config,self.device,storage['partitions']['rescue_a'])
        ensure_unmounted(self.config,self.device,storage['partitions']['rescue_b'])
        storage['partitions']['rescue_b']['start']+=1
        with self.assertRaises(OTAError):layout(self.config,self.device,initialized=True)
    def test_generations_are_separate_and_symlink_rejected(self):
        a=generation(self.config.state,'a','r2');b=generation(self.config.state,'b','r2')
        self.assertNotEqual(a,b)
        a.parent.mkdir(parents=True);a.symlink_to(self.root/'data')
        with self.assertRaises(OTAError):generation(self.config.state,'a','r2')

if __name__=='__main__':unittest.main()
