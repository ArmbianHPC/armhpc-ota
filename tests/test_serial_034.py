# SPDX-License-Identifier: GPL-3.0-only
import base64
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json,read_json,sha256
from armhpc_ota.serial_stream import transfer,PREFIX
from armhpc_ota.serial_extra import upload,export_boot
from armhpc_ota.receive import receive
from support import fixture,release

def frame(op,**v):return json.dumps({'operation':op,**v}).encode()+b'\n'
def chunk(data,offset=0):return frame('chunk',offset=offset,data=base64.b64encode(data).decode(),sha256=hashlib.sha256(data).hexdigest())
def messages(out):return [json.loads(s.split(PREFIX.encode(),1)[1]) for s in out.getvalue().splitlines()]

class Serial034(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.c,self.key=fixture(self.root)
        self.e=Engine(self.c);self.id=str(uuid.uuid4());self.p,self.m=release(self.c,self.key)
        self.plan=receive(self.e,str(self.p),'rescue',self.id)
        self.item=next(a for a in self.m['artifacts'] if a['role']=='rescue-kernel');self.data=Path(self.item['url'].removeprefix('file://')).read_bytes()
    def tearDown(self):self.tmp.cleanup()
    def test_disconnect_resume_and_finish_verified(self):
        out=io.BytesIO();transfer(self.c,self.id,self.item['sha256'],io.BytesIO(chunk(self.data[:30])+frame('cancel')),out)
        self.assertEqual(messages(out)[-1]['offset'],30)
        out=io.BytesIO();transfer(self.c,self.id,self.item['sha256'],io.BytesIO(chunk(self.data[30:],30)+frame('finish')),out)
        self.assertEqual(messages(out)[0]['offset'],30);self.assertEqual(messages(out)[-1]['state'],'verified')
    def test_wrong_offset_corrupt_chunk_and_truncated_frame(self):
        for data in (chunk(self.data,2),chunk(self.data).replace(b'"sha256": "',b'"sha256": "x'),b''):
            with self.assertRaises((OTAError,ValueError)):transfer(self.c,self.id,self.item['sha256'],io.BytesIO(data),io.BytesIO())
    def test_signed_manifest_and_device_binding(self):
        with self.assertRaises(OTAError):transfer(self.c,self.id,'1'*64,io.BytesIO(),io.BytesIO())
        d=read_json(self.root/'device.json');d['device_id']='different';atomic_json(self.root/'device.json',d)
        with self.assertRaisesRegex(OTAError,'device changed'):transfer(self.c,self.id,self.item['sha256'],io.BytesIO(),io.BytesIO())
    def test_file_level_hash_rejects_damaged_full_partial(self):
        p=Path(self.plan['directory'])/(self.item['sha256']+'.part');p.write_bytes(b'x'*self.item['size'])
        with self.assertRaisesRegex(OTAError,'SHA256'):transfer(self.c,self.id,self.item['sha256'],io.BytesIO(frame('finish')),io.BytesIO())
    def test_generic_bundle_resume_binding_and_symlink(self):
        digest=hashlib.sha256(self.data).hexdigest();out=io.BytesIO()
        upload(self.c,self.id,digest,len(self.data),io.BytesIO(chunk(self.data[:20])+frame('cancel')),out)
        out=io.BytesIO();upload(self.c,self.id,digest,len(self.data),io.BytesIO(chunk(self.data[20:],20)+frame('finish')),out)
        self.assertEqual(messages(out)[0]['offset'],20);self.assertEqual(messages(out)[-1]['sha256'],digest)
        with self.assertRaises(OTAError):upload(self.c,self.id,'a'*64,len(self.data),io.BytesIO(),io.BytesIO())
    def test_private_export_offset_sha_and_identity(self):
        directory=self.c.cache/'boot-backups'/self.id;directory.mkdir(parents=True)
        p=directory/'BOOT-rescue.img.xz';p.write_bytes(self.data)
        atomic_json(self.c.state/'boot-maintenance/task.json',{'device_id':'device-001','task_id':self.id,'backups':{p.name:{'path':str(p),'bytes':len(self.data),'sha256':sha256(p)}}})
        out=io.BytesIO();export_boot(self.c,self.id,p.name,7,io.BytesIO(frame('ack',offset=len(self.data))),out)
        rows=messages(out);self.assertEqual(rows[0]['offset'],7);self.assertEqual(base64.b64decode(rows[1]['data']),self.data[7:])
        p.write_bytes(b'changed')
        with self.assertRaises(OTAError):export_boot(self.c,self.id,p.name,0,io.BytesIO(),io.BytesIO())

if __name__=='__main__':unittest.main()
