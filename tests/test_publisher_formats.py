# SPDX-License-Identifier: GPL-3.0-only
import contextlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from armhpc_ota.lan_publish import inspect_runtime, main, tools_bundle
from armhpc_ota.metadata import verify


class PublisherFormatTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.private=Ed25519PrivateKey.generate();self.key=self.root/'key.pem'
        self.key.write_bytes(self.private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.trust=self.root/'trust';self.trust.mkdir()
        (self.trust/'fixture.pub').write_bytes(self.private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    def archive(self,name,content):
        path=self.root/name
        with tarfile.open(path,'w:xz') as archive:
            for member,data in content.items():
                info=tarfile.TarInfo(member);info.size=len(data);archive.addfile(info,io.BytesIO(data))
        return path
    def content(self):
        prefix='armhpc-ota-0.3.0/'
        items={'src/armhpc_ota/__init__.py':b'__version__="0.3.0"\n',
               'src/armhpc_ota/maintenance.py':b'# runner',
               'src/armhpc_ota/profiles/wxy-oect-original-squashfs.json':b'{"anchor_abi":"armhpc-anchor-squashfs-v2"}',
               'packaging/fallback-health.py':b'# health','boot/boot-entry.py':b'# entry','boot/squashfs-boot.py':b'# overlay',
               'helpers/watchdog-guard-arm64':b'fixture-arm64','helpers/watchdog-guard-armhf':b'fixture-armhf'}
        return {prefix+name:data for name,data in items.items()}
    def refused(self,path,code):
        output=self.root/'published';stdout=io.StringIO()
        with contextlib.redirect_stdout(stdout):rc=main(['tools','--runtime',str(path),'--output',str(output),'--key','', '--key-id','fixture'])
        result=json.loads(stdout.getvalue());self.assertEqual(2,rc);self.assertFalse(result['ok']);self.assertEqual(code,result['error']['code'])
        self.assertNotIn('Traceback',stdout.getvalue());self.assertFalse(output.exists())
    def test_signed_envelope_is_directed_to_maintenance(self):
        self.refused(self.archive('maintenance.tar.xz',{'manifest.json':b'{}','runtime.tar.xz':b'fixture'}),'tools_already_signed')
    def test_missing_marker_returns_json_instead_of_stopiteration(self):
        self.refused(self.archive('system.tar.xz',{'ota-index.json':b'{}','blobs/fixture':b'data'}),'tools_runtime_format')
    def test_source_archive_without_architecture_helpers_is_rejected(self):
        content=self.content();del content['armhpc-ota-0.3.0/helpers/watchdog-guard-armhf']
        self.refused(self.archive('source.tar.xz',content),'tools_runtime_resources')
    def test_missing_literal_version_is_rejected(self):
        content=self.content();content['armhpc-ota-0.3.0/src/armhpc_ota/__init__.py']=b'# no version'
        self.refused(self.archive('bad-version.tar.xz',content),'tools_version')
    def test_corrupt_input_has_structured_error(self):
        path=self.root/'wrong.tar.xz';path.write_bytes(b'not an XZ archive');self.refused(path,'tools_runtime_format')
    def test_unsafe_member_rejected_without_output(self):
        content=self.content();content['../escape']=b'bad';self.refused(self.archive('unsafe.tar.xz',content),'tools_archive_path')
    def test_duplicate_version_root_rejected(self):
        content=self.content();content['other/src/armhpc_ota/__init__.py']=b'__version__="0.3.0"';self.refused(self.archive('multiple.tar.xz',content),'tools_runtime_format')
    def test_valid_runtime_still_signs_and_remains_immutable(self):
        path=self.archive('armhpc-ota-0.3.0-linux-runtime.tar.xz',self.content())
        self.assertEqual('0.3.0',inspect_runtime(path)['version'])
        result=tools_bundle(path,self.root/'valid-published',self.key,'fixture')
        with tarfile.open(result['bundle'],'r:xz') as archive:
            signed=verify(archive.extractfile('manifest.json').read(),self.trust)
        self.assertEqual('0.3.0',signed['version']);self.assertEqual(['armhpc-anchor-squashfs-v2'],signed['anchor_abis'])
        self.assertEqual(result['sha256'],tools_bundle(path,self.root/'valid-published',self.key,'fixture')['sha256'])


if __name__=='__main__':unittest.main()
