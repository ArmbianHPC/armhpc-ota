# SPDX-License-Identifier: GPL-3.0-only
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
from pathlib import Path
import socket
import ssl
import tarfile
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from types import SimpleNamespace
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from armhpc_ota.config import Config
from armhpc_ota.download import Transport
from armhpc_ota.engine import Engine
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json, read_json
from armhpc_ota import sources, maintenance
from armhpc_ota.lan_publish import tools_bundle
from support import fixture, release, boot_fixture

DATA=bytes(range(256))*12000
class Handler(BaseHTTPRequestHandler):
    paths=[]; ranges=[]; mode='full'
    def log_message(self,*args):pass
    def do_GET(self):
        type(self).paths.append(self.path);type(self).ranges.append(self.headers.get('Range'))
        if self.path=='/redirect':self.send_response(302);self.send_header('Location','http://127.0.0.1:1/private');self.end_headers();return
        start=int(self.headers.get('Range','bytes=0-')[6:-1])
        self.send_response(206 if start else 200);self.send_header('Content-Length',str(len(DATA)-start));self.send_header('ETag','"one"')
        if start:self.send_header('Content-Range',f'bytes {start}-{len(DATA)-1}/{len(DATA)}')
        self.end_headers()
        if self.mode=='cut' and not start:
            self.wfile.write(DATA[:1200000]);self.wfile.flush();self.connection.shutdown(socket.SHUT_RDWR);self.connection.close()
        else:self.wfile.write(DATA[start:])


class LanTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        Handler.paths=[];Handler.ranges=[];Handler.mode='full'
        self.server=ThreadingHTTPServer(('0.0.0.0',0),Handler);thread=threading.Thread(target=self.server.serve_forever,daemon=True);thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.url=f'http://127.0.0.1:{self.server.server_port}'
    def test_http_refused_before_connect(self):
        for url in (self.url,'http://192.168.100.1:8080/blob','http://localhost:80/blob'):
            with self.assertRaises(OTAError):Transport().metadata(url)
        self.assertEqual([],Handler.paths)
    def test_private_ipv4_authorization_is_exact(self):
        c=SimpleNamespace(allowed_origins=['http://192.168.100.192:8080'],allow_http=True,ca_file=None)
        t=Transport(config=c);t.allowed('http://192.168.100.192:8080/file')
        for url in ('http://192.168.100.193:8080/file','http://192.168.100.192:8081/file','http://example.local:8080/file','http://8.8.8.8:8080/file'):
            with self.assertRaises(OTAError):t.allowed(url)
    def test_redirect_rejected_before_target_request(self):
        c=SimpleNamespace(allowed_origins=[sources.origin(self.url)],allow_http=True,ca_file=None)
        with self.assertRaises(OTAError):Transport(local=True,config=c).metadata(self.url+'/redirect')
        self.assertEqual(['/redirect'],Handler.paths)
    def test_real_interrupted_response_resumes_and_hashes(self):
        Handler.mode='cut';delays=[]
        t=Transport(local=True,sleep=delays.append)
        a={'id':'test','url':self.url+'/blob','size':len(DATA),'sha256':hashlib.sha256(DATA).hexdigest()}
        p=t.download(a,self.root/'cache')
        self.assertEqual(DATA,p.read_bytes());self.assertEqual([1],delays)
        self.assertTrue(any(r for r in Handler.ranges));self.assertFalse(p.with_suffix('.part').exists())
    def test_tls_private_ca_and_bad_hostname(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);now=datetime.now(timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False)
              .add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256()))
        cp=self.root/'ca.pem';kp=self.root/'key.pem';cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM));kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cp,kp)
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        url=f'https://localhost:{self.server.server_port}/blob'
        with self.assertRaisesRegex(OTAError,'certificate'):Transport(sleep=lambda _:None).metadata(url)
        c=SimpleNamespace(allowed_origins=[],allow_http=False,ca_file=cp)
        self.assertEqual(DATA,Transport(config=c).metadata(url))
        with self.assertRaisesRegex(OTAError,'certificate'):Transport(config=c).metadata(url.replace('localhost','127.0.0.1'))
    def test_production_http_transport_on_private_interface(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.connect(('10.0.0.1',9));address=s.getsockname()[0]
        url=f'http://{address}:{self.server.server_port}'
        if not sources.private_http(url):self.skipTest('Host has no RFC1918 interface')
        c=SimpleNamespace(allowed_origins=[sources.origin(url)],allow_http=True,ca_file=None)
        self.assertEqual(DATA,Transport(config=c).metadata(url+'/blob'))


class SourceTaskTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.c,self.key=fixture(self.tmp.name);self.e=Engine(self.c)
        self.path,self.m=release(self.c,self.key);self.e.manifest(location=str(self.path))
    def test_shared_source_survives_reload(self):
        sources.set_source(self.e,'http://192.168.100.192:8080/ota-index.json',True)
        c=Config.load(simulate=self.c.simulate);self.assertEqual(self.c.feed,c.feed);self.assertEqual(self.c.allowed_origins,c.allowed_origins);self.assertTrue(c.allow_http)
    def test_source_rejects_public_http_and_active_job(self):
        with self.assertRaises(OTAError):sources.set_source(self.e,'http://example.local/index',True)
        self.e.apply(self.m)
        with self.assertRaisesRegex(OTAError,'during'):sources.set_source(self.e,'http://192.168.100.192:8080/index',True)
    def test_retry_same_job_then_write_boundary(self):
        job=self.e.apply(self.m);self.e.store.fail(job,OTAError('network','interrupted'))
        retried=self.e.retry(job['job_id']);self.assertEqual(job['job_id'],retried['job_id']);self.assertEqual('queued',retried['stage'])
        retried['write_started']=True;self.e.store.fail(retried,OTAError('network','interrupted'))
        with self.assertRaises(OTAError):self.e.retry(job['job_id'])
    def test_recheck_restores_verified_data_cache_before_resources(self):
        job=self.e.apply(self.m)
        with patch('armhpc_ota.bootstrap_space.prepare_cache') as cache:
            self.e._recheck(job);cache.assert_called_once()
    def test_bad_signature_not_retryable(self):
        j=self.e.apply(self.m);self.e.store.fail(j,OTAError('artifact_hash','damaged'))
        with self.assertRaises(OTAError):self.e.retry(j['job_id'])
    def test_events_order_even_with_wallclock_regression(self):
        j=self.e.apply(self.m)
        with patch('armhpc_ota.store.now',return_value='2000-01-01T00:00:00+00:00'):self.e.store.save(j,message='after restart')
        self.assertEqual([1,2],[e['sequence'] for e in j['events']]);self.assertIn('boot_id',j['events'][-1]);self.assertIn('monotonic_seconds',j['events'][-1])
    def test_incomplete_maintenance_blocks_apply(self):
        atomic_json(self.c.state/'maintenance/task.json',{'stage':'incomplete'})
        with self.assertRaisesRegex(OTAError,'maintenance'):self.e.apply(self.m)


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.c,self.key=fixture(self.root,mode='rescue')
        self.c.storage_layout='oect-squashfs-ab-v2';board=self.c.board();d=read_json(self.root/'device.json')
        for n in d['blocks']:
            role=n.get('fixture_role')
            if role in ('rescue_a','rescue_b'):n.update(fstype='squashfs',uuid=None,size=512*1024**2,start=board[role+'_start'])
            elif role=='shared':n.update(start=board['shared_start'],size=(15269854-board['shared_start']+1)*512)
        atomic_json(self.root/'device.json',d);self.e=Engine(self.c)
        payload=self.root/'pkg'/'armhpc-ota-0.3.0'
        content={'src/armhpc_ota/__init__.py':b'__version__="0.3.0"\n','src/armhpc_ota/maintenance.py':b'# signed runner\n',
                 'src/armhpc_ota/profiles/wxy-oect-original-squashfs.json':__import__('json').dumps(board).encode(),
                 'packaging/fallback-health.py':b'# health','boot/boot-entry.py':b'# entry','boot/squashfs-boot.py':b'# boot',
                 'helpers/watchdog-guard-arm64':b'fake arm64 helper','helpers/watchdog-guard-armhf':b'fake armhf helper'}
        for relative,data in content.items():p=payload/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        runtime=self.root/'runtime.tar.xz'
        with tarfile.open(runtime,'w:xz') as t:
            for p in payload.rglob('*'):
                if p.is_file():t.add(p,arcname='armhpc-ota-0.3.0/'+p.relative_to(payload).as_posix())
        result=tools_bundle(runtime,self.root/'published',self.key,'test');self.bundle=Path(result['bundle'])
    def test_signed_upgrade_all_roots_and_rollback(self):
        before=(self.root/'data/keep.txt').read_bytes();maintenance.schedule(self.e,self.bundle);result=maintenance.worker(self.e)
        self.assertEqual('succeeded',result['maintenance']['stage'])
        for role in ('system','rescue_a','rescue_b'):self.assertTrue((self.root/'roots'/role/'usr/lib/armhpc-ota/armhpc_ota/__init__.py').is_file())
        self.assertEqual(before,(self.root/'data/keep.txt').read_bytes())
        maintenance.schedule(self.e,rollback=True);self.assertEqual('rolled-back',maintenance.worker(self.e)['maintenance']['stage'])
    def test_cancel_queued_maintenance_without_root_changes(self):
        maintenance.schedule(self.e,self.bundle);maintenance.schedule(self.e,rollback=True)
        self.assertEqual('rolled-back',maintenance.worker(self.e)['maintenance']['stage'])
        self.assertFalse((self.c.state/'maintenance/pending').exists())
    def test_initial_baseline_retains_maintained_agent(self):
        maintenance.schedule(self.e,self.bundle);maintenance.worker(self.e)
        root=self.root/'roots/system';p=root/'usr/lib/armhpc-ota/armhpc_ota/__init__.py';p.write_text('__version__="0.2.0"\n')
        maintenance.retain_installed_runtime(self.c,root)
        self.assertIn('0.3.0',p.read_text())
    def test_equal_version_os_restore_keeps_the_explicitly_maintained_rebuild(self):
        maintenance.schedule(self.e,self.bundle);maintenance.worker(self.e)
        root=self.root/'roots/system'
        marker=root/'usr/lib/armhpc-ota/armhpc_ota/__init__.py'
        runner=root/'usr/lib/armhpc-ota/armhpc_ota/maintenance.py'
        self.assertIn('0.3.0',marker.read_text())
        runner.write_text('# older same-version payload')
        maintenance.retain_installed_runtime(self.c,root)
        self.assertEqual('# signed runner\n',runner.read_text())
        record=maintenance.status(self.c)['maintenance']
        self.assertEqual(64,len(record['bundle_sha256']))
        self.assertEqual(64,len(record['runtime_sha256']))
    def test_newer_os_runtime_is_not_downgraded_by_maintenance_retention(self):
        maintenance.schedule(self.e,self.bundle);maintenance.worker(self.e)
        root=self.root/'roots/system'
        marker=root/'usr/lib/armhpc-ota/armhpc_ota/__init__.py'
        marker.write_text('__version__="0.4.0"\n')
        maintenance.retain_installed_runtime(self.c,root)
        self.assertIn('0.4.0',marker.read_text())
    def revision_bundle(self, revision):
        runtime = self.root/'revised-runtime.tar.xz'
        with tarfile.open(self.root/'runtime.tar.xz', 'r:xz') as old, tarfile.open(runtime, 'w:xz') as new:
            for item in old:
                data = old.extractfile(item).read()
                if item.name.endswith('/src/armhpc_ota/__init__.py'):
                    data += ('__revision__="' + revision + '"\n').encode()
                item.size = len(data)
                new.addfile(item, io.BytesIO(data))
        return Path(tools_bundle(runtime, self.root/'revision-published', self.key, 'test')['bundle'])

    def test_higher_os_revision_is_not_replaced_by_older_signed_maintenance(self):
        maintenance.schedule(self.e,self.revision_bundle('r3'));maintenance.worker(self.e)
        root=self.root/'roots/system'
        marker=root/'usr/lib/armhpc-ota/armhpc_ota/__init__.py'
        runner=root/'usr/lib/armhpc-ota/armhpc_ota/maintenance.py'
        marker.write_text('__version__="0.3.0"\n__revision__="r4"\n')
        runner.write_text('# newer image runtime')
        maintenance.retain_installed_runtime(self.c,root)
        self.assertIn('r4',marker.read_text())
        self.assertEqual('# newer image runtime',runner.read_text())

    def test_signed_newer_revision_replaces_equal_base_old_image(self):
        maintenance.schedule(self.e,self.revision_bundle('r3'));maintenance.worker(self.e)
        root=self.root/'roots/system'
        marker=root/'usr/lib/armhpc-ota/armhpc_ota/__init__.py'
        for revision in ('', '__revision__="r2"\n', '__revision__="r3"\n'):
            marker.write_text('__version__="0.3.0"\n'+revision)
            maintenance.retain_installed_runtime(self.c,root)
            self.assertIn('r3',marker.read_text())

    def test_unsigned_task_revision_cannot_override_signed_revision_order(self):
        maintenance.schedule(self.e,self.revision_bundle('r3'));maintenance.worker(self.e)
        record=maintenance.record(self.c);record['revision']='r99'
        atomic_json(self.c.state/'maintenance/task.json',record)
        root=self.root/'roots/system'
        marker=root/'usr/lib/armhpc-ota/armhpc_ota/__init__.py'
        marker.write_text('__version__="0.3.0"\n__revision__="r4"\n')
        maintenance.retain_installed_runtime(self.c,root)
        self.assertIn('r4',marker.read_text())

    def test_interruption_and_resume(self):
        maintenance.schedule(self.e,self.bundle);original=maintenance.backup_and_install;count=[0]
        def failure(*args):
            count[0]+=1
            if count[0]==2:raise OSError('injected interruption')
            return original(*args)
        with patch.object(maintenance,'backup_and_install',failure):result=maintenance.worker(self.e)
        self.assertEqual('incomplete',result['maintenance']['stage']);self.assertFalse(result['consistent'])
        maintenance.schedule(self.e,self.bundle);self.assertEqual('succeeded',maintenance.worker(self.e)['maintenance']['stage'])
    def test_maintenance_idempotent_request(self):
        import uuid
        rid=str(uuid.uuid4());maintenance.schedule(self.e,self.bundle,request_id=rid);maintenance.worker(self.e)
        result=maintenance.schedule(self.e,self.bundle,request_id=rid)
        self.assertEqual(rid,result['maintenance']['task_id']);self.assertEqual('succeeded',result['maintenance']['stage'])
    def test_damaged_tools_payload_rejected(self):
        broken=self.root/'bad.tar.xz'
        with tarfile.open(self.bundle,'r:xz') as t:raw=t.extractfile('manifest.json').read();runtime=t.extractfile('runtime.tar.xz').read()
        runtime=bytes([runtime[0]^1])+runtime[1:]
        with tarfile.open(broken,'w:xz') as t:
            for name,data in [('manifest.json',raw),('runtime.tar.xz',runtime)]:
                m=tarfile.TarInfo(name);m.size=len(data);t.addfile(m,io.BytesIO(data))
        with self.assertRaises(Exception):maintenance.prepare(self.c,broken)
    def test_unsafe_tar_member_rejected(self):
        b=io.BytesIO()
        with tarfile.open(fileobj=b,mode='w') as t:
            m=tarfile.TarInfo('../escape');m.size=1;t.addfile(m,io.BytesIO(b'x'))
        b.seek(0)
        with tarfile.open(fileobj=b) as t,self.assertRaises(OTAError):maintenance.safe_extract(t,self.root/'extract')
