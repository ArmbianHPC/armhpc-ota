# SPDX-License-Identifier: GPL-3.0-only
"""Real Linux PTY: raw large frames and terminal restoration, no device writes."""
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import termios
import time
import unittest
import uuid
from armhpc_ota.engine import Engine
from armhpc_ota.receive import receive
from support import fixture,release
from test_serial_034 import chunk,frame


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Linux root PTY fixture required')
class PtyStreaming(unittest.TestCase):
    def test_raw_32k_frame_resume_and_restore_terminal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);c,key=fixture(root)
            p,m=release(c,key);a=next(x for x in m['artifacts'] if x['role']=='rescue-kernel')
            data=bytes(range(256))*128;payload=root/'release'/('r2-rescue-kernel');payload.write_bytes(data)
            a.update(size=len(data),sha256=hashlib.sha256(data).hexdigest())
            from armhpc_ota.metadata import sign
            p.write_bytes(sign(m,key,'test'));id=str(uuid.uuid4());receive(Engine(c),str(p),'rescue',id)
            master,slave=pty.openpty();before=termios.tcgetattr(slave)
            code="from armhpc_ota.config import Config;import sys; c=Config.load(simulate=sys.argv[1]);Config.load=classmethod(lambda cls:c);from armhpc_ota.serial_stream import main;raise SystemExit(main(['--request-id',sys.argv[2],'--sha256',sys.argv[3]]))"
            process=subprocess.Popen([sys.executable,'-c',code,str(root),id,a['sha256']],stdin=slave,stdout=slave,stderr=subprocess.PIPE)
            buffer=bytearray()
            def response():
                until=time.monotonic()+5
                while b'\n' not in buffer:
                    self.assertLess(time.monotonic(),until);self.assertTrue(select.select([master],[],[],2)[0]);buffer.extend(os.read(master,65536))
                line,_,rest=buffer.partition(b'\n');buffer[:]=rest
                return json.loads(line.split(b'__ARMHPC_STREAM__:',1)[1])
            def send(value):
                while value:
                    count=os.write(master,value[:1024]);value=value[count:]
            try:
                self.assertEqual(response()['state'],'ready')
                send(chunk(data));self.assertEqual(response()['offset'],len(data))
                send(frame('finish'));self.assertEqual(response()['state'],'verified')
                self.assertEqual(process.wait(timeout=5),0,process.stderr.read().decode())
                self.assertEqual(termios.tcgetattr(slave),before,'Receiver must restore shell tty attributes')
            finally:
                if process.poll() is None:process.kill();process.wait()
                os.close(master);os.close(slave)

if __name__=='__main__':unittest.main()
