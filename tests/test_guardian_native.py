# SPDX-License-Identifier: GPL-3.0-only
"""Run the real guardian state machine with a fake ioctl/device and redirected paths."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


@unittest.skipUnless(sys.platform=='linux' and shutil.which('gcc'),'Linux gcc required for isolated guardian harness')
class GuardianNative(unittest.TestCase):
    def test_sole_fd_one_shot_and_genuine_stop_feeding(self):
        with tempfile.TemporaryDirectory(prefix='guardian-native-') as directory:
            root=Path(directory);(root/'run').mkdir();(root/'records').mkdir()
            (root/'boot-id').write_text('fixture-boot\n');(root/'healthy').touch();(root/'watchdog').touch()
            source=(Path(__file__).resolve().parents[1]/'boot/watchdog-guard.c').read_text()
            for original,replacement in [('/run/armhpc',str(root/'run')),('/var/lib/armhpc/ota/watchdog',str(root/'records')),
                ('/proc/sys/kernel/random/boot_id',str(root/'boot-id')),('/proc/sysrq-trigger',str(root/'NEVER-sysrq'))]:source=source.replace(original,replacement)
            # The harness can never operate a host watchdog, sysrq or reboot syscall.
            stub='''
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <linux/watchdog.h>
#define ioctl fixture_ioctl
#define sync fixture_sync
#define syscall fixture_syscall
int fixture_ioctl(int fd,unsigned long op,...) { (void)fd;va_list ap;va_start(ap,op);if(op==WDIOC_SETTIMEOUT){int *p=va_arg(ap,int*);*p=44;}va_end(ap);if(op==WDIOC_KEEPALIVE){FILE *f=fopen("FEEDS","a");fputs("feed\\n",f);fclose(f);}return 0;}
void fixture_sync(void){}
long fixture_syscall(long n,...) {(void)n;return -1;}
'''.replace('FEEDS',str(root/'feeds'))
            p=root/'guardian.c';p.write_text(stub+source);exe=root/'guard'
            subprocess.run(['gcc','-std=gnu11','-O0',str(p),'-o',str(exe)],capture_output=True,check=True)
            process=subprocess.Popen([str(exe),'--guard',str(root/'watchdog'),'180',str(root/'healthy')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                path=root/'run/watchdog-control.sock';deadline=time.monotonic()+3
                while not path.exists():self.assertLess(time.monotonic(),deadline);time.sleep(.02)
                tid=str(uuid.uuid4())
                def submit():
                    with socket.socket(socket.AF_UNIX) as s:s.connect(str(path));s.sendall(('expire '+tid+' 5\n').encode());return s.recv(4096).decode()
                self.assertTrue(submit().startswith('OK '));self.assertTrue(submit().startswith('REFUSED'))
                evidence=root/'records'/('guardian-'+tid+'.json')
                deadline=time.monotonic()+8
                while json.loads(evidence.read_text())['stage']!='triggered':self.assertLess(time.monotonic(),deadline);time.sleep(.05)
                before=(root/'feeds').read_text();time.sleep(3.3)
                self.assertEqual((root/'feeds').read_text(),before,'Guardian must hold its FD while performing NO keepalive')
                self.assertIsNone(process.poll());self.assertEqual(json.loads(evidence.read_text())['timeout_seconds'],44)
                self.assertFalse((root/'NEVER-sysrq').exists())
            finally:process.kill();process.wait(timeout=3)

if __name__=='__main__':unittest.main()
