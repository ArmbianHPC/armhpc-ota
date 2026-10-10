# SPDX-License-Identifier: GPL-3.0-only
"""Disposable real Linux TTY, no PAM changes, accounts, COM or device writes."""
import codecs
import fcntl
import json
import os
import pty
import select
import subprocess
import sys
import termios

master, slave = pty.openpty()
def child():
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
environment = os.environ.copy()
environment.update(PS1='\x1b]0;ARMHPC isolated fixture\a\x1b[32mfixture#\x1b[0m',
                   TERM='xterm', LC_ALL='C.UTF-8', HISTFILE='/dev/null')
process = subprocess.Popen(['/bin/bash', '--noprofile', '--norc', '-i'], stdin=slave,
                           stdout=slave, stderr=slave, env=environment, cwd='/tmp', preexec_fn=child)
os.close(slave)
decoder = codecs.getincrementaldecoder('utf-8')('replace')
try:
    while process.poll() is None:
        ready, _, _ = select.select([master, sys.stdin], [], [], 1)
        if sys.stdin in ready:
            line = sys.stdin.readline()
            if not line:
                break
            request = json.loads(line)
            if request.get('close'):
                break
            os.write(master, request['write'].encode('utf-8'))
        if master in ready:
            data = os.read(master, 4096)
            if not data:
                break
            print(json.dumps({'data': decoder.decode(data)}), flush=True)
finally:
    os.close(master)
    if process.poll() is None:
        process.kill()
    process.wait(timeout=3)
