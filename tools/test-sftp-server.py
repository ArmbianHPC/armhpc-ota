# SPDX-License-Identifier: GPL-3.0-only
import json
import os
from pathlib import Path
import posixpath
import secrets
import socket
import threading
import sys
import paramiko
import uuid
boot_id=str(uuid.uuid4())
import logging
logging.getLogger("paramiko.transport").addHandler(logging.NullHandler())
logging.getLogger("paramiko.transport").propagate=False

root=Path(sys.argv[1]).resolve()
assert not any((path/".git").exists() for path in (root,*root.parents)), "Fixture state must stay outside Git"
root.mkdir(parents=True,exist_ok=True)
password=secrets.token_urlsafe(24)
key=paramiko.RSAKey.generate(2048)
socket_server=socket.socket();socket_server.bind(('127.0.0.1',0));socket_server.listen(5)
files={'/fixture':{'mode':0o40700,'data':bytearray()}}
stop=threading.Event();connections=[]

def normalize(path):return posixpath.normpath(path if path.startswith('/') else '/fixture/'+path)
def attrs(path):
    p=normalize(path)
    if p not in files:return paramiko.SFTP_NO_SUCH_FILE
    a=paramiko.SFTPAttributes();a.st_mode=files[p]['mode'];a.st_size=len(files[p]['data']);a.st_uid=0;a.st_gid=0;return a

class Handle(paramiko.SFTPHandle):
    def __init__(self,path,flags):super().__init__(flags);self.path=path
    def read(self,offset,length):return bytes(files[self.path]['data'][offset:offset+length])
    def write(self,offset,data):
        content=files[self.path]['data'];end=offset+len(data)
        if len(content)<end:content.extend(b'\0'*(end-len(content)))
        content[offset:end]=data;return paramiko.SFTP_OK
    def stat(self):return attrs(self.path)
    def chattr(self,attr):return change(self.path,attr)

def change(path,attr):
    p=normalize(path)
    if p not in files:return paramiko.SFTP_NO_SUCH_FILE
    if attr.st_mode is not None:files[p]['mode']=(files[p]['mode'] & 0o170000)|(attr.st_mode & 0o7777)
    return paramiko.SFTP_OK

class Sftp(paramiko.SFTPServerInterface):
    def canonicalize(self,path):return normalize(path)
    def stat(self,path):return attrs(path)
    def lstat(self,path):return attrs(path)
    def mkdir(self,path,attr):
        files[normalize(path)]={'mode':0o40755,'data':bytearray()};return paramiko.SFTP_OK
    def open(self,path,flags,attr):
        p=normalize(path)
        if p not in files:
            if not flags & os.O_CREAT:return paramiko.SFTP_NO_SUCH_FILE
            files[p]={'mode':0o100644,'data':bytearray()}
        if flags & os.O_TRUNC:files[p]['data'].clear()
        return Handle(p,flags)
    def chattr(self,path,attr):return change(path,attr)
    def remove(self,path):files.pop(normalize(path),None);return paramiko.SFTP_OK
    def rmdir(self,path):files.pop(normalize(path),None);return paramiko.SFTP_OK

class Server(paramiko.ServerInterface):
    def check_auth_password(self,user,pwd):return paramiko.AUTH_SUCCESSFUL if user=='fixture' and secrets.compare_digest(pwd,password) else paramiko.AUTH_FAILED
    def get_allowed_auths(self,user):return 'password'
    def check_channel_request(self,kind,chanid):return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_pty_request(self,channel,term,width,height,pixelwidth,pixelheight,modes):return True
    def check_channel_shell_request(self,channel):
        def shell():
            import time
            time.sleep(0.02);channel.sendall(b"root@fixture-host:~# ")
            try:
                while data:=channel.recv(4096):channel.sendall(b"fixture echo: "+data)
            except (OSError,EOFError):pass
        threading.Thread(target=shell,daemon=True).start();return True
    def check_channel_exec_request(self,channel,command):
        # Fixture identity only; never execute a received shell command.
        if command not in (b"hostname",b"cat /proc/sys/kernel/random/boot_id") and b" ota 'status' " not in command and b"/usr/local/sbin/armhpc-rescue '--help'" not in command and b"armhpc-rescue 'led' '--heartbeat' 'on'" not in command and b"armhpc-rescue 'boot' '--reboot'" not in command:return False
        def reply():
            global boot_id
            import time
            time.sleep(0.02)
            if b"armhpc-rescue 'boot' '--reboot'" in command:
                boot_id=str(uuid.uuid4());channel.transport.close();return
            if b"armhpc-rescue 'led' '--heartbeat' 'on'" in command:
                channel.transport.close();return
            data={'protocol':1,'ok':True,'data':{'device_id':'fixture-device','mode':'rescue','agent_version':'0.3.1','bootstrapped':True}}
            response=boot_id+'\n' if command==b'cat /proc/sys/kernel/random/boot_id' else 'fixture-host\n' if command==b'hostname' else 'ARMHPC fixture help\n' if b"armhpc-rescue '--help'" in command else json.dumps(data)+'\n'
            channel.sendall(response.encode());channel.send_exit_status(0);channel.shutdown_write();channel.close()
        threading.Thread(target=reply,daemon=True).start();return True

import hashlib,base64
config=root/'sftp-fixture.json'
config.write_text(json.dumps({'host':'127.0.0.1','port':socket_server.getsockname()[1],'username':'fixture','password':password,
                             'fingerprint':'SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')}))
try:
    socket_server.settimeout(0.5)
    print('isolated SFTP fixture ready',flush=True)
    while not (root/'sftp-fixture.stop').exists():
        try:client,_=socket_server.accept()
        except socket.timeout:continue
        transport=paramiko.Transport(client);transport.add_server_key(key)
        transport.set_subsystem_handler('sftp',paramiko.SFTPServer,Sftp)
        try:transport.start_server(server=Server())
        except (paramiko.SSHException,EOFError,OSError):transport.close();continue
        connections.append(transport)
finally:
    for transport in connections:transport.close()
    socket_server.close();config.unlink(missing_ok=True)
