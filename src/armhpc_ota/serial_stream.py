# SPDX-License-Identifier: GPL-3.0-only
"""Persistent receiver over an authenticated tty, bound to receive.prepare.

One Python process handles all frames. ACK offsets are fsynced. On reconnect,
receive.prepare returns the durable file length. No deployment occurs here.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import select
import sys
import termios
import uuid
from .io import read_json, sha256, writer_lock
from .errors import require

PREFIX = '__ARMHPC_STREAM__:'
MAX_CHUNK = 49152


def reply(value, output):
    output.write((PREFIX + json.dumps(value, separators=(',', ':')) + '\n').encode()); output.flush()


def transfer(config, request_id, digest, input_stream, output, idle_timeout=60):
    require(str(uuid.UUID(request_id)) == request_id, 'request_id', 'Invalid receive UUID')
    require(re.fullmatch('[a-f0-9]{64}', digest), 'serial_hash', 'Invalid payload hash')
    record = read_json(config.state / 'imports' / (request_id + '.json'))
    from .metadata import verify, validate_manifest
    from .download import required_artifacts
    manifest = config.state / 'manifests' / (record['release'] + '.json')
    require(sha256(manifest) == record['manifest_sha256'], 'serial_binding', 'Imported manifest changed')
    signed = validate_manifest(verify(manifest.read_bytes(), config.trust))
    from .device import discover
    require(record['device_id'] == discover(config)['device_id'], 'serial_identity', 'Receive device changed')
    item = next((a for a in required_artifacts(signed, record['target']) if a['sha256'] == digest), None)
    require(item, 'serial_binding', 'Hash is outside the signed receive plan')
    directory = config.cache / 'incoming' / request_id
    path = directory / (digest + '.part')
    require(directory.is_dir() and not directory.is_symlink() and not path.is_symlink() and
            path.resolve().is_relative_to(config.cache.resolve()), 'serial_path', 'Invalid staging path')
    with writer_lock(directory / (digest + '.lock')):
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'r+b', buffering=0) as stream:
            offset = os.fstat(stream.fileno()).st_size
            require(offset <= item['size'], 'serial_offset', 'Partial file exceeds signed size')
            stream.seek(offset)
            reply({'state': 'ready', 'offset': offset, 'size': item['size'], 'sha256': digest}, output)
            while True:
                if getattr(input_stream, 'selectable', False):
                    require(select.select([input_stream], [], [], idle_timeout)[0], 'serial_timeout', 'Receiver idle timeout')
                line = input_stream.readline(MAX_CHUNK * 2 + 256)
                require(line and len(line) < MAX_CHUNK * 2 + 256, 'serial_frame', 'Truncated or oversized frame')
                f = json.loads(line)
                if f.get('operation') == 'finish':
                    require(offset == item['size'], 'serial_incomplete', 'Payload is incomplete')
                    os.fsync(stream.fileno())
                    require(sha256(path) == digest, 'serial_hash', 'Final SHA256 differs from signed hash')
                    reply({'state': 'verified', 'offset': offset, 'sha256': digest}, output); return
                if f.get('operation') == 'cancel':
                    os.fsync(stream.fileno()); reply({'state': 'paused', 'offset': offset}, output); return
                require(f.get('operation') == 'chunk' and f.get('offset') == offset, 'serial_offset', 'Wrong chunk offset')
                data = base64.b64decode(f['data'], validate=True)
                require(0 < len(data) <= MAX_CHUNK and len(data) + offset <= item['size'] and
                        hashlib.sha256(data).hexdigest() == f.get('sha256'), 'serial_chunk', 'Chunk size/hash is invalid')
                stream.write(data); os.fsync(stream.fileno()); offset += len(data)
                reply({'state': 'ack', 'offset': offset}, output)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--request-id'); p.add_argument('--sha256')
    p.add_argument('--upload-id'); p.add_argument('--size',type=int)
    p.add_argument('--export-task'); p.add_argument('--name'); p.add_argument('--offset',type=int,default=0)
    a = p.parse_args(argv)
    old = termios.tcgetattr(sys.stdin.fileno()) if sys.stdin.isatty() else None
    if old:
        new = termios.tcgetattr(sys.stdin.fileno())
        new[0] &= ~(termios.ICRNL | termios.IXON)
        new[1] &= ~termios.OPOST
        new[3] &= ~(termios.ECHO | termios.ICANON | termios.ISIG)
        new[6][termios.VMIN] = 1; new[6][termios.VTIME] = 0
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, new)
    try:
        from .config import Config
        require(os.geteuid() == 0, 'root', 'Authenticated receive requires root')
        # Use raw descriptors: buffered readline may prefetch data hidden from select().
        with os.fdopen(os.dup(sys.stdin.fileno()), 'rb', buffering=0) as src:
            class Lines:
                def __init__(self): self.pending=bytearray()
                selectable=True
                def fileno(self): return src.fileno()
                def readline(self, limit):
                    while True:
                        pos=self.pending.find(b'\n')
                        if pos>=0:
                            require(pos+1<limit,'serial_frame','Frame exceeds bound')
                            result=bytes(self.pending[:pos+1]);del self.pending[:pos+1];return result
                        require(len(self.pending)<limit,'serial_frame','Frame exceeds bound')
                        require(select.select([src], [], [], 60)[0], 'serial_timeout', 'Truncated frame timeout')
                        data=os.read(src.fileno(),65536)
                        require(data,'serial_frame','Connection ended');self.pending.extend(data)
            if a.upload_id:
                from .serial_extra import upload
                upload(Config.load(),a.upload_id,a.sha256,a.size,Lines(),sys.stdout.buffer)
            elif a.export_task:
                from .serial_extra import export_boot
                export_boot(Config.load(),a.export_task,a.name,a.offset,Lines(),sys.stdout.buffer)
            else:
                require(a.request_id and a.sha256,'serial_args','Missing receive binding')
                transfer(Config.load(), a.request_id, a.sha256, Lines(), sys.stdout.buffer)
        return 0
    except Exception as error:
        reply({'state': 'error', 'code': getattr(error, 'code', 'serial_io'), 'message': str(error)}, sys.stdout.buffer)
        return 2
    finally:
        if old: termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)


if __name__ == '__main__': raise SystemExit(main())
