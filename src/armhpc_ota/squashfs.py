# SPDX-License-Identifier: GPL-3.0-only
"""Direct SquashFS slots, authenticated trailers and isolated overlay generations."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
from .errors import require
from .io import identifier, read_json, atomic_json, sha256
from .metadata import verify, validate_manifest
from .device import run

TRAILER_BYTES = 64 * 1024
MAGIC = b'ARMHPC-SQFS-V2\0\0'
OVERLAY_OPTIONS = 'index=off,metacopy=off,redirect_dir=off,xino=on'
BOOT_RECORD = Path('/run/armhpc/ota-boot.json')


def superblock(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(96)
    require(len(raw) == 96 and raw[:4] == b'hsqs', 'squashfs_format', 'Not a SquashFS filesystem')
    block, compressor, major, minor = struct.unpack_from('<I', raw, 12)[0], *struct.unpack_from('<H', raw, 20), *struct.unpack_from('<HH', raw, 28)
    used = struct.unpack_from('<Q', raw, 40)[0]
    require(major == 4 and minor == 0 and compressor in (1, 3, 4, 5, 6) and
            4096 <= block <= 1024**2 and block & (block - 1) == 0 and used >= 96,
            'squashfs_format', 'Unsupported SquashFS format or compression')
    return {'bytes_used': used, 'block_size': block, 'compression_id': compressor}


def hash_prefix(path, size):
    result = hashlib.sha256()
    with Path(path).open('rb', buffering=0) as stream:
        left = size
        while left:
            chunk = stream.read(min(left, 1024**2))
            require(chunk, 'slot_read', 'Incomplete SquashFS slot')
            result.update(chunk); left -= len(chunk)
    return result.hexdigest()


def trailer_bytes(raw):
    require(0 < len(raw) <= TRAILER_BYTES - 20, 'slot_manifest', 'Signed slot manifest is too large')
    return MAGIC + struct.pack('<I', len(raw)) + raw + bytes(TRAILER_BYTES - 20 - len(raw))


def write_trailer(path, capacity, raw=None):
    require(capacity > TRAILER_BYTES, 'slot_capacity', 'Slot is too small')
    descriptor = os.open(path, os.O_RDWR | os.O_EXCL | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'r+b', buffering=0) as stream:
        stream.seek(capacity - TRAILER_BYTES)
        remaining = memoryview(trailer_bytes(raw) if raw else bytes(TRAILER_BYTES))
        while remaining:
            count = stream.write(remaining)
            require(count and count > 0, 'slot_commit', 'Slot trailer write stopped')
            remaining = remaining[count:]
        os.fsync(stream.fileno())


def read_trailer(path, capacity, trust):
    with Path(path).open('rb', buffering=0) as stream:
        stream.seek(capacity - TRAILER_BYTES)
        raw = stream.read(TRAILER_BYTES)
    require(len(raw) == TRAILER_BYTES and raw[:16] == MAGIC, 'slot_uncommitted', 'Slot has no committed signed manifest')
    length = struct.unpack_from('<I', raw, 16)[0]
    require(0 < length <= TRAILER_BYTES - 20, 'slot_manifest', 'Invalid signed slot manifest length')
    signed = raw[20:20 + length]
    manifest = validate_manifest(verify(signed, trust))
    item = next((a for a in manifest['artifacts'] if a['role'] == 'rescue-rootfs'), None)
    require(item and item.get('encoding') == 'squashfs' and item['size'] <= capacity - TRAILER_BYTES,
            'slot_manifest', 'Slot manifest does not describe a fitting direct SquashFS Rescue')
    require(superblock(path)['bytes_used'] <= item['size'] and hash_prefix(path, item['size']) == item['sha256'],
            'slot_hash', 'Rescue slot failed its signed content hash')
    return manifest, signed


def generation(state, slot, release):
    require(slot in ('a', 'b'), 'slot', 'Unknown Rescue slot')
    base = Path(state) / 'overlays' / slot / identifier(release)
    require(not any(p.is_symlink() for p in (Path(state) / 'overlays', base.parent, base)),
            'overlay_path', 'Overlay directories must not be symbolic links')
    return base


@contextmanager
def overlay_mount(device, state, slot, writable=False, release=None):
    """Only the inactive slot is mounted here; the live slot is guarded by discover()."""
    with tempfile.TemporaryDirectory(prefix='armhpc-squashfs-') as temporary:
        base = Path(temporary); lower = base / 'lower'; merged = base / 'root'
        lower.mkdir(); merged.mkdir()
        run('mount', '-t', 'squashfs', '-o', 'ro', device, lower)
        mounted = False
        try:
            actual = read_json(lower / 'etc/armhpc/release.json')['release']
            require(not release or release == actual, 'root_version', 'Overlay version differs from its base')
            root = generation(state, slot, actual)
            if writable or (root / 'ready.json').exists():
                for name in ('upper', 'work'):
                    path = root / name
                    require(not path.is_symlink(), 'overlay_path', 'Unsafe overlay directory')
                    path.mkdir(parents=True, exist_ok=True, mode=0o755 if name == 'upper' else 0o700)
                    path.chmod(0o755 if name == 'upper' else 0o700)
                options = ('rw' if writable else 'ro') + ',lowerdir=' + str(lower) + ',upperdir=' + str(root / 'upper') + ',workdir=' + str(root / 'work') + ',' + OVERLAY_OPTIONS
                run('mount', '-t', 'overlay', '-o', options, 'overlay', merged); mounted = True
                yield merged
            else:
                yield lower
        finally:
            if mounted: run('umount', merged)
            run('umount', lower)


def mark_ready(state, slot, release, root_hash):
    atomic_json(generation(state, slot, release) / 'ready.json', {'release': release, 'root_sha256': root_hash})


def boot_context():
    return read_json(BOOT_RECORD) if BOOT_RECORD.is_file() else {}


def staging_fingerprint(root):
    h=hashlib.sha256()
    for p in sorted(root.rglob('*')):
        s=p.lstat();relative=p.relative_to(root).as_posix()
        value=[relative,s.st_mode,s.st_uid,s.st_gid]
        if p.is_symlink():value.append(os.readlink(p))
        elif p.is_file():value.append(sha256(p))
        elif not p.is_dir():value.append(s.st_rdev)
        value.append([(n,os.getxattr(p,n,follow_symlinks=False).hex()) for n in sorted(os.listxattr(p,follow_symlinks=False))])
        h.update(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
    return h.hexdigest()
