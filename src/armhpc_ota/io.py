# SPDX-License-Identifier: GPL-3.0-only
"""Bounded JSON, durable atomic writes and an inter-process writer lock."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from .errors import OTAError, require


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'json_duplicate', 'JSON contains a duplicate key', key=key)
        result[key] = value
    return result


def parse_json(raw, limit=4 * 1024 * 1024):
    require(len(raw) <= limit, 'metadata_size', 'JSON exceeds its size limit')
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, UnicodeError) as error:
        raise OTAError('json_invalid', 'Invalid JSON') from error


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def read_json(path):
    return parse_json(Path(path).read_bytes())


def fsync_dir(path):
    if os.name != 'nt':
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def atomic_bytes(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode) if os.name != 'nt' else None
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        fsync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_copy(source, destination, mode=0o600):
    import shutil
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix='.' + destination.name + '-', dir=destination.parent)
    temporary = Path(name)
    try:
        if os.name != 'nt':
            os.fchmod(descriptor, mode)
        with Path(source).open('rb') as input_file, os.fdopen(descriptor, 'wb') as output:
            shutil.copyfileobj(input_file, output, 1024 * 1024)
            output.flush(); os.fsync(output.fileno())
        os.replace(temporary, destination)
        fsync_dir(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_json(path, value):
    atomic_bytes(path, canonical(value) + b'\n')


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value),
            'identifier', 'Unsafe identifier')
    return value


def inside(root, relative):
    root = Path(root).resolve()
    require(isinstance(relative, str) and '\\' not in relative and not relative.startswith('/'),
            'path', 'Expected a relative POSIX path')
    parts = relative.split('/')
    require(all(part and part not in ('.', '..') for part in parts), 'path', 'Unsafe relative path')
    target = root.joinpath(*parts).resolve()
    require(target.is_relative_to(root), 'path', 'Path escapes its root')
    return target


@contextlib.contextmanager
def writer_lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open('a+b')
    try:
        try:
            if os.name == 'nt':
                import msvcrt
                handle.seek(0)
                if handle.read(1) == b'':
                    handle.write(b'0'); handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise OTAError('busy', 'Another OTA writer holds the device lock') from error
        yield
    finally:
        handle.close()
