# SPDX-License-Identifier: GPL-3.0-only
"""Bootstrap cache selection and lossless, bounded-memory boot-region backups."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from .device import run
from .errors import require
from .io import fsync_dir


def prepare_cache(config, storage):
    if config.simulate:
        return
    data = storage['partitions']['data']
    if not data or config.cache not in (config.state / 'cache', Path('/data/armhpc-ota/cache')):
        return
    directory = Path('/data')
    directory.mkdir(exist_ok=True)
    if not directory.is_mount():
        require(not any(directory.iterdir()), 'data_mount_hidden', 'Refusing to hide existing files underneath /data')
        require(not any(data.get('mountpoints') or []), 'data_mount', 'DATA is already mounted outside /data')
        run('mount', '-t', 'ext4', '-o', 'noatime', 'UUID=' + data['uuid'], directory)
    mounted = run('findmnt', '-n', '--mountpoint', directory, '-o', 'SOURCE')
    require(str(Path(mounted).resolve()) == str(Path(data['path']).resolve()), 'data_mount',
            '/data does not refer to the validated SATA DATA partition')
    config.cache = directory / 'armhpc-ota/cache'
    config.cache.mkdir(parents=True, exist_ok=True, mode=0o700)


def backup_prefix(source_path, destination, length):
    """Back up all original bytes; compression does not change the protected prefix."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(shutil.disk_usage(destination.parent).free >= 8 * 1024**2, 'bootstrap_backup_space',
            'Insufficient backup space; mount SATA DATA at /data or use a larger cache')
    descriptor, name = tempfile.mkstemp(prefix='.protected-prefix-', dir=destination.parent)
    temporary = Path(name)
    encoder = None
    try:
        os.fchmod(descriptor, 0o600)
        digest, count = hashlib.sha256(), 0
        with os.fdopen(descriptor, 'wb') as output:
            encoder = subprocess.Popen(['zstd', '-q', '-3', '-c'], stdin=subprocess.PIPE,
                                       stdout=output, stderr=subprocess.DEVNULL)
            try:
                with Path(source_path).open('rb') as source:
                    while count < length:
                        chunk = source.read(min(1024**2, length - count))
                        require(chunk, 'reserved_read', 'Could not read the complete original boot region')
                        encoder.stdin.write(chunk)
                        digest.update(chunk)
                        count += len(chunk)
                encoder.stdin.close()
                require(encoder.wait() == 0, 'bootstrap_backup_space',
                        'Compressed boot backup failed; check cache space before retrying')
            finally:
                if not encoder.stdin.closed:
                    encoder.stdin.close()
                if encoder.poll() is None:
                    encoder.kill(); encoder.wait()
            output.flush(); os.fsync(output.fileno())
        decoder = subprocess.Popen(['zstd', '-q', '-dc', '--', str(temporary)], stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL)
        verified, total = hashlib.sha256(), 0
        try:
            for chunk in iter(lambda: decoder.stdout.read(1024**2), b''):
                total += len(chunk)
                require(total <= length, 'backup_length', 'Decoded backup exceeds the protected prefix')
                verified.update(chunk)
            require(decoder.wait() == 0 and total == length and verified.hexdigest() == digest.hexdigest(),
                    'backup_verify', 'Compressed boot-region backup failed readback verification')
        finally:
            decoder.stdout.close()
            if decoder.poll() is None:
                decoder.kill(); decoder.wait()
        os.replace(temporary, destination)
        fsync_dir(destination.parent)
        return {'format': 'zstd', 'file': str(destination), 'original_bytes': length,
                'original_sha256': digest.hexdigest(), 'compressed_bytes': destination.stat().st_size}
    finally:
        temporary.unlink(missing_ok=True)
