# SPDX-License-Identifier: GPL-3.0-only
"""Opt-in Linux loop-device test. Never run against a user disk or a complete firmware IMG."""
import hashlib
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import subprocess
import sys
import os
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from armhpc_ota.backend import Backend
from armhpc_ota.config import Config
from armhpc_ota.device import run
from armhpc_ota.io import sha256, atomic_json

output = Path(sys.argv[1]).resolve()
assert output.is_relative_to(Path('/mnt/f/armhpc/output').resolve())
output.mkdir(parents=True, exist_ok=True)
results = {}
with tempfile.TemporaryDirectory(prefix='loop-test-', dir=output) as temporary:
    root = Path(temporary).resolve()
    assert root.is_relative_to(output)
    image = root / 'disk.bin'; payload_image = root / 'payload.ext4'; cache = root / 'cache'; cache.mkdir()
    run('truncate', '-s', '320M', image)
    run('sgdisk', '--clear', '--new=1:2048:+128M', '--new=2:0:+128M', image)
    loop = run('losetup', '--find', '--show', '--partscan', image)
    assert loop.startswith('/dev/loop')
    try:
        for number, label in [(1, 'OECT_ROOT'), (2, 'OECT_DATA')]:
            run('mkfs.ext4', '-F', '-L', label, loop + 'p' + str(number))
        target = {'path': loop + 'p1', 'fixture_role': 'system', 'label': 'OECT_ROOT', 'size': 128 * 1024**2,
                  'fstype': 'ext4', 'uuid': run('blkid', '-s', 'UUID', '-o', 'value', loop + 'p1'),
                  'partuuid': run('blkid', '-s', 'PARTUUID', '-o', 'value', loop + 'p1'), 'parent': loop,
                  'maj:min': run('lsblk', '-dn', '-o', 'MAJ:MIN', loop + 'p1'), 'start': 2048, 'mountpoints': []}
        data_uuid = run('blkid', '-s', 'UUID', '-o', 'value', loop + 'p2')
        config = Config(state=root / 'shared', cache=cache)
        backend = Backend(config)
        with backend.mount({'path': loop + 'p2'}, writable=True) as mounted:
            (mounted / 'keep.txt').write_text('data-survives-offline-root-replacement')
        run('truncate', '-s', '32M', payload_image)
        run('mkfs.ext4', '-F', payload_image)
        payload_loop = run('losetup', '--find', '--show', payload_image)
        try:
            with backend.mount({'path': payload_loop}, writable=True) as mounted:
                (mounted / 'new-system.txt').write_text('new-rootfs')
        finally:
            run('losetup', '--detach', payload_loop)
        encoded = root / 'payload.zst'
        run('zstd', '-q', '-f', payload_image, '-o', encoded)
        digest = sha256(encoded); (cache / digest).write_bytes(encoded.read_bytes())
        artifact = {'id': 'system-rootfs', 'size': encoded.stat().st_size, 'sha256': digest,
                    'expanded_size': payload_image.stat().st_size, 'expanded_sha256': sha256(payload_image)}
        device = {'root': '/dev/not-the-loop-test', 'blocks': [target]}
        with patch('armhpc_ota.backend.discover', return_value=device):
            backend.write_image(artifact, target)
        with backend.mount(target) as mounted:
            assert (mounted / 'new-system.txt').read_text() == 'new-rootfs'
        assert run('blkid', '-s', 'UUID', '-o', 'value', loop + 'p1') == target['uuid']
        assert run('blkid', '-s', 'LABEL', '-o', 'value', loop + 'p1') == 'OECT_ROOT'
        assert run('blkid', '-s', 'UUID', '-o', 'value', loop + 'p2') == data_uuid
        with backend.mount({'path': loop + 'p2'}) as mounted:
            assert (mounted / 'keep.txt').read_text() == 'data-survives-offline-root-replacement'
        info = run('dumpe2fs', '-h', loop + 'p1')
        block_count = int(next(line.split(':')[1] for line in info.splitlines() if line.startswith('Block count:')))
        block_size = int(next(line.split(':')[1] for line in info.splitlines() if line.startswith('Block size:')))
        assert block_count * block_size == target['size']
        results = {'compressed_ext4_decode_write': True, 'offline_fsck': True, 'resize_to_partition': True,
                   'system_uuid_preserved': True, 'system_label_preserved': True, 'data_uuid_and_contents_unchanged': True,
                   'real_hardware': False, 'fixture_partition_bytes': target['size']}
    finally:
        run('losetup', '--detach', loop)
atomic_json(output / 'native-ext4-report.json', results)
print(json.dumps(results, indent=2))
