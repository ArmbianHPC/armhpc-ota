# SPDX-License-Identifier: GPL-3.0-only
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import uuid
from armhpc_ota.config import Config
from armhpc_ota.io import atomic_json, atomic_bytes
from armhpc_ota.metadata import sign
from armhpc_ota.publish import keygen
from armhpc_ota.store import Store
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def fixture(root, initialized=True, mode='system'):
    root = Path(root)
    config = Config.load(simulate=root)
    profile = config.board()
    for name in ('trust', 'shared', 'data/cache', 'release', 'roots/system', 'roots/rescue_a', 'roots/rescue_b'):
        (root / name).mkdir(parents=True, exist_ok=True)
    # Ephemeral test keys are not release keys; the TemporaryDirectory is always removed.
    key = Ed25519PrivateKey.generate()
    (root / 'keys').mkdir()
    private = root / 'keys/test.pem'
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    keys = {'private_key': str(private)}
    (root / 'trust/test.pub').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
    blocks = [{'path': '/dev/mmcblk0', 'type': 'disk', 'size': 7818182656, 'log-sec': 512, 'parent': None},
              {'path': '/dev/sda', 'type': 'disk', 'size': 240057409536, 'log-sec': 512, 'parent': None, 'tran': 'sata'}]
    specs = [('boot', '/dev/mmcblk0p1', '/dev/mmcblk0', 368640, 512 * 1024**2),
             ('rescue_a', '/dev/mmcblk0p2', '/dev/mmcblk0', 1417216, 3825631 * 512),
             ('system', '/dev/sda1', '/dev/sda', 2048, 64 * 1024**3),
             ('data', '/dev/sda2', '/dev/sda', 134219776, 171336884224)]
    if initialized:
        specs.extend([('rescue_b', '/dev/mmcblk0p3', '/dev/mmcblk0', 5242880, 3825631 * 512),
                      ('shared', '/dev/mmcblk0p4', '/dev/mmcblk0', 9068544, (15269854 - 9068544 + 1) * 512)])
    for role, path, parent, start, size in specs:
        blocks.append({'path': path, 'type': 'part', 'parent': parent, 'start': start, 'size': size,
                       'label': profile['labels'][role], 'fstype': 'ext4', 'uuid': str(uuid.uuid4()), 'partuuid': str(uuid.uuid4()),
                       'maj:min': '8:' + str(len(blocks)), 'fixture_role': role,
                       'mountpoints': ['/'] if role == ('system' if mode == 'system' else 'rescue_a') else []})
    device = {'device_id': 'device-001', 'board': profile['id'], 'architecture': 'arm64', 'distribution': 'bookworm',
              'mode': mode, 'root': '/dev/sda1' if mode == 'system' else '/dev/mmcblk0p2', 'kernel': '6.12.111-old',
              'simulated_gate': True, 'blocks': blocks}
    atomic_json(root / 'device.json', device)
    for role in ('system', 'rescue_a', 'rescue_b'):
        directory = root / 'roots' / role
        (directory / 'etc').mkdir()
        (directory / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n')
        (directory / 'etc/shadow').write_text('root:secret-test-hash:1:0:99999:7:::\nadmin:admin-hash:1:0:99999:7:::\n')
        (directory / 'etc/group').write_text('root:x:0:\nadmin:x:1000:\nsudo:x:27:admin\n')
        (directory / 'etc/gshadow').write_text('root:*::\nadmin:*::\nsudo:*::admin\n')
        (directory / 'root').mkdir()
        (directory / 'home/admin').mkdir(parents=True)
        (directory / 'home/admin/keep.txt').write_text('user-file')
    (root / 'data/keep.txt').write_text('DATA-MUST-NOT-CHANGE')
    manifest_path, manifest = release(config, Path(keys['private_key']), 'r1', 1, kernel='6.12.111-old')
    if initialized:
        from armhpc_ota.engine import Engine
        engine = Engine(config)
        engine.manifest(location=str(manifest_path)); engine.download(manifest)
        job = {'release': 'r1', 'manifest': manifest}
        system = engine.backend.boot_files(job, 'system')
        rescue = engine.backend.boot_files(job, 'rescue')
        Store(config.state).write_control({'protocol': 1, 'anchor_abi': 'armhpc-anchor-v1', 'anchor_sha256': '0' * 64,
            'confirmed': {'rescue': {'slot': 'a', 'boot': rescue}, 'system': {'boot': system}},
            'highest_sequence': 1, 'system_blocked': False, 'trial': None, 'next': {'target': 'system'}})
    return config, Path(keys['private_key'])


def release(config, key, name='r2', sequence=2, kernel='6.13.1-test', architecture='arm64'):
    root = config.simulate / 'release'
    artifacts = []
    for target in ('system', 'rescue'):
        for suffix in ('rootfs', 'kernel', 'initramfs', 'dtb'):
            path = root / (name + '-' + target + '-' + suffix)
            path.write_bytes((name + target + suffix).encode() * 20)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            item = {'id': target + '-' + suffix, 'role': target + '-' + suffix,
                    'url': path.as_uri(), 'sha256': digest, 'size': path.stat().st_size}
            if suffix == 'rootfs':
                item.update(encoding='ext4.zstd', expanded_size=32 * 1024**2, expanded_sha256=digest)
            artifacts.append(item)
    manifest = {'kind': 'release', 'protocol': 1, 'release': name, 'sequence': sequence,
                'board': 'wxy-oect-original', 'architecture': architecture, 'distribution': 'bookworm',
                'layout': 'oect-ext4-ab-v1', 'anchor_abi': 'armhpc-anchor-v1', 'minimum_agent': '0.1.0',
                'kernels': {'system': kernel, 'rescue': kernel}, 'artifacts': artifacts,
                'packages': {'system': [], 'rescue': []}}
    path = root / (name + '.manifest.json')
    path.write_bytes(sign(manifest, key, 'test'))
    return path, manifest


def boot_fixture(config, target, slot=None, kernel=None):
    from armhpc_ota.io import read_json
    device = read_json(config.simulate / 'device.json')
    role = 'system' if target == 'system' else 'rescue_' + slot
    device['mode'] = target
    device['root'] = next(item['path'] for item in device['blocks'] if item.get('fixture_role') == role)
    if kernel:
        device['kernel'] = kernel
    for item in device['blocks']:
        if 'fixture_role' in item:
            item['mountpoints'] = ['/'] if item['fixture_role'] == role else []
    atomic_json(config.simulate / 'device.json', device)
