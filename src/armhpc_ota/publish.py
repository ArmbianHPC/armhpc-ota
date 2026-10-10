# SPDX-License-Identifier: GPL-3.0-only
"""Offline release tooling. Private keys and generated payloads stay outside Git."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .errors import require
from .io import atomic_bytes, atomic_json, read_json, sha256, identifier, canonical
from .metadata import sign, validate_manifest, anchor_digest
from .device import run


def keygen(destination, key_id):
    destination = Path(destination).resolve()
    identifier(key_id)
    require(not any((path / '.git').exists() for path in (destination, *destination.parents)),
            'private_key_repository', 'Private signing keys must be generated outside a Git repository')
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    private = destination / (key_id + '.pem')
    require(not private.exists() and not (destination / (key_id + '.pub')).exists(),
            'key_exists', 'Refusing to overwrite an existing signing key or trust identity')
    key = Ed25519PrivateKey.generate()
    atomic_bytes(private, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    public = destination / (key_id + '.pub')
    atomic_bytes(public, key.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
    return {'private_key': str(private), 'public_key': str(public)}


def artifact(path, role, base_url, expanded=None):
    result = {'id': role, 'role': role, 'url': base_url.rstrip('/') + '/' + path.name,
              'sha256': sha256(path), 'size': path.stat().st_size}
    if expanded:
        result.update(encoding='ext4.zstd', expanded_size=expanded.stat().st_size, expanded_sha256=sha256(expanded))
    return result


def validate_staging(root, target, release, kernel):
    require(os.name != 'nt' and os.geteuid() == 0, 'build_platform', 'Compact ext4 construction requires Linux root/loop mounts')
    root = Path(root).resolve()
    require(root != Path('/'), 'build_root', 'Never publish a running root filesystem directly')
    require((root / 'sbin/init').exists() and (root / 'lib/modules' / kernel).is_dir(), 'build_root', 'Rootfs lacks init or matched modules')
    require((root / 'usr/lib/armhpc-ota/armhpc_ota').is_dir(), 'build_agent', 'Install the shared OTA runtime into the staging root first')
    marker = read_json(root / 'etc/armhpc/release.json')
    require(marker['release'] == release and marker['target'] == target, 'build_marker', 'Staging root release marker is incorrect')
    forbidden = ('usr/local/bin/k3s', 'usr/bin/k3s', 'usr/lib/u-boot', 'usr/share/armhpc/loader',
                 'root/.ssh', 'root/.bash_history', 'etc/ssh/ssh_host_ed25519_key', 'etc/ssh/ssh_host_rsa_key',
                 'var/lib/armhpc/ota/identity.json', 'var/lib/armhpc/ota/control.json', 'var/lib/armhpc/ota/identities',
                 'var/lib/armhpc/ota/jobs', 'var/lib/armhpc/network-identity.json', 'etc/rancher/k3s/config.yaml',
                 'etc/systemd/system/k3s.service.env', 'etc/systemd/system/k3s-agent.service.env',
                 'etc/armhpc/authentication.json', 'etc/armhpc/ota-install.json')
    require(not any((root / item).exists() for item in forbidden), 'build_private_payload',
            'Published rootfs must not include installed K3s, permanent loaders, or private SSH identity')
    require(not any((root / 'etc/ssh').glob('ssh_host_*')) and
            not any((root / 'data').iterdir() if (root / 'data').is_dir() else []),
            'build_private_payload', 'Published payload must not contain host keys or DATA contents')
    require(not any(root.rglob('*MiniLoader*')) and not any(root.rglob('*miniloader*')),
            'build_loader', 'A MiniLoader was found in the release staging root')
    from .preserve import records
    require(all(row[1].startswith(('!', '*')) for row in records(root, 'shadow')),
            'build_credentials', 'Published baseline must not contain installed user passwords')
    return root


def filesystem(root, output, target, release, kernel):
    root = validate_staging(root, target, release, kernel)
    image = output / (target + '.ext4')
    used = int(run('du', '--apparent-size', '-sx', '--block-size=1', root).split()[0])
    size = ((used + used // 3 + 128 * 1024 * 1024 + 4095) // 4096) * 4096
    run('truncate', '-s', str(size), image)
    run('mkfs.ext4', '-F', '-L', 'ARMHPC_PAYLOAD', image)
    loop = run('losetup', '--find', '--show', image)
    try:
        with tempfile.TemporaryDirectory(prefix='armhpc-release-') as mountpoint:
            run('mount', loop, mountpoint)
            try:
                run('cp', '-a', root.as_posix() + '/.', mountpoint)
                run('sync', '-f', mountpoint)
            finally:
                run('umount', mountpoint)
    finally:
        run('losetup', '--detach', loop)
    run('e2fsck', '-f', '-p', image, accepted=(0, 1))
    run('resize2fs', '-M', image)
    run('e2fsck', '-f', '-n', image)
    compressed = output / (target + '.ext4.zst')
    run('zstd', '-T0', '-10', '--no-progress', '-f', image, '-o', compressed)
    return image, compressed


def squashfs_filesystem(root, output, target, release, kernel, inputs):
    root = validate_staging(root, target, release, kernel)
    require(target == 'rescue', 'filesystem', 'Direct SquashFS is currently a Rescue format')
    from .squashfs import superblock, staging_fingerprint
    options = inputs.get('squashfs_options', ['-comp', 'zstd', '-b', '1M', '-Xcompression-level', '22'])
    require(isinstance(options, list) and all(isinstance(v, str) for v in options), 'compressor', 'Invalid SquashFS compressor options')
    image = output / (target + '.squashfs')
    prepared = inputs.get('prebuilt_squashfs')
    if prepared:
        require(inputs.get('source_fingerprint') == staging_fingerprint(root), 'build_source', 'Compression comparison no longer matches staging content')
        require(sha256(prepared) == inputs.get('prebuilt_sha256'), 'build_hash', 'Measured SquashFS artifact changed')
        shutil.copyfile(prepared, image)
    else:
        run('mksquashfs', root, image, '-noappend', '-no-progress', *options)
    require(superblock(image)['bytes_used'] <= image.stat().st_size, 'build_format', 'Invalid SquashFS output')
    return image


def bundle(specification, destination, private_key, key_id, base_url):
    spec = read_json(specification)
    output = Path(destination).resolve()
    require(not any((path / '.git').exists() for path in (output, *output.parents)),
            'artifact_repository', 'Build update packages outside the source repository')
    output.mkdir(parents=True, exist_ok=True)
    manifest = {key: spec[key] for key in ('release', 'sequence', 'board', 'architecture', 'kernels')}
    manifest.update(kind='release', protocol=1, distribution='bookworm', layout=spec['layout'],
                    anchor_abi=spec.get('anchor_abi', 'armhpc-anchor-v1'), minimum_agent=spec.get('minimum_agent', '0.1.2'), artifacts=[], packages={})
    for target, inputs in spec['targets'].items():
        require(target in ('system', 'rescue'), 'target', 'Unknown rootfs target')
        root = Path(inputs['rootfs'])
        if inputs.get('filesystem') == 'squashfs':
            image = squashfs_filesystem(root, output, target, manifest['release'], manifest['kernels'][target], inputs)
            root_artifact = artifact(image, target + '-rootfs', base_url)
            root_artifact.update(encoding='squashfs', filesystem='squashfs', expanded_size=image.stat().st_size, expanded_sha256=sha256(image))
            manifest['artifacts'].append(root_artifact)
        else:
            image, compressed = filesystem(root, output, target, manifest['release'], manifest['kernels'][target])
            manifest['artifacts'].append(artifact(compressed, target + '-rootfs', base_url, image))
        for role in ('kernel', 'initramfs', 'dtb'):
            source = Path(inputs[role])
            destination_file = output / (target + '-' + role)
            if role == 'initramfs':
                with source.open('rb') as stream:
                    require(stream.read(4) != bytes.fromhex('27051956'), 'raw_initramfs', 'Do not package a legacy uImage initramfs')
            shutil.copyfile(source, destination_file)
            manifest['artifacts'].append(artifact(destination_file, target + '-' + role, base_url))
        inventory = run('chroot', root, 'dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n')
        manifest['packages'][target] = [{'name': row.split('\t')[0], 'version': row.split('\t')[1]} for row in inventory.splitlines()
                                         if len(row.split('\t')) == 3 and row.split('\t')[2] == 'installed']
        if inputs.get('filesystem') != 'squashfs': image.unlink()  # SquashFS is already the final compressed filesystem.
    validate_manifest(manifest)
    signed = output / (identifier(manifest['release']) + '.manifest.json')
    atomic_bytes(signed, sign(manifest, private_key, key_id), 0o644)
    atomic_bytes(output / 'SHA256SUMS', ''.join(sha256(path) + '  ' + path.name + '\n' for path in sorted(output.iterdir())
                                               if path.is_file() and path.name != 'SHA256SUMS').encode(), 0o644)
    return {'manifest': str(signed), 'release': manifest['release']}


def index(entries, destination, private_key, key_id, days=14):
    now = datetime.now(timezone.utc)
    payload = {'kind': 'index', 'protocol': 1, 'created': now.isoformat(),
               'expires': (now + timedelta(days=days)).isoformat(), 'releases': entries}
    atomic_bytes(destination, sign(payload, private_key, key_id), 0o644)


def anchor(source, destination, private_key, key_id, base_url, trust_dir):
    source, destination = Path(source), Path(destination)
    require(not any((path / '.git').exists() for path in (destination.resolve(), *destination.resolve().parents)),
            'artifact_repository', 'Publish bootstrap artifacts outside the source repository')
    destination.mkdir(parents=True, exist_ok=True)
    items = []
    for name in ('kernel', 'initramfs', 'dtb'):
        path = destination / ('anchor-' + name)
        shutil.copy2(source / name, path)
        if name == 'initramfs':
            with path.open('rb') as stream:
                require(stream.read(4) != bytes.fromhex('27051956'), 'raw_initramfs', 'Bootstrap initramfs must be raw')
        item = artifact(path, name, base_url)
        item.pop('role'); items.append(item)
    payload = {'kind': 'anchor', 'board': 'wxy-oect-original', 'anchor_abi': 'armhpc-anchor-v1',
               'anchor_sha256': anchor_digest(items), 'artifacts': items,
               'trusted_key_ids': sorted(key.stem for key in Path(trust_dir).glob('*.pub'))}
    require(key_id in payload['trusted_key_ids'], 'anchor_trust', 'Anchor must include the signing public key in its pinned trust set')
    atomic_bytes(destination / 'anchor.manifest.json', sign(payload, private_key, key_id), 0o644)
    return {'anchor_sha256': payload['anchor_sha256'], 'manifest': str(destination / 'anchor.manifest.json')}


def main(argv=None):
    parser = argparse.ArgumentParser(description='ARMHPC release tooling (not a device OTA command)')
    commands = parser.add_subparsers(dest='command', required=True)
    generate = commands.add_parser('keygen'); generate.add_argument('destination'); generate.add_argument('--key-id', required=True)
    build = commands.add_parser('bundle'); build.add_argument('spec'); build.add_argument('output'); build.add_argument('--base-url', required=True)
    sign_command = commands.add_parser('sign'); sign_command.add_argument('payload'); sign_command.add_argument('output')
    feed = commands.add_parser('index'); feed.add_argument('entries'); feed.add_argument('output'); feed.add_argument('--days', type=int, default=14)
    anchor_command = commands.add_parser('anchor'); anchor_command.add_argument('source'); anchor_command.add_argument('output')
    anchor_command.add_argument('--base-url', required=True); anchor_command.add_argument('--trust-dir', required=True)
    for child in (build, sign_command, feed, anchor_command):
        child.add_argument('--key', required=True); child.add_argument('--key-id', required=True)
    args = parser.parse_args(argv)
    if args.command == 'keygen':
        print(keygen(args.destination, args.key_id))
    elif args.command == 'bundle':
        print(bundle(args.spec, args.output, args.key, args.key_id, args.base_url))
    elif args.command == 'sign':
        atomic_bytes(args.output, sign(read_json(args.payload), args.key, args.key_id), 0o644)
    elif args.command == 'anchor':
        print(anchor(args.source, args.output, args.key, args.key_id, args.base_url, args.trust_dir))
    else:
        index(read_json(args.entries), args.output, args.key, args.key_id, args.days)


if __name__ == '__main__':
    main()
