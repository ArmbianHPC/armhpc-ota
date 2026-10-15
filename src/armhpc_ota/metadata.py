# SPDX-License-Identifier: GPL-3.0-only
"""Ed25519 trust is supplied by the device, never by a downloaded package."""
import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .errors import OTAError, require
from .io import canonical, parse_json, identifier

SCHEMA = 'armhpc-ota-v1'
ARTIFACT_ROLES = {'system-rootfs', 'rescue-rootfs', 'system-kernel', 'system-initramfs',
                  'system-dtb', 'rescue-kernel', 'rescue-initramfs', 'rescue-dtb'}


def sign(payload, private_key, key_id):
    identifier(key_id)
    key = serialization.load_pem_private_key(Path(private_key).read_bytes(), password=None)
    require(isinstance(key, Ed25519PrivateKey), 'key_type', 'An Ed25519 private key is required')
    return canonical({'schema': SCHEMA, 'key_id': key_id, 'payload': payload,
                      'signature': base64.b64encode(key.sign(canonical(payload))).decode('ascii')})


def verify(raw, trust_dir):
    document = parse_json(raw)
    require(isinstance(document, dict) and set(document) == {'schema', 'key_id', 'payload', 'signature'},
            'envelope', 'Invalid signed envelope')
    require(document['schema'] == SCHEMA, 'schema', 'Unsupported signing schema')
    key_id = identifier(document['key_id'])
    key_path = Path(trust_dir) / (key_id + '.pub')
    require(key_path.is_file(), 'untrusted_key', 'Signing key is not trusted', key_id=key_id)
    try:
        key_data = key_path.read_bytes()
        key = (serialization.load_pem_public_key(key_data) if key_data.startswith(b'-----BEGIN')
               else Ed25519PublicKey.from_public_bytes(base64.b64decode(key_data.strip(), validate=True)))
        require(isinstance(key, Ed25519PublicKey), 'key_type', 'Trust anchor is not Ed25519')
        signature = base64.b64decode(document['signature'], validate=True)
        key.verify(signature, canonical(document['payload']))
    except (InvalidSignature, ValueError, TypeError) as error:
        raise OTAError('bad_signature', 'Ed25519 signature verification failed') from error
    require(isinstance(document['payload'], dict), 'payload', 'Signed payload must be an object')
    return document['payload']


def valid_sha(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'hash', 'Invalid SHA256')
    return value


def anchor_digest(artifacts):
    # Mirrors may change URLs. Acceptance binds the actual three boot files.
    body = [{'id': item['id'], 'size': item['size'], 'sha256': item['sha256']} for item in artifacts]
    return hashlib.sha256(canonical(sorted(body, key=lambda item: item['id']))).hexdigest()


def timestamp(value):
    try:
        instant = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(instant.tzinfo is not None, 'timestamp', 'Timestamp needs a timezone')
        return instant
    except (ValueError, AttributeError) as error:
        raise OTAError('timestamp', 'Invalid timestamp') from error


def validate_manifest(manifest):
    require(manifest.get('kind') == 'release' and manifest.get('protocol') == 1,
            'manifest', 'Unsupported release manifest')
    for name in ('release', 'board', 'architecture', 'distribution', 'layout'):
        identifier(manifest.get(name))
    require(manifest['architecture'] in ('arm64', 'armhf'), 'architecture', 'Only ARM64 and ARM32 are supported')
    require(manifest['distribution'] == 'bookworm', 'distribution', 'Cross-distribution upgrades are not supported')
    require(isinstance(manifest.get('sequence'), int) and manifest['sequence'] > 0,
            'sequence', 'Release needs a positive monotonic sequence')
    require(isinstance(manifest.get('minimum_agent'), str) and
            re.fullmatch(r'\d+\.\d+\.\d+', manifest['minimum_agent']), 'agent', 'Invalid minimum agent version')
    identifier(manifest.get('anchor_abi'))
    artifacts = manifest.get('artifacts')
    require(isinstance(artifacts, list) and 1 <= len(artifacts) <= 8, 'artifacts', 'Invalid artifact list')
    roles = set()
    for item in artifacts:
        require(isinstance(item, dict), 'artifact', 'Invalid artifact')
        identifier(item.get('id'))
        role = item.get('role')
        require(role in ARTIFACT_ROLES and role not in roles, 'artifact_role', 'Unknown or duplicate artifact role')
        roles.add(role)
        valid_sha(item.get('sha256'))
        require(isinstance(item.get('size'), int) and item['size'] > 0, 'artifact_size', 'Invalid download size')
        require(isinstance(item.get('url'), str), 'artifact_url', 'Artifact URL is missing')
        if role.endswith('rootfs'):
            expected = 'squashfs' if role == 'rescue-rootfs' and manifest['layout'] in ('oect-squashfs-ab-v2','oesp-mbr-squashfs-ab-v1') else 'ext4.zstd'
            require(item.get('encoding') == expected, 'encoding', 'Root payload format differs from its declared layout')
            if expected == 'squashfs':
                require(item.get('expanded_size') == item['size'] and item.get('expanded_sha256') == item['sha256'],
                        'squashfs_transport', 'Direct SquashFS must not be wrapped in another compression stream')
            require(isinstance(item.get('expanded_size'), int) and item['expanded_size'] >= 16 * 1024 * 1024,
                    'expanded_size', 'Invalid ext4 image size')
            valid_sha(item.get('expanded_sha256'))
    for target in ('system', 'rescue'):
        if target + '-rootfs' in roles:
            require(all(target + '-' + suffix in roles for suffix in ('kernel', 'initramfs', 'dtb')),
                    'boot_pairing', 'Every rootfs must include its matched kernel, raw initramfs and DTB')
            identifier(manifest.get('kernels', {}).get(target))
    return manifest


def validate_index(index, now=None):
    require(index.get('kind') == 'index' and index.get('protocol') == 1,
            'index', 'Unsupported update index')
    current = now or datetime.now(timezone.utc)
    require(timestamp(index.get('expires')) > current, 'index_expired', 'Update index has expired; check the device clock')
    require(timestamp(index.get('created')) <= current, 'clock', 'Update index is from the future; synchronize the clock')
    require(isinstance(index.get('releases'), list) and len(index['releases']) <= 1000,
            'index', 'Invalid release list')
    for item in index['releases']:
        for field in ('release', 'board', 'architecture', 'distribution'):
            identifier(item.get(field))
        valid_sha(item.get('sha256'))
        require(isinstance(item.get('size'), int) and 0 < item['size'] <= 4 * 1024 * 1024,
                'manifest_size', 'Invalid manifest size')
        require(isinstance(item.get('sequence'), int), 'sequence', 'Index sequence is missing')
    return index
