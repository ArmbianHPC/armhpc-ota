# SPDX-License-Identifier: GPL-3.0-only
"""Shared, explicit update-source policy. TLS trust is separate from signing trust."""
import ipaddress
import ssl
from pathlib import Path
from urllib.parse import urlsplit
from .errors import require
from .io import atomic_bytes, atomic_json, read_json, sha256
from .store import Store, TERMINAL


def origin(url):
    p = urlsplit(url)
    require(p.scheme in ('http', 'https') and p.hostname and not p.username and not p.password
            and not p.fragment, 'source_url', 'Expected an HTTP(S) URL without credentials or fragment')
    try:
        port = p.port or (443 if p.scheme == 'https' else 80)
    except ValueError as error:
        from .errors import OTAError
        raise OTAError('source_url', 'Invalid source port') from error
    host = p.hostname.lower()
    return f'{p.scheme}://{host}:{port}'


def private_http(url):
    p = urlsplit(url)
    try:
        address = ipaddress.IPv4Address(p.hostname)
    except (ValueError, TypeError):
        return False
    return any(address in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def shared_available(config):
    if config.simulate:
        return True
    import subprocess
    r = subprocess.run(['findmnt', '-n', '-o', 'FSTYPE,LABEL', '--mountpoint', str(config.state)],
                       text=True, capture_output=True, timeout=10)
    return r.returncode == 0 and r.stdout.split() == ['ext4', 'OTA_SHARED']


def load(config):
    if not shared_available(config):
        return
    p = config.state / 'source/profile.json'
    if p.is_file():
        data = read_json(p)
        config.feed = data['feed']
        config.tools_source = data.get('tools_source', config.tools_source)
        config.allowed_origins = data['allowed_origins']
        config.allow_http = data['allow_http']
        config.ca_file = config.state / ('source/ca-' + data['ca_sha256'] + '.pem') if data.get('ca_sha256') else None
        if config.ca_file:
            require(config.ca_file.is_file() and sha256(config.ca_file) == data['ca_sha256'],
                    'source_ca', 'The shared source CA changed or is missing')


def show(config):
    return {'feed': config.feed, 'tools_source': config.tools_source,
            'allowed_origins': list(config.allowed_origins), 'allow_http': config.allow_http,
            'ca_sha256': sha256(config.ca_file) if config.ca_file else None,
            'shared': shared_available(config)}


def set_source(engine, url, allow_http=False, ca=None, tools_source=None, extra_origins=()):
    c = engine.config
    device = __import__('armhpc_ota.device', fromlist=['discover']).discover(c)
    storage = __import__('armhpc_ota.device', fromlist=['layout']).layout(c, device, initialized=True)
    engine._require_shared_mount(storage)
    origins = sorted({origin(url), *(origin(u) for u in extra_origins), *([origin(tools_source)] if tools_source else [])})
    require(all(not u.startswith('http:') or (allow_http and private_http(u)) for u in origins),
            'http_authorization', 'HTTP requires explicit authorization and an RFC1918 IPv4 address')
    pem = Path(ca).read_bytes() if ca else None
    if pem:
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cadata=pem.decode('ascii'))
    with engine.store.lock():
        job = engine.store.read()
        require(not job or job['stage'] in TERMINAL, 'job_active', 'Cannot change source during an OTA task')
        maintenance = c.state / 'maintenance/task.json'
        require(not maintenance.is_file() or read_json(maintenance)['stage'] in ('succeeded', 'rolled-back'),
                'maintenance_incomplete', 'Finish tool maintenance before changing the source')
        import hashlib
        if pem:
            # Content addressing keeps the previous profile valid across interruption.
            digest = hashlib.sha256(pem).hexdigest()
            atomic_bytes(c.state / ('source/ca-' + digest + '.pem'), pem, 0o644)
        else:
            digest = None
        value = {'protocol': 1, 'feed': url, 'tools_source': tools_source or c.tools_source,
                 'allow_http': bool(allow_http), 'allowed_origins': origins, 'ca_sha256': digest}
        atomic_json(c.state / 'source/profile.json', value)
        c.feed, c.allowed_origins, c.allow_http = url, origins, bool(allow_http)
        c.tools_source = value['tools_source']
        c.ca_file = c.state / ('source/ca-' + digest + '.pem') if digest else None
    return show(c)


def test(engine):
    engine.clock.require_synchronised()
    result = engine.check()
    return {**show(engine.config), 'verified': True, 'compatible_releases': len(result['releases'])}
