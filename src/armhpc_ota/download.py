# SPDX-License-Identifier: GPL-3.0-only
"""Origin-restricted TLS/explicit LAN HTTP; bounded, hash-addressed resumable downloads."""
import hashlib
import http.client
import os
from pathlib import Path
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from .errors import OTAError, require
from .io import atomic_json, read_json, sha256, fsync_dir, writer_lock
from .sources import origin, private_http


class Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, transport): self.transport = transport
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.transport.allowed(newurl)
        require(not (req.full_url.startswith('https:') and newurl.startswith('http:')),
                'tls_downgrade', 'HTTPS redirect cannot downgrade to HTTP')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Transport:
    def __init__(self, local=False, timeout=30, config=None, sleep=time.sleep):
        self.local, self.timeout, self.config, self.sleep = local, timeout, config, sleep

    def allowed(self, url):
        p = urllib.parse.urlsplit(url)
        if self.local and p.scheme == 'file': return
        require(p.scheme in ('http', 'https') and p.hostname and not p.username and not p.password,
                'transport', 'Updates require HTTPS or an explicitly authorized LAN HTTP source')
        o = origin(url)
        origins = getattr(self.config, 'allowed_origins', ())
        require(not origins or o in origins, 'source_origin', 'URL is outside the registered source', origin=o)
        require(p.scheme == 'https' or self.local or
                (getattr(self.config, 'allow_http', False) and o in origins and private_http(url)),
                'http_authorization', 'HTTP source is not explicitly authorized')

    def open(self, url, headers=None):
        self.allowed(url)
        ctx = ssl.create_default_context()
        ca = getattr(self.config, 'ca_file', None)
        if ca: ctx.load_verify_locations(cafile=str(ca))
        opener = urllib.request.build_opener(Redirect(self), urllib.request.HTTPSHandler(context=ctx),
                                            urllib.request.ProxyHandler({}))
        try:
            response = opener.open(urllib.request.Request(url, headers=headers or {}), timeout=self.timeout)
            self.allowed(response.geturl())
            return response
        except urllib.error.HTTPError as e:
            raise OTAError('network' if e.code in (408, 429, 500, 502, 503, 504) else 'http_status',
                           'Update server returned an HTTP error', status=e.code) from e
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                raise OTAError('tls_certificate', 'HTTPS certificate validation failed') from e
            raise OTAError('network', 'Could not fetch update resource', url=url.split('?')[0]) from e
        except (TimeoutError, ConnectionError) as e:
            raise OTAError('network', 'Update connection failed') from e

    def _retry(self, operation):
        delays = (1, 3, 10)
        for attempt in range(4):
            try: return operation()
            except OTAError as e:
                if e.code not in ('network', 'network_read', 'download_incomplete') or attempt == 3: raise
                self.sleep(delays[attempt])

    def metadata(self, url, limit=4 * 1024 * 1024):
        def fetch():
            try:
                with self.open(url) as response: raw = response.read(limit + 1)
            except (http.client.IncompleteRead, TimeoutError, ConnectionError, OSError) as e:
                raise OTAError('network_read', 'Metadata response was interrupted') from e
            require(len(raw) <= limit, 'metadata_size', 'Metadata exceeds its size limit')
            return raw
        return self._retry(fetch)

    def download(self, artifact, cache, progress=None):
        cache = Path(cache); cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        with writer_lock(cache / ('.download-' + artifact['sha256'] + '.lock')):
            return self._retry(lambda: self._download(artifact, cache, progress))

    def _download(self, artifact, cache, progress=None):
        destination = cache / artifact['sha256']
        if destination.exists():
            if destination.stat().st_size == artifact['size'] and sha256(destination) == artifact['sha256']: return destination
            destination.unlink()
        partial, info = destination.with_suffix('.part'), destination.with_suffix('.resume.json')
        offset = partial.stat().st_size if partial.exists() else 0
        if offset >= artifact['size']:
            if offset == artifact['size'] and sha256(partial) == artifact['sha256']:
                os.replace(partial, destination); fsync_dir(cache); info.unlink(missing_ok=True); return destination
            partial.unlink(); offset = 0
        headers = {'Accept-Encoding': 'identity'}
        saved = read_json(info) if info.exists() else {}
        if offset and not artifact['url'].startswith('file:'):
            headers['Range'] = f'bytes={offset}-'
            if saved.get('etag'): headers['If-Range'] = saved['etag']
        with self.open(artifact['url'], headers) as response:
            if getattr(response, 'status', None) == 206:
                match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', response.headers.get('Content-Range', ''))
                require(match and int(match[1]) == offset and int(match[3]) == artifact['size'] and
                        offset <= int(match[2]) < artifact['size'], 'range', 'Server returned an inconsistent byte range')
                require(not saved.get('etag') or not response.headers.get('ETag') or
                        saved['etag'] == response.headers.get('ETag'), 'range', 'Partial response ETag changed')
            else: offset = 0
            require(response.headers.get('Content-Encoding', 'identity') == 'identity',
                    'download_encoding', 'Server changed the payload representation')
            atomic_json(info, {'etag': response.headers.get('ETag')})
            count = offset
            with partial.open('ab' if offset else 'wb') as output:
                try:
                    while True:
                        try: chunk = response.read(1024 * 1024)
                        except http.client.IncompleteRead as e:
                            chunk = e.partial
                            require(count + len(chunk) <= artifact['size'], 'download_size', 'Oversize response')
                            output.write(chunk)
                            raise OTAError('network_read', 'Payload response was interrupted') from e
                        if not chunk: break
                        count += len(chunk)
                        require(count <= artifact['size'], 'download_size', 'Server sent more data than the signed size')
                        output.write(chunk)
                        if progress: progress(count, artifact['size'])
                except (TimeoutError, ConnectionError) as e:
                    raise OTAError('network_read', 'Payload response was interrupted') from e
                finally: output.flush(); os.fsync(output.fileno())
        require(count == artifact['size'], 'download_incomplete', 'Download ended before the signed size', received=count)
        if sha256(partial) != artifact['sha256']:
            partial.unlink(missing_ok=True); info.unlink(missing_ok=True)
            raise OTAError('artifact_hash', 'Downloaded artifact failed SHA256 verification', artifact=artifact['id'])
        os.replace(partial, destination); fsync_dir(cache); info.unlink(missing_ok=True)
        return destination


def required_artifacts(manifest, target):
    selected = ('system', 'rescue') if target == 'all' else (target,)
    result = [item for item in manifest['artifacts'] if item['role'].split('-', 1)[0] in selected]
    require(all(any(item['role'] == name + '-rootfs' for item in result) for name in selected),
            'target_missing', 'Release does not include the requested target')
    return result
