# SPDX-License-Identifier: GPL-3.0-only
"""Persistent jobs use replace+fsync; boot selection is a separate durable record."""
from datetime import datetime, timezone
from contextlib import contextmanager, nullcontext
from pathlib import Path
import uuid
import time
from .errors import require
from .io import atomic_json, identifier, read_json, writer_lock

TERMINAL = {'succeeded', 'failed-recoverable', 'cancelled'}
WRITING = {'deploying-rescue', 'trial-rescue', 'deploying-system', 'trial-system'}


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, root, global_lock=None, clock=None):
        self.root = Path(root)
        self.global_lock = global_lock
        self.clock = clock

    @contextmanager
    def lock(self):
        # A /run lock remains the same inode when bootstrap mounts OTA_SHARED over state.
        with writer_lock(self.global_lock) if self.global_lock else nullcontext():
            with writer_lock(self.root / 'writer.lock'):
                yield

    def job_path(self, job_id):
        return self.root / 'jobs' / (identifier(job_id) + '.json')

    def read(self, job_id=None):
        if not job_id:
            if not (self.root / 'latest.json').exists():
                return None
            job_id = read_json(self.root / 'latest.json')['job_id']
        require(self.job_path(job_id).is_file(), 'job_missing', 'OTA job does not exist')
        return read_json(self.job_path(job_id))

    def create(self, manifest, target, plan, kind='apply', request_id=None, local_only=False):
        existing = self.read()
        require(existing is None or existing['stage'] in TERMINAL, 'job_active', 'A device already has an active OTA job')
        job = {'job_id': request_id or str(uuid.uuid4()), 'created': now(), 'updated': now(), 'stage': 'queued',
               'kind': kind, 'release': manifest['release'], 'manifest': manifest, 'target': target,
               'device_id': plan['device_id'], 'plan': plan, 'write_started': False,
               'checkpoints': [], 'progress': {}, 'events': [], 'attempts': {}, 'local_only': local_only}
        self.save(job, 'queued', 'Upgrade job created')
        atomic_json(self.root / 'latest.json', {'job_id': job['job_id']})
        return job

    def save(self, job, stage=None, message=None, **updates):
        if stage:
            job['stage'] = stage
        job.update(updates)
        job['updated'] = now()
        if self.clock:
            job['clock'] = self.clock()
        if message:
            job['events'].append({'sequence': max((e.get('sequence', i + 1) for i, e in enumerate(job['events'])), default=0) + 1,
                                  'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip() if Path('/proc/sys/kernel/random/boot_id').is_file() else 'host',
                                  'monotonic_seconds': time.monotonic(), 'time': job['updated'], 'stage': job['stage'], 'message': message,
                                  'clock': job.get('clock', {'quality': 'invalid', 'source': 'not-provided'})})
        atomic_json(self.job_path(job['job_id']), job)
        return job

    def checkpoint(self, job, name):
        if name not in job['checkpoints']:
            job['checkpoints'].append(name)
        self.save(job, message='Completed ' + name)

    def cancel(self, job_id=None):
        with self.lock():
            job = self.read(job_id)
            require(job is not None, 'job_missing', 'No job to cancel')
            require(not job['write_started'] and job['stage'] not in TERMINAL, 'cancel_boundary',
                    'The job cannot be cancelled after disk writing starts')
            self.save(job, 'cancelled', 'Cancelled before disk writing')
            return job

    def control(self):
        path = self.root / 'control.json'
        require(path.is_file(), 'bootstrap_required', 'Run bootstrap before enabling OTA')
        value = read_json(path)
        require(value.get('protocol') == 1 and isinstance(value.get('confirmed'), dict),
                'control_invalid', 'Boot control is invalid; boot the independent Rescue fallback')
        return value

    def write_control(self, control):
        atomic_json(self.root / 'control.json', control)

    def fail(self, job, error):
        # Never leave a partial normal root as a boot candidate.
        try:
            control = self.control()
            control['next'] = {'target': 'rescue', 'slot': control['confirmed']['rescue']['slot'], 'trial': False}
            control['system_blocked'] = True if job.get('write_started') else control.get('system_blocked', False)
            control['trial'] = None
            self.write_control(control)
        except Exception:
            # The immutable bootstrap must fall back to the independent A/B copies.
            pass
        return self.save(job, 'failed-recoverable', 'Upgrade stopped; use Rescue recover',
                         error={'code': getattr(error, 'code', 'internal'), 'message': str(error)})
