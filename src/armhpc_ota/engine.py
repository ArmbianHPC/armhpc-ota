# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
import shutil
from . import __version__, __display_version__, __revision__
from .backend import Backend
from .device import discover, layout, ensure_unmounted, check_gate
from .download import Transport, required_artifacts
from .errors import OTAError, require
from .io import atomic_bytes, atomic_json, read_json, sha256, writer_lock, identifier, atomic_copy
from .metadata import verify, validate_manifest, validate_index
from .store import Store, TERMINAL, WRITING


class Engine:
    def __init__(self, config):
        self.config = config
        from .clock import Clock
        self.clock = Clock(config)
        self.store = Store(config.state, config.global_writer_lock, clock=self.clock.snapshot)
        if config.board().get('rescue_fstype') == 'squashfs':
            from .squashfs_backend import SquashFSBackend
            self.backend = SquashFSBackend(config)
        else:
            self.backend = Backend(config)
        self.transport = Transport(local=bool(config.simulate), config=config)

    def status(self, job_id=None):
        device = discover(self.config,recovery=True)
        job = self.store.read(job_id)
        try:
            control = self.store.control()
        except OTAError:
            control = None
        try:
            gate = check_gate(self.config, device, control)
        except OTAError as error:
            gate = {'passed': False, 'reason': str(error), 'code': error.code}
        return {'protocol': 1, 'agent_version': __version__, 'agent_display_version': __display_version__, 'agent_revision': __revision__, 'device_id': device['device_id'],
                'board': device['board'], 'architecture': device['architecture'], 'mode': device['mode'],
                'kernel': device['kernel'], 'bootstrapped': control is not None, 'hardware_gate': gate,
                'write_authorized': gate.get('write_allowed', gate.get('passed', False)),
                'hardware_policy': self.config.hardware_policy,
                'confirmed': control.get('confirmed', {}) if control else {}, 'job': public_job(job),
                'tools_source': self.config.tools_source, 'system_source': self.config.feed,
                'capabilities': {'idempotent_apply': True, 'offline_baselines': True,
                                 'interrupted_root_recovery': True, 'rescue_ab': True, 'push_import': True, 'local_only_apply': True,
                                 'serial_push': True, 'watchdog_diagnostics': True, 'boot_maintenance': True,
                                 'normal_firmware_update': True, 'storage_management': True, 'firmware_system_resume': True, 'multiple_boot_recovery_baselines': True,
                                 'direct_squashfs': self.config.board().get('rescue_fstype') == 'squashfs'},
                'baselines': self._baseline_status(),
                'versions': {name: control.get('confirmed', {}).get(name, {}).get('boot', {}).get('release') if control else None for name in ('system', 'rescue')},
                'rescue_slot': control.get('confirmed', {}).get('rescue', {}).get('slot') if control else None,
                'actions': {'can_cancel': bool(job and not job['write_started'] and job['stage'] not in TERMINAL),
                            'can_retry': bool(job and not job['write_started'] and job['stage'] == 'failed-recoverable' and job.get('error', {}).get('code') in ('network', 'network_read', 'download_incomplete')),
                            'needs_recovery': bool(job and job['stage'] == 'failed-recoverable' and job['write_started'])},
                'clock': self.clock.snapshot(live=True),
                'watchdog': __import__('armhpc_ota.watchdog', fromlist=['status']).status(self),
                'boot_maintenance': __import__('armhpc_ota.boot_maintenance', fromlist=['status']).status(self.config),
                'tools': __import__('armhpc_ota.maintenance', fromlist=['status']).status(self.config),
                'node_runtime': __import__('armhpc_ota.node_runtime',fromlist=['report']).report(self.config),
                'hardware': __import__('armhpc_ota.hardware',fromlist=['report']).report(self.config,device)}

    def _baseline_status(self):
        result = {}
        for name in ('initial', 'current-system', 'current-rescue'):
            path = self.config.state / 'baselines' / (name + '.json')
            if path.is_file():
                value = read_json(path)
                result[name] = {key: value[key] for key in ('release', 'target', 'targets') if key in value}
        return result

    def check(self):
        self.clock.require_synchronised()
        index = validate_index(verify(self.transport.metadata(self.config.feed), self.config.trust))
        device = discover(self.config)
        releases = [item for item in index['releases'] if item['board'] == device['board'] and
                    item['architecture'] == device['architecture'] and item['distribution'] == 'bookworm' and
                    item.get('layout', self.config.board()['layout']) == self.config.board()['layout'] and
                    item.get('anchor_abi', self.config.board()['anchor_abi']) == self.config.board()['anchor_abi']]
        releases.sort(key=lambda item: item['sequence'], reverse=True)
        return {'device_id': device['device_id'], 'releases': releases, 'source': self.config.feed}

    def _baseline_location(self, release, target):
        directory = self.config.state / 'baselines'
        if release == 'initial':
            pointer = read_json(directory / 'initial.json')
            release = pointer['release']
        elif release == 'current':
            targets = ('system', 'rescue') if target == 'all' else (target,)
            versions = {read_json(directory / ('current-' + name + '.json'))['release'] for name in targets}
            require(len(versions) == 1, 'baseline_versions',
                    'System and Rescue have different confirmed versions; recover them separately')
            release = versions.pop()
        identifier(release)
        path = directory / 'releases' / release / 'manifest.json'
        return str(path) if path.is_file() else None

    def manifest(self, release=None, location=None, target='all', recovery=False):
        expected = None
        if recovery and not location:
            require(release, 'recovery_release', 'Specify --release initial, current, or an explicit compatible version')
            location = self._baseline_location(release, target)
            require(location or release not in ('initial', 'current'), 'baseline_missing', 'The requested local baseline is unavailable')
            if location:
                release = verify(Path(location).read_bytes(), self.config.trust)['release']
        if not location and release and release not in ('initial', 'current'):
            cached = self.config.state / 'manifests' / (identifier(release) + '.json')
            if cached.is_file():
                location = str(cached)
        if not location:
            choices = self.check()['releases']
            if release:
                choices = [item for item in choices if item['release'] == release]
            require(choices, 'release_missing', 'No compatible signed release was found')
            expected = choices[0]
            location = expected['url']
        raw = (Path(location).read_bytes() if Path(location).is_file()
               else self.transport.metadata(location))
        if expected:
            import hashlib
            require(len(raw) == expected['size'] and hashlib.sha256(raw).hexdigest() == expected['sha256'],
                    'manifest_hash', 'Manifest does not match the signed update index')
        manifest = validate_manifest(verify(raw, self.config.trust))
        require(not release or release == manifest['release'], 'release_mismatch', 'Requested release differs from manifest')
        destination = self.config.state / 'manifests' / (manifest['release'] + '.json')
        if destination.exists():
            require(destination.read_bytes() == raw, 'release_mutation', 'A published release name cannot be reused with different content')
        else:
            atomic_bytes(destination, raw)
        return manifest

    def compatible(self, manifest, device, control=None, recovery=False):
        board = self.config.board()
        require(manifest['board'] == device['board'] and manifest['architecture'] == device['architecture'],
                'manifest_device', 'Signed release belongs to another board or architecture')
        require(manifest['layout'] == board['layout'] and manifest['anchor_abi'] == board['anchor_abi'],
                'manifest_layout', 'Signed release requires a different layout or fixed bootstrap')
        require(tuple(map(int, __version__.split('.'))) >= tuple(map(int, manifest['minimum_agent'].split('.'))),
                'agent_version', 'Update the OTA agent through its maintenance procedure first')
        if control and not recovery:
            require(manifest['sequence'] >= control.get('highest_sequence', 0), 'downgrade',
                    'Downgrades require the explicit Rescue recover command')
        if control and control.get('anchor_key_ids'):
            signed = read_json(self.config.state / 'manifests' / (manifest['release'] + '.json'))
            require(signed['key_id'] in control['anchor_key_ids'], 'anchor_trust',
                    'Signing key is absent from the fixed bootstrap; use the dedicated trust/anchor maintenance procedure')
        if control:
            from .platform import require_fixed_boot
            require_fixed_boot(self.config, manifest, control)

    def plan(self, manifest, target='all', recovery=False):
        if not self.config.simulate:
            self.backend.require_runtime_resources()
        device = discover(self.config)
        storage = layout(self.config, device, initialized=True)
        self._require_shared_mount(storage)
        if self.config.board().get('rescue_fstype') == 'squashfs':
            from .bootstrap_space import prepare_cache
            prepare_cache(self.config, storage)
        control = self.store.control()
        self.compatible(manifest, device, control, recovery)
        artifacts = required_artifacts(manifest, target)
        if target in ('system', 'all'):
            require(storage['partitions']['system'] is not None, 'sata_missing', 'Normal-system OTA requires installed SATA root and DATA')
        other_slot = 'b' if control['confirmed']['rescue']['slot'] == 'a' else 'a'
        capacity = {'system': storage['partitions']['system']['size'] if storage['partitions']['system'] else 0,
                    'rescue': storage['partitions']['rescue_' + other_slot]['size'] - self.config.board().get('trailer_bytes', 0)}
        for item in artifacts:
            if item['role'].endswith('rootfs'):
                require(item['expanded_size'] <= capacity[item['role'].split('-', 1)[0]],
                        'capacity', 'Expanded filesystem is too large for the target')
        downloads = sum(item['size'] for item in artifacts if not self._cached(item))
        scratch = max(item.get('expanded_size', 0) for item in artifacts)
        self.config.cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        free = shutil.disk_usage(self.config.cache).free
        require(free >= downloads + scratch + 64 * 1024 * 1024, 'space', 'Insufficient update cache and validation space')
        baseline_needed = sum(item['size'] for item in artifacts if not
                              (self.config.state / 'baselines/releases' / manifest['release'] / item['sha256']).exists())
        boot_needed = 2 * sum(item['size'] for item in artifacts if not item['role'].endswith('rootfs'))
        require(shutil.disk_usage(self.config.state).free >= baseline_needed + boot_needed + 32 * 1024 * 1024,
                'baseline_space', 'Insufficient shared space for kernel generations and confirmed recovery packages')
        if self.config.cache.stat().st_dev == self.config.state.stat().st_dev:
            require(free >= downloads + max(scratch, baseline_needed + boot_needed) + 96 * 1024 * 1024,
                    'shared_peak_space', 'Shared cache cannot hold downloads plus validation/recovery peak space')
        gate_error = None
        try:
            check_gate(self.config, device, control)
        except OTAError as error:
            gate_error = {'code': error.code, 'message': str(error)}
        clock = self.clock.snapshot(live=True)
        if not clock.get('valid_anchor') and gate_error is None:
            gate_error = {'code': 'clock_state_invalid', 'message': 'Synchronize chrony before starting OTA; no recoverable clock anchor'}
        return {'device_id': device['device_id'], 'release': manifest['release'], 'target': target,
                'mode': device['mode'], 'inactive_rescue_slot': other_slot,
                'targets': {name: item['path'] for name, item in storage['partitions'].items() if item},
                'partition_identity': {name: {key: item.get(key) for key in ('uuid', 'partuuid', 'start', 'size')}
                                       for name, item in storage['partitions'].items() if item},
                'disk_identity': {item['path']: {'serial': item.get('serial'), 'wwn': item.get('wwn'), 'size': item['size']}
                                  for item in device['blocks'] if item['type'] == 'disk'},
                'required_download_bytes': downloads, 'validation_scratch_bytes': scratch, 'free_bytes': free,
                'recovery_storage_bytes': baseline_needed + boot_needed,
                'preserve': list(__import__('armhpc_ota.preserve', fromlist=['policy']).policy(target)),
                'preserve_by_target': {name: list(__import__('armhpc_ota.preserve', fromlist=['policy']).policy(name))
                                       for name in ('system', 'rescue') if target in (name, 'all')},
                'steps': ['download and verify', 'prepare configuration/software resources', 'reboot to confirmed Rescue',
                          'write and trial inactive Rescue' if target in ('rescue', 'all') else 'keep confirmed Rescue',
                          'write offline SATA root and trial normal OS' if target in ('system', 'all') else 'confirm Rescue',
                          'commit after health checks'], 'clock': clock, 'write_allowed': gate_error is None, 'blocked': gate_error,
                'recovery': recovery}

    def _cached(self, item):
        path = self.config.cache / item['sha256']
        return path.is_file() and path.stat().st_size == item['size'] and sha256(path) == item['sha256']

    def prime_bootstrap_asset(self, item):
        destination = self.config.cache / item['sha256']
        if self._cached(item):
            return
        directories = (self.config.bootstrap_assets,) if self.config.simulate else (self.config.bootstrap_assets, Path('/boot/armhpc-ota-bootstrap'))
        source = next((directory / item['sha256'] for directory in directories if (directory / item['sha256']).is_file()), None)
        if source is None:
            return
        require(source.stat().st_size == item['size'] and sha256(source) == item['sha256'],
                'bootstrap_asset_hash', 'Bundled bootstrap resource failed its signed integrity check')
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        import os, uuid
        temporary = destination.with_name('.asset-' + uuid.uuid4().hex)
        try:
            if source.stat().st_dev == destination.parent.stat().st_dev:
                os.link(source, temporary)
            else:
                # BOOT is read-only. Avoid a duplicate payload on the small legacy Rescue root;
                # the migration copies these verified files onto OTA_SHARED before deployment.
                temporary.symlink_to(source.resolve())
            os.replace(temporary, destination)
            from .io import fsync_dir
            fsync_dir(destination.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _prime_baseline(self, manifest, item):
        if self._cached(item):
            return
        source = self.config.state / 'baselines/releases' / manifest['release'] / item['sha256']
        if source.exists():
            require(source.is_file() and source.stat().st_size == item['size'] and sha256(source) == item['sha256'],
                    'baseline_hash', 'Local recovery package failed its signed integrity check')
            atomic_copy(source, self.config.cache / item['sha256'])

    def download(self, manifest, target='all', job=None):
        device = discover(self.config)
        self.compatible(manifest, device)
        downloaded = []
        for item in required_artifacts(manifest, target):
            def progress(count, total):
                if job:
                    self._check_cancel(job)
                    previous = job.get('progress', {})
                    if previous.get('artifact') != item['id'] or count == total or count - previous.get('bytes', 0) >= 4 * 1024 * 1024:
                        self.store.save(job, progress={'artifact': item['id'], 'bytes': count, 'total': total})
            self.prime_bootstrap_asset(item)
            self._prime_baseline(manifest, item)
            if job and job.get('local_only'):
                require(self._cached(item), 'push_payload_missing', 'Push payload is absent or damaged; re-upload it from the host')
                downloaded.append(str(self.config.cache/item['sha256']))
            else:
                downloaded.append(str(self.transport.download(item, self.config.cache, progress)))
        return {'release': manifest['release'], 'target': target, 'files': downloaded, 'verified': True}

    def existing_request(self, manifest, target, recovery, request_id, local_only=False):
        if not request_id:
            return None
        import uuid
        require(str(uuid.UUID(request_id)) == request_id, 'request_id', 'Request ID must be a canonical UUID')
        path = self.store.job_path(request_id)
        if not path.exists():
            return None
        job = self.store.read(request_id)
        require(job['device_id'] == discover(self.config)['device_id'] and job['manifest'] == manifest and
                job.get('local_only',False)==local_only and job['target'] == target and job['kind'] == ('recover' if recovery else 'apply'),
                'request_conflict', 'This request ID already belongs to a different device, release or operation')
        return job

    def retry(self, job_id):
        from .maintenance import require_complete
        with self.store.lock():
            require_complete(self.config)
            job = self.store.read(job_id)
            latest = self.store.read()
            require(latest and latest['job_id'] == job['job_id'], 'retry_latest', 'Only the latest task can be retried')
            require(job['stage'] == 'failed-recoverable' and not job['write_started'] and
                    job.get('error', {}).get('code') in ('network', 'network_read', 'download_incomplete'),
                    'retry_boundary', 'Only a pre-write transient download failure can be retried')
            self._recheck(job)
            job.pop('error', None)
            self.store.save(job, 'queued', 'Retrying the same verified pre-write task', retry_count=job.get('retry_count', 0) + 1)
        self.backend.start_service()
        return job

    def apply(self, manifest, target='all', recovery=False, request_id=None, local_only=False):
        with self.store.lock():
            from .watchdog import require_idle as watchdog_idle
            from .boot_maintenance import require_idle as boot_idle
            watchdog_idle(self.config); boot_idle(self.config)
            existing = self.existing_request(manifest, target, recovery, request_id, local_only)
            if existing:
                job = existing
            else:
                from .maintenance import require_complete
                require_complete(self.config)
                device = discover(self.config)
                if device['mode'] == 'system':
                    from .preserve import require_network_confirmed
                    require_network_confirmed(self.config.simulate / 'roots/system' if self.config.simulate else Path('/'))
                if not self.config.simulate:
                    journal = self.config.state / 'bootstrap.json'
                    require(journal.is_file() and read_json(journal).get('complete') is True,
                            'bootstrap_incomplete', 'Complete the bootstrap transaction before starting OTA')
                require(not recovery or device['mode'] == 'rescue', 'recovery_mode', 'Recover only runs from Rescue')
                plan = self.plan(manifest, target, recovery)
                require(plan['write_allowed'], plan['blocked']['code'] if plan['blocked'] else 'hardware_gate', plan['blocked']['message'] if plan['blocked'] else 'OTA is disabled')
                self.clock.require_valid()
                self.clock.flush('ota-start')
                previous = self.store.read()
                if local_only:
                    require(all(self._cached(item) for item in required_artifacts(manifest,target)), 'push_payload_missing', 'Upload and verify every payload before submitting push OTA')
                retained = {}
                if recovery and previous and previous['stage'] == 'failed-recoverable' and previous['write_started']:
                    from .preserve import validate_snapshot
                    for name in ('system', 'rescue'):
                        key = 'snapshot' if name == 'system' else 'rescue_snapshot'
                        inventory_key = 'inventory' if name == 'system' else 'rescue_inventory'
                        if target in ('all', name) and previous.get(key):
                            retained[key] = previous[key]
                            retained[inventory_key] = validate_snapshot(previous[key])
                job = self.store.create(manifest, target, plan, 'recover' if recovery else 'apply', request_id, local_only=local_only)
                if retained:
                    self.store.save(job, message='Reusing verified pre-failure configuration resources', **retained)
        self.backend.start_service()
        return job

    def _recheck(self, job):
        device = discover(self.config)
        require(device['device_id'] == job['device_id'], 'identity', 'Job belongs to another device')
        raw = (self.config.state / 'manifests' / (job['release'] + '.json')).read_bytes()
        manifest = validate_manifest(verify(raw, self.config.trust))
        require(manifest == job['manifest'], 'task_manifest', 'Persistent task differs from its signed release')
        control = self.store.control()
        self.compatible(manifest, device, control, job['kind'] == 'recover')
        check_gate(self.config, device, control)
        storage = layout(self.config, device, initialized=True)
        self._require_shared_mount(storage)
        for role, expected in job['plan']['partition_identity'].items():
            actual = storage['partitions'][role]
            require(actual and all(actual.get(key) == value for key, value in expected.items()),
                    'target_changed', 'Partition identity changed after the job was created', role=role)
        for item in device['blocks']:
            if item['type'] == 'disk' and item['path'] in job['plan']['disk_identity']:
                expected = job['plan']['disk_identity'][item['path']]
                require(expected['serial'] == item.get('serial') and expected['size'] == item['size'] and
                        ('wwn' not in expected or expected['wwn'] == item.get('wwn')),
                        'target_changed', 'Physical disk changed after planning')
        # Rescue DATA is nofail and may not be mounted when this service starts.
        # Select the same verified cache used before the reboot before reading resources.
        from .bootstrap_space import prepare_cache
        prepare_cache(self.config, storage)
        return device, storage, control

    def _require_shared_mount(self, storage):
        if self.config.simulate:
            return
        from .device import run
        source = str(Path(run('findmnt', '-n', '-o', 'SOURCE', '--mountpoint', self.config.state).split('[')[0]).resolve())
        require(source == storage['partitions']['shared']['path'], 'shared_mount',
                'OTA state must be on the verified OTA_SHARED mount')

    def worker(self):
        if not self.config.simulate and Path('/run/armhpc-ota-maintenance-recovery').exists(): return None
        from .boot_maintenance import require_idle
        with self.store.lock():
            job = self.store.read()
            require_idle(self.config,job_id=job['job_id'] if job else None)
            from .boot_maintenance import finish_paired_system
            if finish_paired_system(self,job):return job
            if not job or job['stage'] in TERMINAL:
                return job
            try:
                self._check_cancel(job)
                device, storage, control = self._recheck(job)
                if job['stage'] in ('trial-rescue', 'trial-system'):
                    target = job['stage'].split('-', 1)[1]
                    if control.get('trial') or target + '-health-passed' in job['checkpoints']:
                        return job
                    require(device['mode'] == 'rescue' and
                            device['root'] == storage['partitions']['rescue_' + control['confirmed']['rescue']['slot']]['path'] and
                            target + '-written' in job['checkpoints'], 'trial_transaction',
                            'Incomplete trial-control transaction cannot resume outside confirmed Rescue')
                    self._trial(job, control, target, job[target + '_candidate'])
                    return job
                if job['stage'] in ('queued', 'downloading'):
                    self.store.save(job, 'downloading', 'Verifying download cache')
                    self.download(job['manifest'], job['target'], job)
                    if job['target'] in ('rescue', 'all') and not job.get('rescue_snapshot'):
                        role = 'rescue_' + control['confirmed']['rescue']['slot']
                        partition = storage['partitions'][role]
                        if device['mode'] == 'rescue' and device['root'] == partition['path']:
                            root = self.config.simulate / 'roots' / role if self.config.simulate else Path('/')
                            path, inventory = self.backend.preserve(job, root, 'rescue')
                        else:
                            ensure_unmounted(self.config, device, partition)
                            with self.backend.mount(partition) as root:
                                path, inventory = self.backend.preserve(job, root, 'rescue')
                        self.store.save(job, rescue_snapshot=path, rescue_inventory=inventory)
                    if job['target'] in ('system', 'all') and not job.get('snapshot'):
                        if device['mode'] == 'system':
                            root = self.config.simulate / 'roots/system' if self.config.simulate else Path('/')
                            path, inventory = self.backend.preserve(job, root)
                        else:
                            partition = storage['partitions']['system']
                            ensure_unmounted(self.config, device, partition)
                            with self.backend.mount(partition) as root:
                                path, inventory = self.backend.preserve(job, root)
                        self.store.save(job, snapshot=path, inventory=inventory)
                    self.backend.validate_payloads(job)
                    self._check_cancel(job)
                    self.store.save(job, 'ready', 'All resources verified before disk writing')
                if device['mode'] == 'system':
                    require(not job['write_started'], 'running_root', 'A write-stage task cannot resume in the normal OS')
                    control['next'] = {'target': 'rescue', 'slot': control['confirmed']['rescue']['slot'], 'trial': False}
                    self.store.write_control(control)
                    self.store.save(job, 'awaiting-rescue', 'Rebooting into confirmed Rescue')
                    self.backend.request_reboot()
                    return job
                self.backend.verify_resources(job)
                if job['target'] in ('rescue', 'all') and 'rescue-confirmed' not in job['checkpoints']:
                    slot = job['plan']['inactive_rescue_slot']
                    partition = storage['partitions']['rescue_' + slot]
                    # Even if the control data is wrong, active-root guards prevent overwriting the running slot.
                    ensure_unmounted(self.config, device, partition)
                    control['next'] = {'target': 'rescue', 'slot': control['confirmed']['rescue']['slot'], 'trial': False}
                    self.store.write_control(control)
                    self._begin_write(job, 'deploying-rescue', 'Writing inactive Rescue slot')
                    if 'rescue-written' not in job['checkpoints']:
                        artifact = next(item for item in job['manifest']['artifacts'] if item['role'] == 'rescue-rootfs')
                        from .deployment import begin, complete
                        begin(self.config, device, 'rescue_' + slot, partition, job)
                        partition['_deployment_role'] = 'rescue_' + slot
                        self.backend.write_image(artifact, partition, lambda done, total: self._progress(job, done, total))
                        self.backend.restore(job, partition, 'rescue')
                        self.backend.prepare_root(job, 'rescue', partition)
                        reference = self.backend.boot_files(job, 'rescue', partition)
                        self.store.save(job, rescue_candidate={'slot': slot, 'boot': reference})
                        self.store.checkpoint(job, 'rescue-written')
                        complete(self.config, 'rescue_' + slot)
                    self._trial(job, control, 'rescue', job['rescue_candidate'])
                    return job
                if job['target'] in ('system', 'all') and 'system-confirmed' not in job['checkpoints']:
                    partition = storage['partitions']['system']
                    ensure_unmounted(self.config, device, partition)
                    # Make a half-written normal root unbootable before the first write.
                    control['system_blocked'] = True
                    control['next'] = {'target': 'rescue', 'slot': control['confirmed']['rescue']['slot'], 'trial': False}
                    self.store.write_control(control)
                    self._begin_write(job, 'deploying-system', 'Writing offline SATA system; DATA is untouched')
                    if 'system-written' not in job['checkpoints']:
                        artifact = next(item for item in job['manifest']['artifacts'] if item['role'] == 'system-rootfs')
                        from .deployment import begin, complete
                        begin(self.config, device, 'system', partition, job)
                        partition['_deployment_role'] = 'system'
                        self.backend.write_image(artifact, partition, lambda done, total: self._progress(job, done, total))
                        self.backend.restore(job, partition)
                        self.backend.prepare_root(job, 'system', partition)
                        reference = self.backend.boot_files(job, 'system')
                        self.store.save(job, system_candidate={'boot': reference})
                        self.store.checkpoint(job, 'system-written')
                        complete(self.config, 'system')
                    self._trial(job, control, 'system', job['system_candidate'])
                    return job
                return self._success(job, control)
            except Exception as error:
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                if getattr(error, 'code', '') == 'cancelled':
                    self.store.save(job, 'cancelled', 'Cancelled before disk writing')
                    control = self.store.control()
                    control['next'] = {'target': 'system' if control['confirmed'].get('system') else 'rescue',
                                       'slot': control['confirmed']['rescue']['slot'], 'trial': False}
                    self.store.write_control(control)
                else:
                    self.store.fail(job, error)
                return job

    def _check_cancel(self, job):
        marker = self.config.state / 'cancel-requests' / (job['job_id'] + '.json')
        if marker.exists() and not job['write_started']:
            raise OTAError('cancelled', 'Cancellation was requested before disk writing')

    def _begin_write(self, job, stage, message):
        with writer_lock(self.config.state / 'admission.lock'):
            self._check_cancel(job)
            self.clock.require_valid()
            self.clock.flush('before-writing')
            self.store.save(job, stage, message, write_started=True)

    def _progress(self, job, done, total):
        old = job.get('progress', {})
        if done == total or done - old.get('bytes', 0) >= 8 * 1024 * 1024:
            self.store.save(job, progress={'bytes': done, 'total': total, 'operation': job['stage']})

    def _trial(self, job, control, target, candidate):
        trial = {'task': job['job_id'], 'target': target, 'candidate': candidate, 'attempted': False}
        control['trial'] = trial
        control['next'] = {'target': target, 'slot': candidate.get('slot'), 'trial': True}
        self.store.save(job, 'trial-' + target, 'Starting one monitored boot trial')
        # Job is durable first; a crash before control switches leaves a confirmed Rescue available.
        self.store.write_control(control)
        self.backend.request_reboot()

    def confirm(self):
        with self.store.lock():
            if not self.config.simulate and Path('/run/armhpc-ota-maintenance-recovery').exists():
                Path('/run/armhpc-ota-healthy').touch(); return None
            from .boot_maintenance import confirm_diagnostic
            if confirm_diagnostic(self): return None
            job = self.store.read()
            if job and job['stage']=='succeeded':
                from .boot_maintenance import finish_paired_system
                finish_paired_system(self,job)
            if not job or job['stage'] not in ('trial-rescue', 'trial-system'):
                self._confirm_regular_boot()
                return None
            try:
                device, storage, control = self._recheck(job)
                target = job['stage'].split('-', 1)[1]
                reconciled = target + '-health-passed' in job['checkpoints']
                if not reconciled and not control.get('trial'):
                    require(device['mode'] == 'rescue' and device['root'] ==
                            storage['partitions']['rescue_' + control['confirmed']['rescue']['slot']]['path'],
                            'trial_transaction', 'Uncommitted trial is not running in confirmed Rescue')
                    self._confirm_regular_boot()
                    return job
                require(device['mode'] == target and (reconciled or (control.get('trial') and control['trial']['task'] == job['job_id'])),
                        'trial_target', 'Health confirmation is from the wrong boot environment')
                self.backend.health(job, target, storage)
                candidate = job[target + '_candidate']
                control['confirmed'][target] = candidate
                control['highest_sequence'] = max(control.get('highest_sequence', 0), job['manifest']['sequence'])
                control['trial'] = None
                if target == 'system':
                    control['system_blocked'] = False
                else:
                    control['bad_slots'] = [slot for slot in control.get('bad_slots', []) if slot != candidate['slot']]
                self.backend.baseline(job, target)
                self.store.checkpoint(job, target + '-health-passed')
                self.store.write_control(control)
                self.store.checkpoint(job, target + '-confirmed')
                if target == 'rescue' and job['target'] == 'all':
                    self.store.save(job, 'ready', 'Rescue confirmed; preparing normal-system deployment')
                    return job
                return self._success(job, control)
            except Exception as error:
                result = self.store.fail(job, error)
                if getattr(error, 'code', '') not in ('clock_persist_failed', 'clock_state_invalid'):
                    self.backend.request_reboot()
                return result

    def _confirm_regular_boot(self):
        control = self.store.control()
        attempt = control.get('boot_attempt')
        if not attempt or not attempt.get('pending'):
            return
        device = discover(self.config)
        target = attempt['target']
        require(device['mode'] == target, 'health_mode', 'Regular boot did not enter the selected environment')
        storage = layout(self.config, device, initialized=True)
        candidate = control['confirmed'][target]
        dummy = {'job_id': 'confirmed-boot', 'checkpoints': [target + '-health-passed'],
                 'manifest': {'kernels': {target: candidate['boot']['kernel_release']}},
                 'rescue_candidate': control['confirmed']['rescue']}
        self.backend.health(dummy, target, storage)
        attempt['pending'] = False
        self.store.write_control(control)

    def _success(self, job, control):
        control['next'] = {'target': 'system' if control['confirmed'].get('system') and not control.get('system_blocked') else 'rescue',
                           'slot': control['confirmed']['rescue']['slot'], 'trial': False}
        self.store.write_control(control)
        self.backend.collect_old_baselines()
        result=self.store.save(job, 'succeeded', 'Upgrade confirmed by boot, storage, network and SSH health checks')
        from .boot_maintenance import finish_paired_system
        finish_paired_system(self,result)
        return result

    def cancel(self, job_id=None):
        with writer_lock(self.config.state / 'admission.lock'):
            job = self.store.read(job_id)
            require(job is not None, 'job_missing', 'No job to cancel')
            require(not job['write_started'] and job['stage'] not in TERMINAL, 'cancel_boundary',
                    'The job cannot be cancelled after disk writing starts')
            atomic_json(self.config.state / 'cancel-requests' / (job['job_id'] + '.json'), {'job_id': job['job_id']})
        try:
            with self.store.lock():
                self.store.save(job, 'cancelled', 'Cancelled before disk writing')
                control = self.store.control()
                control['next'] = {'target': 'system' if control['confirmed'].get('system') else 'rescue',
                                   'slot': control['confirmed']['rescue']['slot'], 'trial': False}
                self.store.write_control(control)
        except OTAError as error:
            if error.code != 'busy':
                raise
            job = {**job, 'stage': 'cancel-requested'}
        return job

    def request_rescue_boot(self, cancel=False):
        with self.store.lock():
            control = self.store.control()
            job = self.store.read()
            require(job is None or job['stage'] in TERMINAL, 'job_active', 'Finish or cancel the OTA task before changing its boot target')
            target = 'system' if cancel and control['confirmed'].get('system') and not control.get('system_blocked') else 'rescue'
            control['next'] = {'target': target, 'slot': control['confirmed']['rescue']['slot'], 'trial': False, 'once': not cancel}
            self.store.write_control(control)
        return target


def public_job(job):
    if not job:
        return None
    return {key: value for key, value in job.items() if key in (
        'job_id', 'created', 'updated', 'stage', 'kind', 'release', 'target', 'device_id',
        'write_started', 'checkpoints', 'progress', 'events', 'error', 'retry_count', 'clock', 'resume_count', 'trial_failures')}
