# SPDX-License-Identifier: GPL-3.0-only
"""Linux block writes and a directory-backed fault-injection backend."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from .device import run, discover, layout, ensure_unmounted
from .errors import require, OTAError
from .io import atomic_json, atomic_bytes, read_json, sha256, identifier
from . import preserve
import time
import re


def verify_software_plan(simulation, available):
    """APT simulation may choose repository dependencies without proving they are cached."""
    for line in simulation.splitlines():
        if line.startswith('Inst '):
            match = re.match(r'Inst\s+(\S+)(?:\s+\[[^]]+\])?\s+\((\S+)', line)
            require(match and (match[1].split(':')[0], match[2]) in available,
                    'software_resources', 'Offline software plan needs a package/version not present in the prepared resources')


def _prepare_chroot_null(root):
    """Only the null sink is needed for offline sshd/APT; expose no host devices."""
    directory = Path(root) / "dev"
    require(not directory.is_symlink(), "chroot_device", "Offline /dev must not be a symlink")
    directory.mkdir(exist_ok=True)
    null = directory / "null"
    require(not null.is_symlink(), "chroot_device", "Offline /dev/null must not be a symlink")
    if not null.exists():
        os.mknod(null, 0o20666, os.makedev(1, 3))
        null.chmod(0o666)
    require(null.is_char_device() and null.stat().st_rdev == os.makedev(1, 3),
            "chroot_device", "Offline /dev/null is not the expected null device")


@contextmanager
def _staged_debs(root, resources, packages):
    """APT --no-download needs local archives already in its own cache."""
    directory = Path(root) / "var/cache/apt/archives"
    directory.mkdir(parents=True, exist_ok=True)
    created, arguments = [], []
    try:
        for package in packages:
            filename = package["file"]
            require(Path(filename).name == filename and not filename.startswith("."),
                    "software_path", "Invalid preserved package filename")
            source = Path(resources) / filename
            require(sha256(source) == package["sha256"], "software_hash", "Software resource changed")
            destination = directory / filename
            require(not destination.is_symlink(), "software_cache", "Package cache entry must not be a symlink")
            if destination.exists():
                require(sha256(destination) == package["sha256"], "software_cache", "Existing cached package differs")
            else:
                created.append(destination)
                shutil.copy2(source, destination)
                destination.chmod(0o644)
            arguments.append("/var/cache/apt/archives/" + filename)
        yield arguments
    finally:
        for destination in created:
            destination.unlink(missing_ok=True)


def validation_copy_size(expanded_size, preserved_bytes, package_bytes, capacity):
    """Size a disposable validation image without counting free blocks as used.

    The preservation estimate is deliberately conservative and may exceed the
    partition even when the actual restored filesystem fits. Clamp that estimate
    to the real target; restoring into this copy is the authoritative fit check.
    """
    target_size = capacity // 4096 * 4096
    require(expanded_size <= target_size, "capacity", "Expanded image does not fit the target")
    wanted = ((expanded_size + preserved_bytes + package_bytes + 128 * 1024**2 + 4095) // 4096) * 4096
    return min(wanted, target_size)


class Backend:
    def __init__(self, config):
        self.config = config

    @contextmanager
    def mount(self, partition, writable=False):
        if self.config.simulate:
            role = identifier(partition['fixture_role'])
            path = self.config.simulate / 'roots' / role
            path.mkdir(parents=True, exist_ok=True)
            yield path
            return
        with tempfile.TemporaryDirectory(prefix='armhpc-ota-mount-') as directory:
            run('mount', '-t', 'ext4', '-o', 'rw' if writable else 'ro,noload', partition['path'], directory)
            try:
                yield Path(directory)
            finally:
                run('umount', directory)

    def write_image(self, artifact, partition, progress=None):
        config = self.config
        current = discover(config)
        from .deployment import verify_target
        actual = verify_target(config, current, partition)
        ensure_unmounted(config, current, actual)
        ensure_unmounted(config, current, partition)
        limit = partition['size'] - (config.board().get('trailer_bytes', 0) if artifact.get('encoding') == 'squashfs' else 0)
        require(artifact['expanded_size'] <= limit, 'capacity', 'Expanded image does not fit the target')
        payload = config.cache / artifact['sha256']
        require(payload.exists() and payload.stat().st_size == artifact['size'] and sha256(payload) == artifact['sha256'],
                'artifact_hash', 'Cached payload has changed before writing')
        if config.simulate:
            fault = current.get('fault')
            if fault == 'write-' + partition['fixture_role']:
                raise OTAError('injected_power_loss', 'Simulated interruption during rootfs deployment')
            destination = config.simulate / 'roots' / identifier(partition['fixture_role'])
            require(destination.resolve().is_relative_to((config.simulate / 'roots').resolve()),
                    'fixture_path', 'Unsafe fixture root')
            if destination.exists():
                shutil.rmtree(destination)
            destination.mkdir(parents=True, exist_ok=True)
            (destination / 'etc').mkdir()
            (destination / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\n')
            (destination / 'etc/shadow').write_text('root:*:1:0:99999:7:::\n')
            (destination / 'etc/group').write_text('root:x:0:\nsudo:x:27:\n')
            (destination / 'etc/gshadow').write_text('root:*::\nsudo:*::\n')
            atomic_json(destination / 'payload.json', {'sha256': artifact['sha256']})
            # Model the real tune2fs identity restoration after a successful rewrite.
            node = next(node for node in current['blocks'] if node['path'] == partition['path'])
            for key in ('label', 'uuid', 'fstype'):
                node[key] = partition[key]
            atomic_json(config.simulate / 'device.json', current)
            return
        path = Path(partition['path'])
        require(path.is_block_device(), 'block_target', 'Real writes require a block device')
        # The root path and device major/minor are checked again while holding the writer lock.
        if artifact.get('encoding') == 'squashfs':
            from .squashfs import write_trailer
            write_trailer(path, partition['size'])  # Invalidate before the first payload byte.
        command = ['cat', str(payload.resolve(strict=True))] if artifact.get('encoding') == 'squashfs' else ['zstd', '-dc', '--', str(payload.resolve(strict=True))]
        result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        digest, count = hashlib.sha256(), 0
        try:
            # On Linux block devices O_EXCL also rejects a mount that raced with the preflight.
            descriptor = os.open(path, os.O_RDWR | os.O_EXCL | os.O_CLOEXEC)
            with os.fdopen(descriptor, 'r+b', buffering=0) as output:
                descriptor = os.fstat(output.fileno())
                require(str(os.major(descriptor.st_rdev)) + ':' + str(os.minor(descriptor.st_rdev)) == partition['maj:min'],
                        'target_changed', 'Opened block device differs from the inspected target')
                for chunk in iter(lambda: result.stdout.read(1024 * 1024), b''):
                    count += len(chunk)
                    require(count <= artifact['expanded_size'], 'expanded_size', 'Decoded payload exceeds the signed size')
                    remaining = memoryview(chunk)
                    while remaining:
                        written = output.write(remaining)
                        require(written and written > 0, 'short_write', 'Block device stopped accepting payload bytes')
                        remaining = remaining[written:]
                    digest.update(chunk)
                    if progress:
                        progress(count, artifact['expanded_size'])
                os.fsync(output.fileno())
            require(result.wait() == 0 and count == artifact['expanded_size'] and digest.hexdigest() == artifact['expanded_sha256'],
                    'expanded_hash', 'Decoded ext4 payload failed size/SHA256 verification')
        finally:
            result.stdout.close()
            if result.poll() is None:
                result.kill(); result.wait()
        readback, remaining = hashlib.sha256(), artifact['expanded_size']
        with path.open('rb', buffering=0) as source:
            while remaining:
                data = source.read(min(1024 * 1024, remaining))
                require(data, 'readback', 'Could not read back the deployed filesystem')
                readback.update(data); remaining -= len(data)
        require(readback.hexdigest() == artifact['expanded_sha256'], 'readback_hash', 'Deployed filesystem failed readback SHA256')
        if artifact.get('encoding') == 'squashfs':
            from .squashfs import superblock
            require(superblock(path)['bytes_used'] <= artifact['size'], 'squashfs_size', 'Written SquashFS exceeds signed bytes')
            return
        run('e2fsck', '-f', '-p', path, accepted=(0, 1))
        run('tune2fs', '-U', partition['uuid'], '-L', partition['label'], path)
        run('resize2fs', path)
        run('e2fsck', '-f', '-p', path, accepted=(0, 1))

    def preserve(self, job, root, target='system'):
        if target == 'system':
            preserve.require_network_confirmed(root)
        destination = self.config.cache.parent / 'jobs' / job['job_id'] / ('preserved-' + target)
        inventory = preserve.snapshot(root, destination, job['manifest'].get('packages', {}).get(target, []),
                                      simulate=bool(self.config.simulate),
                                      extra=preserve.SYSTEM_POLICY if target == 'system' else
                                      (('usr/share/armhpc/factory',) if self.config.board().get('rescue_fstype') != 'squashfs' else ()))
        if inventory['packages'] and not self.config.simulate:
            packages = destination / 'debs'
            packages.mkdir(exist_ok=True)
            # Running in the old normal root only downloads exact installed versions.
            args = [item['name'] + '=' + item['version'] for item in inventory['packages']]
            process = subprocess.run(['apt-get', 'download', *args], cwd=packages,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            require(process.returncode == 0, 'software_resources', 'Could not download exact installed package versions')
            for item in inventory['packages']:
                require(any(run('dpkg-deb', '-f', candidate, 'Package') == item['name'].split(':')[0] and
                            run('dpkg-deb', '-f', candidate, 'Version') == item['version'] for candidate in packages.glob('*.deb')),
                        'software_resources', 'An exact installed software version could not be prepared', package=item['name'])
            inventory['debs'] = [{'file': path.name, 'sha256': sha256(path)} for path in packages.glob('*.deb')]
            atomic_json(destination / 'inventory.json', inventory)
        return str(destination), inventory

    def restore(self, job, partition, target='system'):
        snapshot = job.get('snapshot') if target == 'system' else job.get('rescue_snapshot')
        if not snapshot:
            return
        with self.mount(partition, writable=True) as root:
            if not self.config.simulate:
                _prepare_chroot_null(root)
            inventory = preserve.restore(snapshot, root)
            if not self.config.simulate and inventory.get('debs'):
                resources = Path(snapshot) / 'debs'
                with _staged_debs(root, resources, inventory['debs']) as arguments:
                    run('chroot', root, 'apt-get', '-o', 'Dpkg::Use-Pty=0', '-y', '--no-download', '--no-remove',
                        'install', *arguments)
            if not self.config.simulate:
                for service in inventory.get('enabled_services', []):
                    require(service in ('k3s.service', 'k3s-agent.service'), 'service', 'Unsupported preserved service')
                    run('systemctl', '--root', root, 'enable', service)
            if inventory.get('k3s_version') and not self.config.simulate:
                require(run('chroot', root, '/usr/local/bin/k3s', '--version') == inventory['k3s_version'],
                        'k3s_version', 'Installed K3s version changed during system restoration')
            layout_module = root / 'usr/lib/armhpc/command_layout.py'
            if layout_module.exists() and not self.config.simulate:
                import runpy
                runpy.run_path(str(layout_module))['finalize'](root, 'normal' if target == 'system' else 'rescue')

    def boot_files(self, job, target, partition=None):
        generation = self.config.state / 'kernels' / job['release'] / target
        generation.mkdir(parents=True, exist_ok=True)
        references = {}
        for item in job['manifest']['artifacts']:
            if item['role'] in (target + '-kernel', target + '-initramfs', target + '-dtb'):
                kind = item['role'].split('-', 1)[1]
                source = self.config.cache / item['sha256']
                require(sha256(source) == item['sha256'], 'boot_hash', 'Boot payload changed')
                if kind == 'initramfs':
                    require(source.read_bytes()[:4] != bytes.fromhex('27051956'), 'raw_initramfs',
                            'Legacy uImage headers are forbidden; boot requires the exact raw initramfs')
                destination = generation / kind
                atomic_bytes(destination, source.read_bytes(), 0o644)
                references[kind] = {'path': destination.relative_to(self.config.state).as_posix(), 'sha256': item['sha256']}
        references['kernel_release'] = job['manifest']['kernels'][target]
        references['release'] = job['release']
        if target == 'rescue' and partition:
            with self.mount(partition, writable=True) as root:
                copy = root / 'usr/lib/armhpc-ota/boot'
                copy.mkdir(parents=True, exist_ok=True)
                for kind in ('kernel', 'initramfs', 'dtb'):
                    atomic_bytes(copy / kind, (generation / kind).read_bytes(), 0o644)
                atomic_bytes(copy / 'manifest.json', (self.config.state / 'manifests' / (job['release'] + '.json')).read_bytes(), 0o644)
        return references

    def prepare_root(self, job, target, partition):
        with self.mount(partition, writable=True) as root:
            marker = root / 'etc/armhpc/release.json'
            if not self.config.simulate:
                actual = read_json(marker)
                require(actual.get('release') == job['release'] and actual.get('target') == target,
                        'root_version', 'Image release marker does not match its signed manifest')
                kernel = job['manifest']['kernels'][target]
                require((root / 'usr/lib/modules' / kernel).is_dir() or (root / 'lib/modules' / kernel).is_dir(),
                        'modules', 'Root image does not contain its paired kernel modules')
            else:
                marker.parent.mkdir(parents=True, exist_ok=True)
                atomic_json(marker, {'release': job['release'], 'target': target})
            atomic_json(root / 'etc/armhpc/ota-install.json', {'task': job['job_id'], 'release': job['release'], 'target': target})
            if not self.config.simulate:
                if job.get("job_id", "").startswith("bootstrap-") and target == "rescue":
                    self.install_existing_runtime(root, layout(self.config, discover(self.config), initialized=True))
                self.configure_shared_mount(root, layout(self.config, discover(self.config), initialized=True), target, partition)
                from .maintenance import retain_installed_runtime
                retain_installed_runtime(self.config, root)
                self.restore_shared_identity(root, target)

    def request_reboot(self):
        if self.config.simulate:
            device = discover(self.config)
            device['reboot_requested'] = True
            atomic_json(self.config.simulate / 'device.json', device)
        elif self.config.reboot:
            from .clock import Clock
            Clock(self.config).flush('ota-reboot')
            run('systemctl', '--no-block', 'reboot')

    def start_service(self):
        if not self.config.simulate:
            run('systemctl', 'start', '--no-block', 'armhpc-ota-worker.service')

    def verify_resources(self, job):
        from .download import required_artifacts
        if not self.config.simulate:
            self.require_runtime_resources()
        for item in required_artifacts(job['manifest'], job['target']):
            path = self.config.cache / item['sha256']
            require(path.is_file() and path.stat().st_size == item['size'] and sha256(path) == item['sha256'],
                    'artifact_hash', 'Prepared upgrade resource changed before partition writing', artifact=item['id'])
        for key in ('snapshot', 'rescue_snapshot'):
            if job.get(key):
                preserve.validate_snapshot(job[key])

    def validate_payloads(self, job):
        """Decode and inspect every filesystem before touching a real partition."""
        self.verify_resources(job)
        if self.config.simulate:
            require(not discover(self.config).get('invalid_payload'), 'payload_invalid', 'Simulated invalid rootfs')
            return
        for item in job['manifest']['artifacts']:
            target = item['role'].split('-', 1)[0]
            if job['target'] not in ('all', target) or item['role'].endswith('rootfs'):
                continue
            path = self.config.cache / item['sha256']
            require(sha256(path) == item['sha256'], 'boot_hash', 'Boot payload failed validation')
            with path.open('rb') as source:
                header = source.read(64)
            role = item['role'].split('-', 1)[1]
            if role == 'kernel':
                expected = header[56:60] == b'ARMd' if job['manifest']['architecture'] == 'arm64' else header[36:40] == bytes.fromhex('18286f01')
                require(expected, 'kernel_format', 'Boot kernel is not a raw ARM64 Image / ARM32 zImage')
            elif role == 'dtb':
                require(header[:4] == bytes.fromhex('d00dfeed'), 'dtb_format', 'Invalid DTB header')
            else:
                require(header[:4] != bytes.fromhex('27051956'), 'raw_initramfs', 'Do not use a legacy uImage header')
                with tempfile.TemporaryDirectory(prefix='initramfs-', dir=self.config.cache) as directory:
                    # Bookworm's zstd helper skips symlinks; extract the already hash-verified file.
                    run('unmkinitramfs', path.resolve(strict=True), directory)
                    selectors = list(Path(directory).rglob('scripts/local-top/armhpc-root-select'))
                    direct = list(Path(directory).rglob('scripts/armhpc')) if self.config.board().get('rescue_fstype') == 'squashfs' else []
                    require((selectors and any('armhpc.target=system|armhpc.target=rescue' in selector.read_text() for selector in selectors)) or
                            (direct and any('squashfs-boot.py' in selector.read_text() for selector in direct)), 'initramfs_root_selection',
                            'Target raw initramfs must preserve the bootstrap-selected system/Rescue A/B PARTUUID')
        for artifact in job['manifest']['artifacts']:
            target = artifact['role'].split('-', 1)[0]
            if not artifact['role'].endswith('rootfs') or job['target'] not in ('all', target):
                continue
            if artifact.get('encoding') == 'squashfs':
                self.validate_squashfs(job, artifact)
                continue
            payload = self.config.cache / artifact['sha256']
            require(sha256(payload) == artifact['sha256'], 'artifact_hash', 'Validation source changed')
            with tempfile.TemporaryDirectory(prefix='validate-', dir=self.config.cache) as directory:
                image = Path(directory) / 'root.ext4'
                decoder = subprocess.Popen(['zstd', '-dc', '--', str(payload.resolve(strict=True))], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                digest, count = hashlib.sha256(), 0
                try:
                    with image.open('wb') as output:
                        for chunk in iter(lambda: decoder.stdout.read(1024 * 1024), b''):
                            count += len(chunk)
                            require(count <= artifact['expanded_size'], 'expanded_size', 'Decoded payload exceeds signed size')
                            digest.update(chunk); output.write(chunk)
                    require(decoder.wait() == 0 and count == artifact['expanded_size'] and
                            digest.hexdigest() == artifact['expanded_sha256'], 'expanded_hash', 'Filesystem decode/hash validation failed')
                finally:
                    decoder.stdout.close()
                    if decoder.poll() is None:
                        decoder.kill(); decoder.wait()
                with image.open('rb') as handle:
                    handle.seek(1080)
                    require(handle.read(2) == b'\x53\xef', 'filesystem', 'Root image is not ext4')
                run('e2fsck', '-f', '-n', image)
                # The signed image is compact. Give the validation copy room for restored files.
                snapshot = job.get("snapshot") if target == "system" else job.get("rescue_snapshot")
                if snapshot:
                    inventory = preserve.validate_snapshot(snapshot)
                    package_extra = 0
                    for package in inventory.get("debs", []):
                        source = Path(snapshot) / "debs" / package["file"]
                        installed = run("dpkg-deb", "-f", source, "Installed-Size")
                        require(installed.isdigit(), "software_size", "Prepared package has no valid Installed-Size")
                        package_extra += source.stat().st_size + int(installed) * 1024
                    extra = int(inventory["bytes"]) + package_extra + 128 * 1024**2
                    board = self.config.board()
                    capacity = board["system_bytes"] if target == "system" else board["rescue_a_sectors"] * board["sector_size"]
                    validation_size = validation_copy_size(artifact["expanded_size"], int(inventory["bytes"]), package_extra, capacity)
                    require(shutil.disk_usage(self.config.cache).free >= extra + 64 * 1024**2,
                            "validation_space", "Not enough cache space to validate the restored filesystem")
                    with image.open("r+b") as output:
                        output.truncate(validation_size)
                    run("resize2fs", image)
                    run("e2fsck", "-f", "-n", image)
                loop = run('losetup', '--find', '--show', image)
                try:
                    with self.mount({'path': loop}, writable=True) as root:
                        _prepare_chroot_null(root)
                        marker = read_json(root / 'etc/armhpc/release.json')
                        require(marker.get('release') == job['release'] and marker.get('target') == target,
                                'root_version', 'Decoded root image belongs to a different release/target')
                        kernel = job['manifest']['kernels'][target]
                        require((root / 'lib/modules' / kernel).is_dir() and (root / 'usr/lib/armhpc-ota/armhpc_ota').is_dir(),
                                'payload_runtime', 'Paired modules or the OTA runtime are missing from the image')
                        snapshot = job.get('snapshot') if target == 'system' else job.get('rescue_snapshot')
                        if snapshot:
                            inventory = read_json(Path(snapshot) / 'inventory.json')
                            preserve.validate_accounts(inventory['accounts'], root)
                            try:
                                preserve.restore(snapshot, root)
                            except OSError as error:
                                if error.errno == 28:
                                    require(False, "preserved_capacity", "Restored files do not fit the actual target filesystem")
                                raise
                            # Prepared software and a small operating reserve must
                            # also fit after the real files have been restored.
                            require(shutil.disk_usage(root).free >= package_extra + 16 * 1024**2,
                                    "preserved_capacity", "Restored filesystem has insufficient space for prepared software and reserve")
                            (root / 'run/sshd').mkdir(parents=True, exist_ok=True)
                            run('chroot', root, '/usr/sbin/sshd', '-t')
                            if inventory.get('debs'):
                                temporary = root / 'var/tmp/armhpc-ota-debs'
                                temporary.mkdir(parents=True, exist_ok=True)
                                resources = Path(snapshot) / 'debs'
                                for item in inventory['debs']:
                                    require(sha256(resources / item['file']) == item['sha256'], 'software_hash', 'Software resource changed')
                                    shutil.copy2(resources / item['file'], temporary / item['file'])
                                # Simulation never fetches packages. --no-download rejects unstaged local .debs in Bookworm.
                                simulation = run('chroot', root, 'apt-get', '-s', '--no-remove', 'install',
                                    *['/var/tmp/armhpc-ota-debs/' + item['file'] for item in inventory['debs']])
                                available = {(run('dpkg-deb', '-f', temporary / item['file'], 'Package'),
                                              run('dpkg-deb', '-f', temporary / item['file'], 'Version')) for item in inventory['debs']}
                                verify_software_plan(simulation, available)
                finally:
                    run('losetup', '--detach', loop)

    def health(self, job, target, storage):
        device = discover(self.config)
        if self.config.simulate:
            require(not device.get('health_failure'), 'health', 'Simulated health check failed')
            expected = 'rescue_' + job['rescue_candidate']['slot'] if target == 'rescue' else 'system'
            require(device['root'] == storage['partitions'][expected]['path'], 'health_root', 'Trial boot uses the wrong root')
            require(device['kernel'] == job['manifest']['kernels'][target], 'health_kernel', 'Trial kernel differs from the manifest')
            return
        cmdline = Path('/proc/cmdline').read_text().split()
        from .squashfs import boot_context
        runtime = boot_context()
        if runtime:
            cmdline += ['armhpc.target=' + runtime['target']]
            if runtime.get('task'): cmdline += ['armhpc.task=' + runtime['task']]
        require(('armhpc.task=' + job['job_id'] in cmdline or target + '-health-passed' in job['checkpoints']) and 'armhpc.target=' + target in cmdline,
                'health_boot', 'Trial boot identity is missing or mismatched')
        expected_role = 'system' if target == 'system' else 'rescue_' + job['rescue_candidate']['slot']
        require(device['root'] == storage['partitions'][expected_role]['path'], 'health_root', 'Wrong root partition is running')
        require(device['kernel'] == job['manifest']['kernels'][target], 'health_kernel', 'Running kernel differs from manifest')
        require((Path('/lib/modules') / device['kernel']).is_dir(), 'health_modules', 'Running kernel has no matching modules')
        require('ro' in run('findmnt', '-n', '-o', 'OPTIONS', '/boot').split(','), 'health_boot_mount', 'BOOT must be mounted read-only')
        if target == 'system':
            data_source = str(Path(run('findmnt', '-n', '-o', 'SOURCE', '/data')).resolve())
            require(data_source == storage['partitions']['data']['path'], 'health_data', 'DATA is not mounted from the expected partition')
        deadline = time.monotonic() + self.config.health_timeout
        while time.monotonic() < deadline:
            ssh = subprocess.run(['systemctl', 'is-active', '--quiet', 'ssh.service']).returncode == 0
            addresses = run('ip', '-j', 'address', 'show', 'scope', 'global')
            from .io import parse_json
            connected = any(address.get('family') == 'inet' for interface in parse_json(addresses.encode())
                            for address in interface.get('addr_info', []))
            guardian = subprocess.run(['systemctl', 'is-active', '--quiet', 'armhpc-ota-watchdog.service']).returncode == 0
            watchdog_required = runtime.get('watchdog') or 'armhpc.watchdog=1' in cmdline
            if ssh and connected and (guardian or not watchdog_required):
                # fallback-health already acknowledged basic boot health before this service.
                # Waiting for NTP cannot cause an otherwise healthy boot to expire its watchdog.
                from .clock import Clock
                clock = Clock(self.config)
                state = clock.wait_ready(30)
                if state.get('valid_anchor'):
                    clock.flush('health-confirmed')
                return
            time.sleep(2)
        raise OTAError('health_network', 'SSH and a routable IPv4 address were not ready before the trial deadline')

    def baseline(self, job, target):
        """Initial baseline is immutable; current confirmed recovery resources are separate."""
        directory = self.config.state / 'baselines'
        destination = directory / 'releases' / job['release']
        destination.mkdir(parents=True, exist_ok=True)
        items = [item for item in job['manifest']['artifacts'] if item['role'].startswith(target + '-')]
        needed = sum(item['size'] for item in items if not (destination / item['sha256']).exists())
        require(shutil.disk_usage(directory).free >= needed + 32 * 1024 * 1024,
                'baseline_space', 'Insufficient shared space for the confirmed recovery package')
        for item in items:
            path = destination / item['sha256']
            if not path.exists():
                shutil.copyfile(self.config.cache / item['sha256'], path)
                with path.open('r+b') as handle:
                    os.fsync(handle.fileno())
            require(sha256(path) == item['sha256'], 'baseline_hash', 'Recovery baseline failed verification')
        atomic_bytes(destination / 'manifest.json', (self.config.state / 'manifests' / (job['release'] + '.json')).read_bytes())
        initial = directory / 'initial.json'
        if not initial.exists():
            atomic_json(initial, {'release': job['release'], 'targets': [target]})
        else:
            saved = read_json(initial)
            if saved['release'] == job['release']:
                targets = sorted(set(saved.get('targets', [saved.get('target', target)]) + [target]))
                atomic_json(initial, {'release': saved['release'], 'targets': targets})
        atomic_json(directory / ('current-' + target + '.json'), {'release': job['release'], 'target': target})

    def collect_old_baselines(self):
        directory = self.config.state / 'baselines'
        keep = set()
        for name in ('initial.json', 'current-system.json', 'current-rescue.json'):
            if (directory / name).exists():
                keep.add(identifier(read_json(directory / name)['release']))
        if (self.config.state / 'control.json').exists():
            control = read_json(self.config.state / 'control.json')
            for candidate in control.get('confirmed', {}).values():
                keep.add(identifier(candidate['boot']['release']))
        base = directory / 'releases'
        if base.exists():
            for candidate in base.iterdir():
                if candidate.is_dir() and not candidate.is_symlink() and candidate.name not in keep:
                    identifier(candidate.name)
                    require(candidate.resolve().is_relative_to(base.resolve()), 'cleanup_path', 'Unsafe recovery cleanup path')
                    shutil.rmtree(candidate)
        kernels = self.config.state / 'kernels'
        if kernels.exists():
            for candidate in kernels.iterdir():
                if candidate.is_dir() and not candidate.is_symlink() and candidate.name not in keep:
                    identifier(candidate.name)
                    require(candidate.resolve().is_relative_to(kernels.resolve()), 'cleanup_path', 'Unsafe kernel cleanup path')
                    shutil.rmtree(candidate)
        # Kernel copies inside Rescue A/B are never removed by this cache cleanup.
        return sorted(keep)

    def install_slot_fallback(self, job, root):
        root = Path(root)
        destination = root / 'usr/lib/armhpc-ota/boot'
        destination.mkdir(parents=True, exist_ok=True)
        generation = self.config.state / 'kernels' / job['release'] / 'rescue'
        for kind in ('kernel', 'initramfs', 'dtb'):
            atomic_bytes(destination / kind, (generation / kind).read_bytes(), 0o644)
        atomic_bytes(destination / 'manifest.json', (self.config.state / 'manifests' / (job['release'] + '.json')).read_bytes(), 0o644)

    def install_anchor(self, anchor, raw_manifest, storage):
        if self.config.simulate:
            atomic_json(self.config.simulate / 'anchor-installed.json', anchor)
            return
        require('ro' in run('findmnt', '-n', '-o', 'OPTIONS', '/boot').split(','), 'boot_mount',
                'BOOT must be read-only before the bootstrap cutover')
        run('mount', '-o', 'remount,rw', '/boot')
        try:
            destination = Path('/boot/armhpc-anchor')
            destination.mkdir(exist_ok=True)
            for item in anchor['artifacts']:
                atomic_bytes(destination / item['id'], (self.config.cache / item['sha256']).read_bytes(), 0o644)
            atomic_bytes(destination / 'manifest.json', raw_manifest, 0o644)
            old = Path('/boot/extlinux/extlinux.conf').read_bytes()
            atomic_bytes(Path('/boot/extlinux/legacy.conf'), old, 0o644)
            config = ('DEFAULT ARMHPC-OTA\nTIMEOUT 10\nLABEL ARMHPC-OTA\n'
                      '  LINUX /armhpc-anchor/kernel\n  INITRD /armhpc-anchor/initramfs\n'
                      '  FDT /armhpc-anchor/dtb\n'
                      '  APPEND root=LABEL=OECT_RESCUE rootfstype=ext4 rw rootwait armhpc.anchor=1 '
                      'net.ifnames=0 console=ttyS2,1500000 console=tty1 systemd.unified_cgroup_hierarchy=1 '
                      'watchdog.open_timeout=180 watchdog.stop_on_reboot=0 dw_wdt.nowayout=1\n'
                      'LABEL ARMHPC-LEGACY\n')
            # Keep an explicitly selectable legacy entry. Default switches only after all resources are durable.
            legacy_lines = old.decode().splitlines()
            config += '\n'.join('  ' + line.strip() for line in legacy_lines if line.strip() and not line.strip().startswith('LABEL ')) + '\n'
            atomic_bytes(Path('/boot/extlinux/extlinux.conf'), config.encode(), 0o644)
            run('sync', '-f', '/boot')
        finally:
            run('mount', '-o', 'remount,ro', '/boot')

    def configure_shared_mount(self, root, storage, target=None, root_partition=None):
        root = Path(root)
        fstab = root / 'etc/fstab'
        lines = fstab.read_text().splitlines() if fstab.exists() else []
        target = target or ('rescue' if (root / 'etc/armhpc/rescue-environment').exists() else 'system')
        managed_mounts = {'/', '/boot', '/data', '/var/lib/armhpc/ota'}
        lines = [line for line in lines if len(line.split()) < 2 or line.lstrip().startswith('#') or line.split()[1] not in managed_mounts]
        boot = storage['partitions']['boot']
        kind=storage['board'].get('boot_fstype','ext4')
        options='ro,noatime,umask=022' if kind=='vfat' else 'ro,noatime'
        lines.append('UUID=' + boot['uuid'] + ' /boot '+kind+' '+options+' 0 2')
        if target == 'system':
            normal, data = storage['partitions']['system'], storage['partitions']['data']
            lines.extend(['UUID=' + normal['uuid'] + ' / ext4 defaults,noatime 0 1',
                          'UUID=' + data['uuid'] + ' /data ext4 defaults,noatime 0 2'])
        else:
            cue = root_partition or storage['partitions']['rescue_a']
            if cue.get('fstype') != 'squashfs':
                lines.append('UUID=' + cue['uuid'] + ' / ext4 defaults,noatime 0 1')
            data = storage['partitions']['data']
            if data:
                lines.append('UUID=' + data['uuid'] + ' /data ext4 defaults,noatime,nofail,x-systemd.device-timeout=5s 0 2')
        shared = storage['partitions']['shared']
        shared_options = 'defaults,noatime' if target == 'system' else 'defaults,noatime,nofail,x-systemd.device-timeout=5s'
        lines.append('UUID=' + shared['uuid'] + ' /var/lib/armhpc/ota ext4 ' + shared_options + ' 0 2')
        atomic_bytes(fstab, ('\n'.join(lines) + '\n').encode(), 0o644)
        (root / 'var/lib/armhpc/ota').mkdir(parents=True, exist_ok=True)
        (root / 'data').mkdir(exist_ok=True)
        for key in self.config.trust.glob('*.pub'):
            destination = root / 'etc/armhpc/ota-trust.d' / key.name
            atomic_bytes(destination, key.read_bytes(), 0o644)
        config = {'state': '/var/lib/armhpc/ota',
                  'cache': '/data/armhpc-ota/cache' if storage['partitions']['data'] else '/var/lib/armhpc/ota/cache',
                  'trust': '/etc/armhpc/ota-trust.d', 'feed': self.config.feed,
                  'tools_source': self.config.tools_source, 'profile': self.config.profile,
                  'hardware_policy': self.config.hardware_policy, 'storage_layout': self.config.storage_layout,
                  'allowed_origins': self.config.allowed_origins, 'allow_http': self.config.allow_http}
        atomic_json(root / 'etc/armhpc/ota.json', config)

    def save_shared_identity(self, root, target):
        root = Path(root)
        directory = self.config.state / 'identities' / target
        selected = ['etc/machine-id', 'var/lib/armhpc/network-identity.json','var/lib/armhpc/network-ports-identity.json']
        selected.extend(path.relative_to(root).as_posix() for path in (root / 'etc/ssh').glob('ssh_host_*'))
        for relative in selected:
            source = root / relative
            if source.is_file():
                if relative == 'etc/machine-id' and not source.read_text().strip():
                    continue  # Bind this identity only after systemd has generated it.
                destination = directory / relative
                if relative == 'etc/machine-id' and destination.exists() and not destination.read_text().strip():
                    atomic_bytes(destination, source.read_bytes(), 0o600)
                if destination.exists():
                    require(destination.read_bytes() == source.read_bytes(), 'shared_identity', 'Existing shared SSH/machine identity differs')
                else:
                    atomic_bytes(destination, source.read_bytes(), 0o600)
        network = root / 'var/lib/armhpc/network-identity.json'
        common = self.config.state / 'identity-root/var/lib/armhpc/network-identity.json'
        if network.exists() and not common.exists():
            atomic_bytes(common, network.read_bytes())

    def restore_shared_identity(self, root, target):
        directory = self.config.state / 'identities' / target
        if not directory.exists():
            return
        for source in directory.rglob('*'):
            if source.is_file():
                relative = source.relative_to(directory)
                if relative.as_posix() == 'etc/machine-id' and not source.read_text().strip():
                    continue
                atomic_bytes(Path(root) / relative, source.read_bytes(),
                             0o644 if source.name.endswith('.pub') or source.name == 'machine-id' else 0o600)

    def install_existing_runtime(self, root, storage):
        """Install exactly this agent into legacy A/normal roots during one-time bootstrap."""
        root = Path(root)
        self.require_runtime_resources()
        current = Path(__file__).resolve().parent
        destination = root / 'usr/lib/armhpc-ota/armhpc_ota'
        if current.resolve() != destination.resolve():
            shutil.copytree(current, destination, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        resources = current.parent / 'resources'
        require(resources.is_dir(), 'runtime_resources', 'Install the release runtime resources before bootstrap')
        for source in resources.glob('*.service'):
            target = root / 'etc/systemd/system' / source.name
            atomic_bytes(target, source.read_bytes(), 0o644)
            wanted = root / 'etc/systemd/system' / ('sysinit.target.wants' if 'watchdog' in source.name else 'multi-user.target.wants')
            wanted.mkdir(parents=True, exist_ok=True)
            link = wanted / source.name
            if not link.exists():
                link.symlink_to('../' + source.name)
        for filename in ('fallback-health.py', 'boot-entry.py', 'watchdog-guard'):
            source = current.parent / filename
            require(source.is_file(), 'runtime_resources', 'Missing target-architecture runtime helper', helper=filename)
            atomic_bytes(root / 'usr/lib/armhpc-ota' / filename, source.read_bytes(), 0o755 if filename == 'watchdog-guard' else 0o644)
        self.configure_shared_mount(root, storage)

    def require_runtime_resources(self):
        current = Path(__file__).resolve().parent.parent
        require((current / 'resources').is_dir() and all((current / name).is_file() for name in
                ('watchdog-guard', 'fallback-health.py', 'boot-entry.py')),
                'runtime_resources', 'Install the target runtime resources before bootstrap; a standalone wheel is insufficient')
        if not self.config.simulate:
            from .dependencies import require_commands
            require_commands()
