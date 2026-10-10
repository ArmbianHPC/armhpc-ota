# SPDX-License-Identifier: GPL-3.0-only
"""SquashFS-specific preservation and offline validation; normal roots remain ext4."""
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import tempfile
from .backend import Backend, _prepare_chroot_null, _staged_debs, verify_software_plan
from . import preserve
from .device import discover, layout, run
from .errors import require
from .io import read_json, sha256, atomic_json
from .squashfs import overlay_mount, generation, mark_ready, write_trailer, superblock, boot_context


class SquashFSBackend(Backend):
    def write_image(self, artifact, partition, progress=None):
        super().write_image(artifact, partition, progress)
        if artifact.get('encoding') != 'squashfs' or self.config.simulate: return
        from .deployment import ledger
        role = partition.get('_deployment_role')
        require(role in ('rescue_a', 'rescue_b'), 'deployment_intent', 'Direct slot deployment requires a durable write intent')
        release = ledger(self.config)['targets'][role]['release']
        slot = role[-1]
        base = generation(self.config.state, slot, release).parent
        # The active lower partition is protected by the parent writer. Remove only
        # obsolete writable generations of this just-rewritten inactive slot.
        if base.exists():
            for item in base.iterdir():
                require(item.is_dir() and not item.is_symlink() and item.resolve().is_relative_to(base.resolve()),
                        'overlay_path', 'Unsafe inactive overlay generation')
                shutil.rmtree(item)

    @contextmanager
    def mount(self, partition, writable=False):
        if self.config.simulate or partition.get('fstype') != 'squashfs':
            with super().mount(partition, writable) as root: yield root
            return
        labels = self.config.board()['labels']
        slot = next((s for s in ('a', 'b') if partition['label'] == labels['rescue_' + s]), None)
        require(slot, 'slot_target', 'Unknown SquashFS partition')
        with overlay_mount(partition['path'], self.config.state, slot, writable) as root: yield root

    def validate_squashfs(self, job, artifact):
        path = self.config.cache / artifact['sha256']
        require(path.stat().st_size == artifact['size'] and sha256(path) == artifact['sha256'],
                'artifact_hash', 'SquashFS payload has changed')
        require(superblock(path)['bytes_used'] <= artifact['size'], 'squashfs_size', 'Invalid SquashFS used size')
        snapshot = job.get('rescue_snapshot')
        inventory = preserve.validate_snapshot(snapshot) if snapshot else None
        needed = (int(inventory['bytes']) if inventory else 0) + 128 * 1024**2
        require(shutil.disk_usage(self.config.cache).free >= needed + 64 * 1024**2,
                'validation_space', 'No room for offline Rescue overlay validation')
        require(shutil.disk_usage(self.config.state).free >= needed + 512 * 1024**2,
                'overlay_space', 'Shared storage cannot preserve Rescue configuration and reserve')
        loop = run('losetup', '--find', '--show', '--read-only', path.resolve(strict=True))
        try:
            with tempfile.TemporaryDirectory(prefix='validate-overlay-', dir=self.config.cache) as temporary:
                with overlay_mount(loop, temporary, 'b', True, job['release']) as root:
                    _prepare_chroot_null(root)
                    marker = read_json(root / 'etc/armhpc/release.json')
                    require(marker.get('release') == job['release'] and marker.get('target') == 'rescue',
                            'root_version', 'SquashFS root version differs from its signed release')
                    kernel = job['manifest']['kernels']['rescue']
                    require((root / 'lib/modules' / kernel).is_dir() and
                            (root / 'usr/lib/armhpc-ota/armhpc_ota').is_dir(), 'payload_runtime', 'Missing Rescue modules or OTA agent')
                    for name in ('kernel', 'initramfs', 'dtb'):
                        item = next(a for a in job['manifest']['artifacts'] if a['role'] == 'rescue-' + name)
                        require(sha256(root / 'usr/lib/armhpc-ota/boot' / name) == item['sha256'],
                                'fallback_pairing', 'SquashFS independent boot copy differs from signed boot artifact')
                    if inventory:
                        preserve.validate_accounts(inventory['accounts'], root)
                        preserve.restore(snapshot, root)
                        (root / 'run/sshd').mkdir(parents=True, exist_ok=True)
                        run('chroot', root, '/usr/sbin/sshd', '-t')
                        if inventory.get('debs'):
                            with _staged_debs(root, Path(snapshot) / 'debs', inventory['debs']) as arguments:
                                simulation = run('chroot', root, 'apt-get', '-s', '--no-remove', 'install', *arguments)
                                available = {(run('dpkg-deb', '-f', Path(snapshot) / 'debs' / d['file'], 'Package'),
                                              run('dpkg-deb', '-f', Path(snapshot) / 'debs' / d['file'], 'Version')) for d in inventory['debs']}
                                verify_software_plan(simulation, available)
        finally: run('losetup', '--detach', loop)

    def prepare_root(self, job, target, partition):
        super().prepare_root(job, target, partition)
        if not self.config.simulate and target == 'rescue':
            slot = 'a' if partition['label'] == self.config.board()['labels']['rescue_a'] else 'b'
            artifact = next(a for a in job['manifest']['artifacts'] if a['role'] == 'rescue-rootfs')
            mark_ready(self.config.state, slot, job['release'], artifact['sha256'])
            # Publish the slot only after its entire image and restored writable state are durable.
            os.sync()
            write_trailer(partition['path'], partition['size'],
                          (self.config.state / 'manifests' / (job['release'] + '.json')).read_bytes())

    def boot_files(self, job, target, partition=None):
        # Independent boot files are part of the immutable, signed SquashFS payload.
        return super().boot_files(job, target, None)

    def install_slot_fallback(self, job, root):
        raise RuntimeError('SquashFS fallback copies must be built into the signed base image')
