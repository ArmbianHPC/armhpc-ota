# SPDX-License-Identifier: GPL-3.0-only
"""Explicit preservation policy; never replace the new system's entire /etc."""
import base64
import fnmatch
import hashlib
import os
import re
from pathlib import Path
import shutil
import stat
import tarfile
from .device import run
from .errors import require
from .io import atomic_json, read_json, sha256, inside, fsync_dir

POLICY = (
    'root', 'home', 'etc/ssh/ssh_host_*', 'etc/ssh/sshd_config', 'etc/ssh/sshd_config.d',
    'etc/ssh/image-framework-admin.conf', 'var/lib/armhpc/auth',
    'var/lib/armhpc/firewall',
    'etc/armhpc/management-network.json', 'var/lib/armhpc/network-config',
    'etc/armhpc/data-identity.json',
    'etc/systemd/network', 'etc/NetworkManager/system-connections', 'etc/netplan',
    'etc/network/interfaces', 'etc/network/interfaces.d', 'etc/rancher/k3s',
    'etc/systemd/system/k3s.service', 'etc/systemd/system/k3s-agent.service',
    'etc/systemd/system/k3s.service.env', 'etc/systemd/system/k3s-agent.service.env',
    'etc/systemd/system/k3s.service.d', 'etc/systemd/system/k3s-agent.service.d',
    'etc/chrony/chrony.conf', 'etc/chrony/conf.d', 'etc/chrony/sources.d',
    'etc/machine-id', 'var/lib/armhpc/clock-floor.json', 'var/lib/armhpc/clock-resume.json', 'var/lib/armhpc/network-identity.json', 'var/lib/armhpc/k3s',
    'var/lib/armhpc/network-ports-identity.json','var/lib/armhpc/fan-settings.json',
    'etc/armhpc/k3s.json', 'etc/armhpc/installation-policy.json',
    'etc/image-framework/k3s.json', 'var/lib/image-framework/k3s', 'etc/rancher/node',
    'etc/sysctl.d/90-k3s.conf',
    'usr/local/bin/k3s', 'usr/local/bin/k3s-uninstall.sh', 'usr/local/bin/k3s-agent-uninstall.sh',
    'usr/local/bin/k3s-killall.sh', 'etc/sudoers.d', 'etc/apt/sources.list.d',
    'etc/image-framework/admin-provisioned.json', 'etc/armhpc/authentication.json',
)


SYSTEM_POLICY = ('etc/hostname', 'etc/hosts')


def policy(target='system'):
    require(target in ('system', 'rescue', 'all'), 'preserve_target', 'Unknown preservation target')
    return POLICY + (SYSTEM_POLICY if target in ('system', 'all') else ())


def require_network_confirmed(root):
    firewall = Path(root) / 'var/lib/armhpc/firewall/state.json'
    if firewall.exists():
        require(not firewall.is_symlink() and read_json(firewall).get('stage')!='pending',
                'firewall_pending','Confirm or roll back the firewall transaction before OTA')
    auth = Path(root) / 'var/lib/armhpc/auth/state.json'
    if auth.exists():
        require(not auth.is_symlink(), 'auth_pending', 'Authentication state must not be a symbolic link')
        require(read_json(auth).get('stage') not in ('key-check', 'policy-check'),
                'auth_pending', 'Confirm or roll back SSH authentication before OTA or tool maintenance')
    path = Path(root) / 'var/lib/armhpc/network-config/transaction.json'
    if path.exists():
        require(not path.is_symlink(), 'network_pending', 'Network transaction must not be a symbolic link')
        value = read_json(path)
        require(value.get('stage') in ('confirmed', 'rolled-back', 'failed'),
                'network_pending', 'Confirm or roll back the pending network configuration before OTA or tool maintenance')


def records(root, filename):
    path = Path(root) / 'etc' / filename
    return [line.split(':') for line in path.read_text().splitlines() if line and not line.startswith('#')] if path.exists() else []


def accounts(root):
    passwd = records(root, 'passwd')
    admins = {'root'}
    for group in records(root, 'group'):
        if group[0] in ('sudo', 'wheel', 'admin'):
            admins.update(filter(None, group[3].split(',')))
    selected = [row for row in passwd if row[0] in admins or 1000 <= int(row[2]) < 65534]
    names, gids = {row[0] for row in selected}, {row[3] for row in selected}
    groups = [row for row in records(root, 'group') if row[2] in gids or names.intersection(row[3].split(','))]
    return {'passwd': selected, 'shadow': [row for row in records(root, 'shadow') if row[0] in names],
            'group': groups, 'gshadow': [row for row in records(root, 'gshadow') if row[0] in {g[0] for g in groups}]}


def validate_accounts(saved, target):
    for filename, index in (('passwd', 2), ('group', 2)):
        existing = records(target, filename)
        for item in saved[filename]:
            for original in existing:
                require(not (original[index] == item[index] and original[0] != item[0]),
                        'identity_conflict', 'User/group numeric ID conflicts with the new baseline', name=item[0])
                require(not (original[0] == item[0] and original[index] != item[index]),
                        'identity_conflict', 'User/group name has a different ID in the new baseline', name=item[0])


def merge_accounts(saved, target):
    validate_accounts(saved, target)
    from .io import atomic_bytes
    for filename in ('passwd', 'shadow', 'group', 'gshadow'):
        existing = {row[0]: row for row in records(target, filename)}
        for row in saved[filename]:
            if filename in ('group', 'gshadow') and row[0] in existing:
                old = existing[row[0]]
                combined = sorted(set(filter(None, old[3].split(',') + row[3].split(','))))
                row = row[:3] + [','.join(combined)]
            existing[row[0]] = row
        path = Path(target) / 'etc' / filename
        atomic_bytes(path, ('\n'.join(':'.join(row) for row in existing.values()) + '\n').encode(),
                     mode=0o600 if filename in ('shadow', 'gshadow') else 0o644)


def selected_paths(root, saved, extra=()):
    root = Path(root)
    result = []
    patterns = list(POLICY) + list(extra)
    for user in saved['passwd']:
        home = user[5].lstrip('/')
        if home and home not in ('', 'nonexistent') and home not in patterns:
            patterns.append(home)
    for pattern in patterns:
        for path in sorted(root.glob(pattern)):
            require(path.resolve().is_relative_to(root.resolve()) or path.is_symlink(),
                    'preserve_path', 'Preservation path escapes the root')
            if any(path == parent or parent in path.parents for parent in result):
                continue
            result.append(path)
    return result


DATA_BIND_TARGETS = {'/var/lib/kubelet', '/etc/rancher/node'}


def data_bindings(root):
    fstab = Path(root) / 'etc/fstab'
    result = []
    for line in fstab.read_text().splitlines() if fstab.exists() else []:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        fields = line.split()
        if len(fields) < 4 or fields[1] not in DATA_BIND_TARGETS:
            continue
        source, target, filesystem, options = fields[:4]
        require(source.startswith('/data/') and '..' not in source.split('/') and
                '\\' not in source and filesystem == 'none' and 'bind' in options.split(','),
                'preserve_binding', 'K3s persistent mounts must be safe directory bindings from DATA')
        require(not any(item['target'] == target for item in result),
                'preserve_binding', 'Duplicate persistent DATA binding')
        result.append({'source': source, 'target': target})
    return result


def restore_bindings(bindings, root):
    fstab = Path(root) / 'etc/fstab'
    lines = fstab.read_text().splitlines() if fstab.exists() else []
    for item in bindings:
        source, target = item['source'], item['target']
        require(target in DATA_BIND_TARGETS and source.startswith('/data/') and
                '..' not in source.split('/') and '\\' not in source,
                'restore_binding', 'Unsafe saved DATA binding')
        destination = inside(root, target.lstrip('/'))
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        lines = [line for line in lines if line.lstrip().startswith('#') or
                 len(line.split()) < 2 or line.split()[1] != target]
        lines.append(source + ' ' + target + ' none bind,x-systemd.requires-mounts-for=/data 0 0')
    if bindings:
        from .io import atomic_bytes
        atomic_bytes(fstab, ('\n'.join(lines) + '\n').encode(), 0o644)


def tree_size(paths, excluded=()):
    total = 0
    excluded = set(excluded)
    for path in paths:
        if path in excluded or path.is_symlink():
            continue
        if path.is_dir():
            for directory, dirs, files in os.walk(path, followlinks=False):
                dirs[:] = [name for name in dirs if Path(directory) / name not in excluded and
                           not (Path(directory) / name).is_symlink()]
                total += sum((Path(directory) / name).lstat().st_size for name in files
                             if not (Path(directory) / name).is_symlink())
        else:
            total += path.stat().st_size
    return total


def validate_snapshot(snapshot_dir):
    snapshot_dir = Path(snapshot_dir)
    inventory = read_json(snapshot_dir / 'inventory.json')
    archive = snapshot_dir / 'selected.tar'
    require(archive.is_file() and sha256(archive) == inventory['archive_sha256'],
            'preserve_hash', 'Configuration backup failed integrity verification')
    for package in inventory.get('debs', []):
        name = package['file']
        require(Path(name).name == name and '/' not in name and '\\' not in name,
                'software_path', 'Unsafe prepared package filename')
        path = snapshot_dir / 'debs' / name
        require(path.is_file() and sha256(path) == package['sha256'],
                'software_hash', 'Prepared exact-version software resource changed')
    return inventory


def snapshot(root, destination, baseline_packages, simulate=False, extra=()):
    root, destination = Path(root), Path(destination)
    saved = accounts(root)
    packages, conffiles, k3s_version = [], [], None
    if not simulate:
        k3s_version = run('chroot', root, '/usr/local/bin/k3s', '--version') if (root / 'usr/local/bin/k3s').exists() else None
        installed = run('chroot', root, 'dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n')
        known = {item['name'] for item in baseline_packages}
        packages = [{'name': row.split('\t')[0], 'version': row.split('\t')[1]}
                    for row in installed.splitlines() if len(row.split('\t')) == 3 and row.split('\t')[2] == 'installed'
                    and row.split('\t')[0] not in known and
                    not row.startswith(('linux-image-', 'linux-dtb-', 'linux-headers-', 'armhpc-ota\t'))]
        for package in packages:
            output = run('chroot', root, 'dpkg-query', '-W', '-f=${Conffiles}', package['name'])
            for line in output.splitlines():
                if line.strip():
                    name = line.split()[0].lstrip('/')
                    if name.startswith('etc/') and name not in ('etc/passwd', 'etc/shadow', 'etc/group', 'etc/gshadow', 'etc/fstab'):
                        inside(root, name)
                        conffiles.append(name)
    bindings = data_bindings(root)
    excluded = {root / item['target'].lstrip('/') for item in bindings}
    selected = selected_paths(root, saved, [*conffiles, *extra])
    total = tree_size(selected, excluded)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(shutil.disk_usage(destination).free >= total + 64 * 1024 * 1024,
            'preserve_space', 'Not enough space for the selected user/configuration backup')
    archive = destination / 'selected.tar'
    temporary_archive = destination / '.selected.tar.partial'
    root_device = root.stat().st_dev
    overlay_root = not simulate and run('findmnt', '-n', '-o', 'FSTYPE', '--mountpoint', root, accepted=(0, 1)) == 'overlay'
    boundaries = []
    if overlay_root:
        # SquashFS has no filesystem UUID; Linux may disable xino and expose the
        # backing inode's st_dev. Mount boundaries, not st_dev, identify external data.
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            name = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), line.split()[4])
            point = Path(name)
            if point != root.resolve() and point.is_relative_to(root.resolve()): boundaries.append(point)
    def metadata(member):
        physical = root / member.name
        if physical in excluded:
            return None
        require((not any(p == physical or p in physical.parents for p in boundaries)) if overlay_root else
                physical.lstat().st_dev == root_device, 'preserve_mount',
                'Selected directory crosses a mounted filesystem; keep that data on DATA')
        require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                'preserve_special', 'Devices/sockets/FIFOs cannot be restored from user directories')
        if hasattr(os, 'listxattr'):
            for name in os.listxattr(physical, follow_symlinks=False):
                if name.startswith(('user.', 'security.', 'system.posix_acl_')):
                    member.pax_headers['ARMHPC.xattr.' + name] = base64.b64encode(
                        os.getxattr(physical, name, follow_symlinks=False)).decode('ascii')
        return member
    with tarfile.open(temporary_archive, 'w', format=tarfile.PAX_FORMAT, dereference=False) as output:
        for path in selected:
            output.add(path, arcname=path.relative_to(root).as_posix(), filter=metadata)
    os.chmod(temporary_archive, 0o600)
    with temporary_archive.open('rb') as handle:
        os.fsync(handle.fileno())
    os.replace(temporary_archive, archive)
    fsync_dir(destination)
    enabled = [service for service in ('k3s.service', 'k3s-agent.service')
               if (root / 'etc/systemd/system/multi-user.target.wants' / service).is_symlink()]
    inventory = {'accounts': saved, 'archive_sha256': sha256(archive), 'bytes': total,
                 'paths': [path.relative_to(root).as_posix() for path in selected], 'packages': packages, 'k3s_version': k3s_version,
                 'data_bindings': bindings, 'enabled_services': enabled}
    atomic_json(destination / 'inventory.json', inventory)
    return inventory


def restore(snapshot_dir, target):
    snapshot_dir, target = Path(snapshot_dir), Path(target)
    inventory = validate_snapshot(snapshot_dir)
    archive = snapshot_dir / 'selected.tar'
    validate_accounts(inventory['accounts'], target)
    with tarfile.open(archive) as source:
        for member in source:
            path = target.joinpath(*member.name.split('/'))
            require(not member.name.startswith('/') and all(part not in ('', '.', '..') for part in member.name.split('/')),
                    'restore_path', 'Unsafe backup member')
            require(path.parent.resolve().is_relative_to(target.resolve()), 'restore_path', 'A backup symlink escapes the target')
            if path.is_symlink() and not member.issym():
                path.unlink()
            path.parent.mkdir(parents=True, exist_ok=True)
            if not member.isdir() and path.is_dir() and not path.is_symlink():
                require(path.resolve().is_relative_to(target.resolve()) and not path.is_mount(),
                        'restore_path', 'Cannot replace a mounted or external baseline directory')
                shutil.rmtree(path)
            if member.isdir():
                path.mkdir(exist_ok=True)
            elif member.issym():
                path.unlink(missing_ok=True); path.symlink_to(member.linkname)
            elif member.islnk():
                link = inside(target, member.linkname)
                path.unlink(missing_ok=True); os.link(link, path)
            elif member.isfile():
                with source.extractfile(member) as input_file, path.open('wb') as output:
                    shutil.copyfileobj(input_file, output)
            else:
                require(False, 'restore_special', 'Unsafe special file in backup')
            if os.name != 'nt':
                os.chown(path, member.uid, member.gid, follow_symlinks=False)
                if not member.issym():
                    os.chmod(path, member.mode)
                for name, value in member.pax_headers.items():
                    if name.startswith('ARMHPC.xattr.'):
                        os.setxattr(path, name[len('ARMHPC.xattr.'):], base64.b64decode(value), follow_symlinks=False)
    merge_accounts(inventory['accounts'], target)
    restore_bindings(inventory.get('data_bindings', []), target)
    return inventory
