# SPDX-License-Identifier: GPL-3.0-only
"""One dependency contract for the device preflight and image builders."""
import shutil
from .errors import require

SYSTEM_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
TOOL_PACKAGES = {
    'sgdisk': 'gdisk', 'sfdisk': 'fdisk', 'partx': 'util-linux',
    'lsblk': 'util-linux', 'findmnt': 'util-linux', 'blkid': 'util-linux',
    'losetup': 'util-linux', 'mount': 'mount', 'umount': 'mount',
    'mkfs.ext4': 'e2fsprogs', 'e2fsck': 'e2fsprogs',
    'resize2fs': 'e2fsprogs', 'tune2fs': 'e2fsprogs',
    'zstd': 'zstd', 'unmkinitramfs': 'initramfs-tools-core',
    'kexec': 'kexec-tools', 'sshd': 'openssh-server',
    'systemctl': 'systemd', 'ip': 'iproute2',
    'chroot': 'coreutils', 'sync': 'coreutils', 'tar': 'tar',
    'xz': 'xz-utils', 'gzip': 'gzip', 'cpio': 'cpio',
    'dpkg': 'dpkg', 'dpkg-query': 'dpkg', 'dpkg-deb': 'dpkg', 'apt-get': 'apt',
}
RUNTIME_PACKAGES = tuple(dict.fromkeys(('python3', 'python3-cryptography', *TOOL_PACKAGES.values())))


def require_commands():
    missing = [name for name in TOOL_PACKAGES if shutil.which(name, path=SYSTEM_PATH) is None]
    packages = sorted({TOOL_PACKAGES[name] for name in missing})
    require(not missing, 'runtime_dependencies',
            'Missing required OTA tools: ' + ', '.join(missing) +
            '. Install Debian packages: ' + ' '.join(packages),
            missing=missing, packages=packages)
