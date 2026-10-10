# SPDX-License-Identifier: GPL-3.0-only
"""Build a raw anchor initramfs in a prepared ARM Bookworm root; no disk IMG is built."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--root', required=True)
parser.add_argument('--kernel', required=True)
parser.add_argument('--dtb', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--watchdog-binary', required=True, help='Compiled for the target architecture, not the Windows/WSL host')
parser.add_argument('--trust-dir', required=True)
args = parser.parse_args()
root, output = Path(args.root).resolve(), Path(args.output).resolve()
if root == Path('/') or not (root / 'lib/modules' / args.kernel).is_dir():
    parser.error('Use an offline ARM root with the requested kernel modules')
source = Path(__file__).resolve().parent.parent
output.mkdir(parents=True, exist_ok=True)
subprocess.run([sys.executable, str(source / 'tools/install-runtime.py'), '--root', str(root), '--watchdog-binary', args.watchdog_binary, '--bootstrap-hooks'], check=True)
trust = root / 'etc/armhpc/ota-trust.d'; trust.mkdir(parents=True, exist_ok=True)
public = list(Path(args.trust_dir).glob('*.pub'))
if not public: parser.error('At least one pinned release public key is required')
for key in public:
    if key.resolve() != (trust / key.name).resolve():
        shutil.copy2(key, trust / key.name)
# Bind both kernel and DTB; equal kernels do not imply equal board descriptions.
identity=root/'etc/armhpc';identity.mkdir(parents=True,exist_ok=True)
for name,path in [('kernel',root/'boot'/('vmlinuz-'+args.kernel)),('dtb',Path(args.dtb))]:
    with path.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
    (identity/('anchor-'+name+'-sha256')).write_text(digest+'\n')
# The fixed anchor selector replaces the legacy root selector in this initramfs only.
legacy = root / 'etc/initramfs-tools/scripts/local-top/armhpc-root-select'
backup = None
if legacy.exists():
    backup = legacy.read_bytes(); legacy.unlink()
try:
    subprocess.run(['chroot', str(root), '/usr/bin/python3.11', '-c', 'import cryptography'], check=True)
    subprocess.run(['chroot', str(root), 'mkinitramfs', '-o', '/tmp/armhpc-anchor-initramfs', args.kernel], check=True)
    shutil.copy2(root / 'tmp/armhpc-anchor-initramfs', output / 'initramfs')
finally:
    if backup is not None: legacy.write_bytes(backup); legacy.chmod(0o755)
    (root / 'tmp/armhpc-anchor-initramfs').unlink(missing_ok=True)
with (output / 'initramfs').open('rb') as stream:
    if stream.read(4) == bytes.fromhex('27051956'): raise RuntimeError('Unexpected legacy uImage header')
shutil.copy2(root / 'boot' / ('vmlinuz-' + args.kernel), output / 'kernel')
shutil.copy2(args.dtb, output / 'dtb')
print('Raw fixed-bootstrap files built at ' + str(output) + '; signing and physical acceptance are still required.')
