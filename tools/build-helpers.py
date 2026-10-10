# SPDX-License-Identifier: GPL-3.0-only
"""Build both target-architecture helpers without opening any watchdog."""
import argparse
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--output', required=True)
args = parser.parse_args()
output = Path(args.output).resolve()
if any((path / '.git').exists() for path in (output, *output.parents)):
    parser.error('Generated binaries belong outside the source repository')
output.mkdir(parents=True, exist_ok=True)
source = Path(__file__).resolve().parents[1] / 'boot/watchdog-guard.c'
lock=json.loads((source.parents[1]/'DEPENDENCIES.lock.json').read_text())
for architecture, compiler in [('arm64', 'aarch64-linux-gnu-gcc'), ('armhf', 'arm-linux-gnueabihf-gcc')]:
    version=subprocess.check_output([compiler,'-dumpfullversion'],text=True).strip()
    if version!=lock['native_compilers'][compiler]:raise RuntimeError('Compiler version differs from dependency lock')
    destination = output / ('watchdog-guard-' + architecture)
    subprocess.run([compiler, '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(destination)], check=True)
    subprocess.run(['file', str(destination)], check=True)
    symbols = subprocess.check_output(['readelf', '--version-info', str(destination)], text=True)
    import re
    versions = [tuple(map(int, version.split('.'))) for version in re.findall(r'GLIBC_(\d+\.\d+)', symbols)]
    if versions and max(versions) > (2, 36): raise RuntimeError('Helper exceeds Bookworm glibc 2.36 ABI')
