# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Publish only the three user-facing packages, with a version-only title."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def files(version):
    return [f'armhpc-ota-{version}-windows-x64.msi', f'armhpc-ota-{version}-linux-cli.tar.gz',
            f'armhpc-ota-{version}-maintenance.tar.xz']


def update(repo, tag, directory, apply=False, notes=None):
    version = tag.removeprefix('v')
    if tag != 'v' + version or len(version.split('.')) != 3 or not all(x.isdigit() for x in version.split('.')):
        raise ValueError('Release tag must be vMAJOR.MINOR.PATCH')
    notes = Path(notes) if notes else Path(__file__).resolve().parents[1] / 'docs/releases' / (tag + '.md')
    if not notes.is_file():
        raise ValueError('Provide the English release notes and their Simplified Chinese counterpart')
    paths = [Path(directory).resolve(strict=True) / name for name in files(version)]
    if not all(p.is_file() for p in paths):
        raise ValueError('All three packages must exist before editing the Release')
    release = json.loads(subprocess.check_output(['gh', 'api', f'repos/{repo}/releases/tags/{tag}'], text=True, encoding='utf-8'))
    known = {a['name']: a for a in release['assets']}
    records = [{'file': p.name, 'size': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths]
    obsolete = [a for a in release['assets'] if a['name'] not in files(version)]
    for r in records:
        if r['file'] in known:
            a = known[r['file']]
            if a['size'] != r['size'] or a.get('digest') != 'sha256:' + r['sha256']:
                raise ValueError('An existing versioned package has different bytes; create a new version')
    preview = {'title': tag, 'packages': records, 'remove_assets': [a['name'] for a in obsolete]}
    if not apply:
        return preview
    for path in paths:
        if path.name not in known:
            subprocess.run(['gh', 'release', 'upload', tag, str(path), '--repo', repo], check=True)
    updated = json.loads(subprocess.check_output(['gh', 'api', f'repos/{repo}/releases/tags/{tag}'], text=True, encoding='utf-8'))
    present = {a['name']: a for a in updated['assets']}
    for r in records:
        a = present[r['file']]
        if a['size'] != r['size'] or a['digest'] != 'sha256:' + r['sha256']:
            raise ValueError('Uploaded package hash differs; old assets are retained')
    command = ['gh', 'release', 'edit', tag, '--repo', repo, '--title', tag]
    if notes:
        command += ['--notes-file', str(notes)]
    subprocess.run(command, check=True)
    for asset in obsolete:
        subprocess.run(['gh', 'api', '--method', 'DELETE', f'repos/{repo}/releases/assets/{asset["id"]}'], check=True)
    final = json.loads(subprocess.check_output(['gh', 'api', f'repos/{repo}/releases/tags/{tag}'], text=True, encoding='utf-8'))
    if final['name'] != tag or set(a['name'] for a in final['assets']) != set(files(version)):
        raise ValueError('Final Release does not match the three-package policy')
    return {'url': final['html_url'], 'title': final['name'], 'packages': records, 'assets': len(final['assets'])}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='ArmbianHPC/armhpc-ota')
    parser.add_argument('--tag', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--notes', type=Path)
    args = parser.parse_args()
    print(json.dumps(update(args.repo, args.tag, args.directory, args.apply, args.notes), indent=2))
