# SPDX-License-Identifier: GPL-3.0-only
"""Copy upstream license materials and record the exact portable dependencies."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET
import zipfile


def collect(project, portable, cache):
    project, portable, cache = (Path(p).resolve(strict=True) for p in (project, portable, cache))
    lock = json.loads((project / 'DEPENDENCIES.lock.json').read_text(encoding='utf-8'))
    target = portable / 'LICENSES/third-party'
    target.mkdir(parents=True, exist_ok=True)
    rows = [{'name': 'CPython', 'version': lock['python']['version'], 'license': 'PSF-2.0 AND Python-2.0',
             'source': 'https://github.com/python/cpython/tree/v' + lock['python']['version'],
             'artifact_sha256': lock['python']['sha256'], 'license_file': 'publisher/LICENSE.txt'}]
    for wheel in lock['wheels']:
        directory = target / (wheel['name'] + '-' + wheel['version'])
        directory.mkdir(exist_ok=True)
        with zipfile.ZipFile(cache / wheel['file']) as archive:
            licenses = [name for name in archive.namelist() if '.dist-info/licenses/' in name and not name.endswith('/')]
            if not licenses:
                raise ValueError('Wheel has no license materials: ' + wheel['file'])
            for name in licenses:
                p = directory / name.split('.dist-info/licenses/', 1)[1]
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(archive.read(name))
        rows.append({'name': wheel['name'], 'version': wheel['version'], 'source': wheel['url'],
                     'artifact_sha256': wheel['sha256'], 'license_directory': str(directory.relative_to(portable)).replace('\\', '/')})
    dependencies = {}
    for name in ('ArmHpc.Ota.Windows', 'ArmHpc.Ota.Cli', 'ArmHpc.Ota.Server'):
        packages = json.loads((project / 'windows' / name / 'packages.lock.json').read_text(encoding='utf-8'))
        for framework in packages['dependencies'].values():
            for package, item in framework.items():
                if item['type'] != 'Project':
                    dependencies[(package, item['resolved'])] = item['contentHash']
    for item in lock['runtime_packs']:
        dependencies[(item['name'], item['version'])] = item['contentHash']
    nuget = Path.home() / '.nuget/packages'
    for (name, version), expected in sorted(dependencies.items()):
        p = nuget / name.lower() / version
        package = p / (name.lower() + '.' + version + '.nupkg')
        actual = base64.b64encode(hashlib.sha512(package.read_bytes()).digest()).decode()
        if expected != actual:
            raise ValueError('NuGet content hash differs: ' + str(package))
        ns = {'n': 'http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd'}
        metadata = ET.parse(p / (name.lower() + '.nuspec')).getroot().find('n:metadata', ns)
        license_node = metadata.find('n:license', ns)
        license_value = license_node.text if license_node is not None else 'See bundled upstream notices'
        repo = metadata.find('n:repository', ns)
        directory = target / (name + '-' + version)
        directory.mkdir(exist_ok=True)
        license_files = []
        with zipfile.ZipFile(package) as z:
            for member in z.namelist():
                if member.endswith('/'):
                    continue
                basename = Path(member).name.lower()
                if basename.startswith(('license', 'copying', 'notice', 'third-party-notice')):
                    dest = directory / member
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(z.read(member))
                    license_files.append(dest.relative_to(portable).as_posix())
        if not license_files and license_value == 'MIT':
            copyright_text = metadata.findtext('n:copyright', default='', namespaces=ns)
            dest = directory / 'LICENSE.txt'
            dest.write_text(copyright_text + '\n\n' + (project / 'LICENSES/third-party/MIT.txt').read_text(encoding='utf-8'), encoding='utf-8')
            license_files.append(dest.relative_to(portable).as_posix())
        if not license_files:
            raise ValueError('Dependency license files missing: ' + name)
        native_other_platform = name.startswith('runtime.') and name != 'runtime.native.System.IO.Ports'
        rows.append({'name': name, 'version': version, 'license': license_value,
                     'source': dict(repo.attrib) if repo is not None else 'https://www.nuget.org/packages/' + name + '/' + version,
                     'nuget_sha512': actual, 'license_files': license_files,
                     'scope': 'restore graph; other platform asset excluded' if native_other_platform else 'portable runtime'})
    rows.extend(lock['embedded_components'])
    (portable / 'DEPENDENCIES.json').write_text(json.dumps({'protocol': 1, 'components': rows}, indent=2) + '\n', encoding='utf-8')
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--portable', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(collect(args.project, args.portable, args.cache), indent=2))
