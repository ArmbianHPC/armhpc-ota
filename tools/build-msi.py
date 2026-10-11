# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Build a per-user MSI from a verified Windows application tree."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import uuid
import xml.etree.ElementTree as ET

NS = 'http://wixtoolset.org/schemas/v4/wxs'
ET.register_namespace('', NS)
UPGRADE = '93f09792-ec62-50b2-a42b-b8a131973b18'


def node(parent, name, **attributes):
    return ET.SubElement(parent, '{' + NS + '}' + name, {k: str(v) for k, v in attributes.items()})


def build(payload, output, work, wix, version):
    payload = Path(payload).resolve(strict=True)
    output, work = Path(output).resolve(), Path(work).resolve()
    if output.exists():
        raise ValueError('MSI already exists')
    if any((p / '.git').exists() for d in (output.parent, work) for p in (d, *d.parents)):
        raise ValueError('Build outside source repositories')
    if not (payload / 'ARMHPC-OTA.exe').is_file() or not (payload / 'maintenance/maintenance.tar.xz').is_file():
        raise ValueError('Missing GUI or signed maintenance')
    actual = subprocess.check_output([str(wix), '--version'], text=True).strip()
    if not actual.startswith('4.0.6+'):
        raise ValueError('Use pinned WiX 4.0.6')
    work.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    root = ET.Element('{' + NS + '}Wix')
    package = node(root, 'Package', Name='ARMHPC OTA', Manufacturer='ARMHPC', Version=version,
                   Language='1033', UpgradeCode=UPGRADE, Scope='perUser')
    node(package, 'MajorUpgrade', DowngradeErrorMessage='A newer ARMHPC OTA is already installed.')
    node(package, 'MediaTemplate', EmbedCab='yes', CompressionLevel='high')
    node(package, 'Property', Id='ARPCOMMENTS', Value='ARMHPC OTA GUI, CLI and signed maintenance')
    node(package, 'Property', Id='ARPURLINFOABOUT', Value='https://github.com/ArmbianHPC/armhpc-ota')
    local = node(package, 'StandardDirectory', Id='LocalAppDataFolder')
    programs = node(local, 'Directory', Id='LocalPrograms', Name='Programs')
    manufacturer = node(programs, 'Directory', Id='ArmHpcPrograms', Name='ARMHPC')
    install = node(manufacturer, 'Directory', Id='INSTALLFOLDER', Name='OTA')
    directories = {'': install}
    feature = node(package, 'Feature', Id='Application', Title='ARMHPC OTA', Level='1')
    files = []
    for path in sorted(payload.rglob('*')):
        if not path.is_file() or path.suffix in ('.pdb', '.pyc') or '__pycache__' in path.parts:
            continue
        if path.is_symlink():
            raise ValueError('Installer payload contains a symbolic link')
        relative = path.relative_to(payload).as_posix()
        parent = path.parent.relative_to(payload)
        current = ''
        for part in parent.parts:
            previous = current
            current = (current + '/' + part).strip('/')
            if current not in directories:
                identifier = 'D_' + hashlib.sha256(current.encode()).hexdigest()[:24]
                directories[current] = node(directories[previous], 'Directory', Id=identifier, Name=part)
        identity = hashlib.sha256(relative.encode()).hexdigest()[:24]
        component = node(directories[current], 'Component', Id='C_' + identity,
                         Guid=str(uuid.uuid5(uuid.UUID(UPGRADE), relative)))
        node(component, 'File', Id='F_' + identity, Source=str(path), Name=path.name)
        node(component, 'RegistryValue', Root='HKCU', Key='Software\\ARMHPC\\OTA\\Installer',
             Name=identity, Type='integer', Value='1', KeyPath='yes')
        if relative == next((f['path'] for f in files if Path(f['path']).parent.as_posix() == parent.as_posix()), relative):
            node(component, 'RemoveFolder', Id='R_' + identity, On='uninstall')
        node(feature, 'ComponentRef', Id='C_' + identity)
        files.append({'path': relative, 'size': path.stat().st_size,
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    menu = node(package, 'StandardDirectory', Id='ProgramMenuFolder')
    appmenu = node(menu, 'Directory', Id='ArmHpcMenu', Name='ARMHPC OTA')
    component = node(appmenu, 'Component', Id='Shortcuts', Guid=str(uuid.uuid5(uuid.UUID(UPGRADE), 'shortcuts')))
    node(component, 'Shortcut', Id='LaunchGui', Name='ARMHPC OTA', Target='[INSTALLFOLDER]ARMHPC-OTA.exe', WorkingDirectory='INSTALLFOLDER')
    node(component, 'Shortcut', Id='License', Name='ARMHPC OTA License', Target='[INSTALLFOLDER]LICENSE-ARMHPC.txt', WorkingDirectory='INSTALLFOLDER')
    node(component, 'RemoveFolder', Id='RemoveAppMenu', On='uninstall')
    for key, directory in directories.items():
        node(component, 'RemoveFolder', Id='Cleanup_' + hashlib.sha256(key.encode()).hexdigest()[:24],
             Directory=directory.attrib['Id'], On='uninstall')
    node(component, 'RemoveFolder', Id='CleanupArmHpcPrograms', Directory='ArmHpcPrograms', On='uninstall')
    node(component, 'RemoveFolder', Id='CleanupLocalPrograms', Directory='LocalPrograms', On='uninstall')
    node(component, 'RegistryValue', Root='HKCU', Key='Software\\ARMHPC\\OTA\\Installer', Name='shortcuts', Type='integer', Value='1', KeyPath='yes')
    node(component, 'Environment', Id='CliPath', Name='PATH', Value='[INSTALLFOLDER]', Part='last', Action='set', System='no', Permanent='no')
    node(feature, 'ComponentRef', Id='Shortcuts')
    source = work / 'ARMHPC-OTA.wxs'
    ET.indent(root)
    source.write_bytes(b'<?xml version="1.0" encoding="utf-8"?>\n<!-- SPDX-License-Identifier: GPL-3.0-only -->\n' + ET.tostring(root, encoding='utf-8'))
    subprocess.run([str(wix), 'build', str(source), '-arch', 'x64', '-o', str(output)], check=True)
    report = {'version': version, 'wix': actual, 'per_user': True, 'user_configuration_included': False,
              'file_count': len(files), 'files': files, 'msi_sha256': hashlib.sha256(output.read_bytes()).hexdigest()}
    (work / 'msi-files.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('payload', 'output', 'work', 'wix'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    report = build(args.payload, args.output, args.work, args.wix, args.version)
    print(json.dumps({k: v for k, v in report.items() if k != 'files'}, indent=2))
