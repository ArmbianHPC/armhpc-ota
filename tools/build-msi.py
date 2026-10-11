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
UI_NS = 'http://wixtoolset.org/schemas/v4/wxs/ui'
ET.register_namespace('ui', UI_NS)
UPGRADE = '93f09792-ec62-50b2-a42b-b8a131973b18'


def node(parent, name, **attributes):
    return ET.SubElement(parent, '{' + NS + '}' + name, {k: str(v) for k, v in attributes.items()})



def rtf_license(text):
    parts=[]
    for char in text:
        code=ord(char)
        if char in ('\\','{','}'):parts.append('\\'+char)
        elif char=='\n':parts.append('\\par\n')
        elif code>127:parts.append('\\u'+str(code if code<32768 else code-65536)+'?')
        else:parts.append(char)
    return '{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Segoe UI;}}\\f0\\fs18 '+''.join(parts)+'}'


def add_install_ui(package, payload, work):
    license_path=work/'license.rtf'
    license_path.write_text(rtf_license((payload/'LICENSE-ARMHPC.txt').read_text(encoding='utf-8')),encoding='ascii')
    node(package,'WixVariable',Id='WixUILicenseRtf',Value=license_path)
    ET.SubElement(package,'{'+UI_NS+'}WixUI',{'Id':'WixUI_InstallDir','InstallDirectory':'INSTALLFOLDER'})
    node(package,'Property',Id='INSTALLUI_OPTIONS_CHOSEN',Secure='yes')
    for option, previous, key, normalised in (
            ('INSTALLDESKTOPSHORTCUT','PREVIOUS_DESKTOP_OPTION','DesktopOption','DESKTOP_SELECTED'),
            ('ADDCLIPATH','PREVIOUS_CLI_OPTION','CliPathOption','CLI_PATH_SELECTED')):
        node(package,'Property',Id=option,Secure='yes')
        saved=node(package,'Property',Id=previous)
        node(saved,'RegistrySearch',Id='Search'+previous,Root='HKCU',
             Key='Software\\ARMHPC\\OTA\\Installer',Name=key,Type='raw')
        node(package,'SetProperty',Id=option,Action='Restore'+option,Value='['+previous+']',
             Before='CostFinalize',Sequence='both',
             Condition='NOT '+option+' AND '+previous+' AND NOT INSTALLUI_OPTIONS_CHOSEN')
        node(package,'SetProperty',Id=option,Action='Default'+option,Value='1',
             Before='CostFinalize',Sequence='both',
             Condition='NOT '+option+' AND NOT '+previous+' AND NOT INSTALLUI_OPTIONS_CHOSEN')
        node(package,'SetProperty',Id=option,Action='ClearUi'+option,Value='{}',
             Before='CostFinalize',Sequence='ui',Condition=option+' = "0"')
        node(package,'SetProperty',Id=normalised,Action='NormaliseOff'+option,Value='0',
             Before='InstallInitialize',Sequence='execute',Condition=option+' <> "1"')
        node(package,'SetProperty',Id=normalised,Action='NormaliseOn'+option,Value='1',
             Before='InstallInitialize',Sequence='execute',Condition=option+' = "1"')
    ui=node(package,'UI')
    dialog=node(ui,'Dialog',Id='ArmHpcOptionsDlg',Width='370',Height='270',Title='[ProductName] Setup')
    node(dialog,'Control',Id='BannerBitmap',Type='Bitmap',X='0',Y='0',Width='370',Height='44',TabSkip='no',Text='WixUI_Bmp_Banner')
    node(dialog,'Control',Id='Title',Type='Text',X='15',Y='6',Width='300',Height='15',Transparent='yes',NoPrefix='yes',Text='{\\WixUI_Font_Title}Installation options')
    node(dialog,'Control',Id='Description',Type='Text',X='25',Y='23',Width='320',Height='15',Transparent='yes',NoPrefix='yes',Text='Choose shortcuts and command-line access.')
    node(dialog,'Control',Id='BannerLine',Type='Line',X='0',Y='44',Width='370',Height='0')
    node(dialog,'Control',Id='Desktop',Type='CheckBox',X='25',Y='70',Width='310',Height='18',Property='INSTALLDESKTOPSHORTCUT',CheckBoxValue='1',Text='Create an ARMHPC OTA desktop shortcut')
    node(dialog,'Control',Id='CliPath',Type='CheckBox',X='25',Y='104',Width='310',Height='18',Property='ADDCLIPATH',CheckBoxValue='1',Text='Add command-line tools to my PATH')
    node(dialog,'Control',Id='Scope',Type='Text',X='25',Y='144',Width='310',Height='44',NoPrefix='yes',Text='ARMHPC OTA is installed for the current Windows user. Device and login settings are kept when the application is uninstalled.')
    node(dialog,'Control',Id='BottomLine',Type='Line',X='0',Y='234',Width='370',Height='0')
    back=node(dialog,'Control',Id='Back',Type='PushButton',X='180',Y='243',Width='56',Height='17',Text='< Back')
    node(back,'Publish',Event='NewDialog',Value='InstallDirDlg')
    nxt=node(dialog,'Control',Id='Next',Type='PushButton',X='236',Y='243',Width='56',Height='17',Default='yes',Text='Next >')
    node(nxt,'Publish',Property='INSTALLUI_OPTIONS_CHOSEN',Value='1',Order='1')
    node(nxt,'Publish',Event='NewDialog',Value='VerifyReadyDlg',Order='2')
    cancel=node(dialog,'Control',Id='Cancel',Type='PushButton',X='304',Y='243',Width='56',Height='17',Cancel='yes',Text='Cancel')
    node(cancel,'Publish',Event='SpawnDialog',Value='CancelDlg')
    node(ui,'Publish',Dialog='InstallDirDlg',Control='Next',Event='NewDialog',Value='ArmHpcOptionsDlg',Order='100',
         Condition='WIXUI_DONTVALIDATEPATH OR WIXUI_INSTALLDIR_VALID="1"')
    node(ui,'Publish',Dialog='VerifyReadyDlg',Control='Back',Event='NewDialog',Value='ArmHpcOptionsDlg',Order='100',Condition='NOT Installed')


def build(payload, output, work, wix, version, ui_extension):
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
    ui_extension = Path(ui_extension).resolve(strict=True)
    if '4.0.6' not in ui_extension.parts:
        raise ValueError('Use pinned WixToolset.UI.wixext 4.0.6')
    work.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    root = ET.Element('{' + NS + '}Wix')
    package = node(root, 'Package', Name='ARMHPC OTA', Manufacturer='ARMHPC', Version=version,
                   Language='1033', UpgradeCode=UPGRADE, Scope='perUser')
    node(package, 'MajorUpgrade', DowngradeErrorMessage='A newer ARMHPC OTA is already installed.',
         AllowSameVersionUpgrades='yes', Schedule='afterInstallInitialize')
    node(package, 'MediaTemplate', EmbedCab='yes', CompressionLevel='high')
    node(package, 'Property', Id='ARPCOMMENTS', Value='ARMHPC OTA GUI, CLI and signed maintenance')
    node(package, 'Property', Id='ARPURLINFOABOUT', Value='https://github.com/ArmbianHPC/armhpc-ota')
    node(package, 'Property', Id='INSTALLFOLDER', Secure='yes')
    previous = node(package, 'Property', Id='PREVIOUSINSTALLFOLDER')
    node(previous, 'RegistrySearch', Id='PreviousInstallDirectory', Root='HKCU',
         Key='Software\\ARMHPC\\OTA\\Installer', Name='InstallDirectory', Type='raw')
    node(package, 'SetProperty', Id='INSTALLFOLDER', Value='[PREVIOUSINSTALLFOLDER]',
         Before='CostFinalize', Sequence='both',
         Condition='PREVIOUSINSTALLFOLDER AND NOT INSTALLFOLDER')
    add_install_ui(package, payload, work)

    local = node(package, 'StandardDirectory', Id='LocalAppDataFolder')
    programs = node(local, 'Directory', Id='LocalPrograms', Name='Programs')
    manufacturer = node(programs, 'Directory', Id='ArmHpcPrograms', Name='ARMHPC')
    install = node(manufacturer, 'Directory', Id='INSTALLFOLDER', Name='OTA')
    directories = {'': install}
    feature = node(package, 'Feature', Id='Application', Title='ARMHPC OTA', Level='1')
    saved = node(install, 'Component', Id='InstallDirectoryRecord', Guid=str(uuid.uuid5(uuid.UUID(UPGRADE), 'install-directory')))
    node(saved, 'RegistryValue', Root='HKCU', Key='Software\\ARMHPC\\OTA\\Installer',
         Name='InstallDirectory', Type='string', Value='[INSTALLFOLDER]', KeyPath='yes')
    node(feature, 'ComponentRef', Id='InstallDirectoryRecord')
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

    node(feature, 'ComponentRef', Id='Shortcuts')
    desktop = node(package, 'StandardDirectory', Id='DesktopFolder')
    shortcut = node(desktop, 'Component', Id='DesktopShortcut',
                    Guid=str(uuid.uuid5(uuid.UUID(UPGRADE), 'desktop-shortcut')),
                    Condition='INSTALLDESKTOPSHORTCUT = "1"', Transitive='yes')
    node(shortcut, 'Shortcut', Id='DesktopGui', Name='ARMHPC OTA',
         Target='[INSTALLFOLDER]ARMHPC-OTA.exe', WorkingDirectory='INSTALLFOLDER')
    node(shortcut, 'RegistryValue', Root='HKCU', Key='Software\\ARMHPC\\OTA\\Installer',
         Name='desktop-shortcut', Type='integer', Value='1', KeyPath='yes')
    node(feature, 'ComponentRef', Id='DesktopShortcut')
    cli_path = node(install, 'Component', Id='CliPathRegistration',
                    Guid=str(uuid.uuid5(uuid.UUID(UPGRADE), 'cli-user-path')),
                    Condition='ADDCLIPATH = "1"', Transitive='yes')
    node(cli_path, 'Environment', Id='CliPath', Name='PATH', Value='[INSTALLFOLDER]',
         Part='last', Action='set', System='no', Permanent='no')
    node(cli_path, 'RegistryValue', Root='HKCU', Key='Software\\ARMHPC\\OTA\\Installer',
         Name='cli-path', Type='integer', Value='1', KeyPath='yes')
    node(feature, 'ComponentRef', Id='CliPathRegistration')
    options = node(install, 'Component', Id='InstallationOptions',
                   Guid=str(uuid.uuid5(uuid.UUID(UPGRADE), 'installation-options')))
    for key, value in (('DesktopOption', '[DESKTOP_SELECTED]'), ('CliPathOption', '[CLI_PATH_SELECTED]')):
        node(options, 'RegistryValue', Root='HKCU', Key='Software\\ARMHPC\\OTA\\Installer',
             Name=key, Type='string', Value=value, KeyPath='yes' if key=='DesktopOption' else 'no')
    node(feature, 'ComponentRef', Id='InstallationOptions')

    source = work / 'ARMHPC-OTA.wxs'
    ET.indent(root)
    source.write_bytes(b'<?xml version="1.0" encoding="utf-8"?>\n<!-- SPDX-License-Identifier: GPL-3.0-only -->\n' + ET.tostring(root, encoding='utf-8'))
    subprocess.run([str(wix), 'build', str(source), '-ext', str(ui_extension), '-culture', 'en-us', '-arch', 'x64', '-o', str(output)], check=True)
    report = {'version': version, 'wix': actual, 'per_user': True, 'user_configuration_included': False,
              'wizard': True, 'custom_install_directory': True, 'optional_desktop_shortcut': True,
              'optional_cli_path': True, 'installer_revision': 1, 'file_count': len(files), 'files': files, 'msi_sha256': hashlib.sha256(output.read_bytes()).hexdigest()}
    (work / 'msi-files.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('payload', 'output', 'work', 'wix', 'ui-extension'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    report = build(args.payload, args.output, args.work, args.wix, args.version, args.ui_extension)
    print(json.dumps({k: v for k, v in report.items() if k != 'files'}, indent=2))
