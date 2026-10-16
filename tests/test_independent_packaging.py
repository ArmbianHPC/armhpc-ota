# SPDX-License-Identifier: GPL-3.0-only
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def put(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')


def fixture(tmp_path, ota_version='1.2.10', framework_version='1.2.1'):
    ota = tmp_path / 'armhpc-ota'
    frame = tmp_path / 'armbian-hpc'
    for root, number in ((ota, ota_version), (frame, framework_version)):
        put(root, 'VERSION', number)
    put(ota, 'src/armhpc_ota/__init__.py', '__version__ = ' + repr(ota_version))
    put(ota, 'tools/compatibility.py', (ROOT / 'tools/compatibility.py').read_text())
    put(ota, 'COMPATIBILITY.json', (ROOT / 'COMPATIBILITY.json').read_text())
    for name in ('GPL-2.0-only', 'GPL-3.0-only'):
        put(frame, 'LICENSES/' + name + '.txt', 'license fixture')
    for name in ('clock_floor.py', 'cli.py', 'watchdog.py'):
        put(frame, 'components/common/rootfs-overlay/usr/lib/armhpc/' + name, '# fixture')
    services = 'components/common/rootfs-overlay/etc/systemd/system/'
    for name in ('armhpc-clock-floor.service', 'armhpc-clock-checkpoint.service',
                 'armhpc-clock-checkpoint.timer', 'armhpc-clock-shutdown.service',
                 'armhpc-firstboot.service.d/20-armhpc-clock.conf'):
        put(frame, services + name, '# fixture')
    return ota, frame


def test_runtime_records_distinct_versions_and_legacy_framework(tmp_path, monkeypatch):
    packager = load('package-runtime')
    ota, frame = fixture(tmp_path)
    helpers = tmp_path / 'helpers'
    for architecture in ('arm64', 'armhf'):
        put(helpers, 'watchdog-guard-' + architecture, 'unsigned helper fixture')
    monkeypatch.setattr(packager, 'provenance', lambda repo: ('a' if Path(repo) == ota else 'b') * 40)
    output = tmp_path / 'output'
    result = packager.build(ota, output, helpers=helpers, framework=frame)
    expected = {'armhpc-ota': '1.2.10', 'armbian-hpc': '1.2.1'}
    assert result['version'] == '1.2.10'
    assert result['source_versions'] == expected
    with tarfile.open(output / 'armhpc-ota-1.2.10-linux-runtime.tar.xz') as archive:
        inventory = json.load(archive.extractfile('armhpc-ota-1.2.10/compat/framework-files.json'))
        assert inventory['framework_version'] == '1.2.1'
        assert inventory['compatibility']['source_versions'] == expected
        assert inventory['compatibility']['minimum_agent'] == '1.2.1'
    with tarfile.open(output / 'armhpc-ota-1.2.10-source.tar.xz') as archive:
        assert 'armhpc-ota-1.2.10/COMPATIBILITY.json' in archive.getnames()


def test_incompatible_sources_fail_before_output_creation(tmp_path):
    packager = load('package-runtime')
    ota, frame = fixture(tmp_path, framework_version='1.2.0')
    output = tmp_path / 'output'
    with pytest.raises(ValueError, match='requires armbian-hpc >= 1.2.1'):
        packager.build(ota, output, framework=frame)
    assert not output.exists()


def test_software_release_names_framework_archive_with_its_own_version(tmp_path, monkeypatch):
    builder = load('build-release')
    ota, frame = fixture(tmp_path)
    for name in ('README.md', 'README.zh-CN.md', 'CHANGELOG.md', 'docs/fixture.md'):
        put(ota, name, '# fixture')
    put(ota, 'DEPENDENCIES.lock.json', json.dumps({'sdk': 'fixture-sdk', 'dotnet_runtime': 'fixture-runtime'}))
    for root in (ota, frame):
        subprocess.run(['git', 'init', '-q', str(root)], check=True)
        subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'fixture source'], check=True)
    monkeypatch.setattr(builder, '__file__', str(ota / 'tools/build-release.py'))
    real_output = builder.subprocess.check_output
    real_run = builder.subprocess.run
    real_load = builder.load

    def check_output(command, **kwargs):
        if command[0] == 'dotnet':
            return 'fixture-sdk'
        if Path(command[0]).name == 'ARMHPC-OTA-CLI.exe':
            return '1.2.10'
        return real_output(command, **kwargs)

    def run(command, **kwargs):
        if command[0] in ('dotnet', builder.sys.executable):
            return SimpleNamespace(returncode=0)
        return real_run(command, **kwargs)

    def runtime(project, output, helpers, framework):
        put(output, 'armhpc-ota-1.2.10-linux-runtime.tar.xz', 'runtime fixture')
        put(output, 'armhpc-ota-1.2.10-source.tar.xz', 'source fixture')

    def portable(path, cache):
        put(path, 'ARMHPC-OTA-CLI.exe', 'controller fixture')
        put(path, 'DEPENDENCIES.json', '{}')

    def licenses(repo, path, cache):
        put(path, 'LICENSES/fixture.txt', 'license fixture')

    def modules(path, name):
        if path.name == 'compatibility.py':
            return real_load(path, name)
        if path.name == 'package-runtime.py':
            return SimpleNamespace(build=runtime)
        if path.name == 'build-portable-windows.py':
            return SimpleNamespace(build=portable)
        return SimpleNamespace(collect=licenses)

    def sign(runtime, output, key, key_id):
        put(output, 'bundle.tar.xz', 'signed fixture')
        return {'bundle': output / 'bundle.tar.xz'}

    monkeypatch.setattr(builder.subprocess, 'check_output', check_output)
    monkeypatch.setattr(builder.subprocess, 'run', run)
    monkeypatch.setattr(builder, 'load', modules)
    monkeypatch.setattr('armhpc_ota.lan_publish.tools_bundle', sign)
    args = SimpleNamespace(framework_source=frame, work=tmp_path/'work', output=tmp_path/'output',
                           helpers=tmp_path/'helpers', cache=tmp_path/'cache', signing_key=tmp_path/'key', key_id='fixture')
    result = builder.build(args)
    assert result['source_versions'] == {'armhpc-ota': '1.2.10', 'armbian-hpc': '1.2.1'}
    source = args.work / 'windows/source/armbian-hpc-1.2.1-source.tar.xz'
    with tarfile.open(source) as archive:
        assert archive.extractfile('armbian-hpc-1.2.1/VERSION').read() == b'1.2.1'
        assert all(member.name.startswith('armbian-hpc-1.2.1') for member in archive)
    info = json.loads((args.work / 'windows/BUILD-INFO.json').read_text())
    assert info['source_versions'] == result['source_versions']
    assert info['source_commits']['armbian-hpc'] == real_output(['git','-C',str(frame),'rev-parse','HEAD'], text=True).strip()
