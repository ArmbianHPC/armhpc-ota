# SPDX-License-Identifier: GPL-3.0-only
"""Build the software release from committed OTA and framework checkouts."""
import argparse
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def commit(repo):
    if subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip():
        raise ValueError('Build from a clean committed checkout: ' + str(repo))
    return subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build(args):
    repo = Path(__file__).resolve().parents[1]
    frame = args.framework_source.resolve(strict=True)
    refs = {'armhpc-ota': commit(repo), 'armbian-hpc': commit(frame)}
    version = (repo / 'VERSION').read_text(encoding='utf-8').strip()
    compatibility = load(repo / 'tools/compatibility.py', 'release_compatibility').check_sources(repo, frame)
    import ast
    tree=ast.parse((repo/'src/armhpc_ota/__init__.py').read_text(encoding='utf-8'))
    revision=next((n.value.value for n in tree.body if isinstance(n,ast.Assign) and
                  any(isinstance(t,ast.Name) and t.id=='__revision__' for t in n.targets) and isinstance(n.value,ast.Constant)),None)
    display_version=version+('-'+revision if revision else '')
    source_versions = compatibility['source_versions']
    framework_version = source_versions['armbian-hpc']
    work, output = args.work.resolve(), args.output.resolve()
    for p in (work, output):
        if any((q / '.git').exists() for q in (p, *p.parents)):
            raise ValueError('Generated outputs must be outside repositories')
    if work.exists() or output.exists():
        raise ValueError('Choose new empty work and release directories')
    lock = json.loads((repo / 'DEPENDENCIES.lock.json').read_text(encoding='utf-8'))
    sdk = subprocess.check_output(['dotnet', '--version'], cwd=repo, text=True).strip()
    if sdk != lock['sdk']:
        raise ValueError('Build SDK differs from the dependency lock')
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    if 'SOURCE_DATE_EPOCH' not in os.environ:
        os.environ['SOURCE_DATE_EPOCH'] = subprocess.check_output(['git', '-C', str(repo), 'show', '-s', '--format=%ct', 'HEAD'], text=True).strip()
    subprocess.run([sys.executable, str(frame / 'tools/build/prepare-firmware-inputs.py'),
                    '--project', str(frame)], check=True)
    packager = load(repo / 'tools/package-runtime.py', 'runtime_packager')
    runtime_report = packager.build(repo, output, args.helpers, framework=frame)
    portable = work / 'windows'
    cache = args.cache.resolve()
    load(repo / 'tools/build-portable-windows.py', 'portable_builder').build(portable, cache)
    for name, dest in [('ArmHpc.Ota.Windows', portable), ('ArmHpc.Ota.Cli', portable), ('ArmHpc.Ota.Server', portable / 'server')]:
        project = repo / 'windows' / name / (name + '.csproj')
        with (work / (name + '-publish.txt')).open('w', encoding='utf-8') as log:
            for command in [['dotnet', 'restore', str(project), '--locked-mode'],
                            ['dotnet', 'publish', str(project), '-c', 'Release', '-f', 'net10.0-windows', '-r', 'win-x64', '--self-contained', 'true',
                             '--no-restore', '-o', str(dest)]]:
                subprocess.run(command, cwd=repo, stdout=log, stderr=subprocess.STDOUT, check=True)
        print('Published ' + name, flush=True)
    installed = subprocess.check_output([str(portable / 'ARMHPC-OTA-CLI.exe'), '--version'], text=True).strip()
    if installed != display_version:
        raise ValueError('Portable CLI version differs: ' + installed)
    load(repo / 'tools/collect-licenses.py', 'license_collector').collect(repo, portable, cache)
    sys.path.insert(0, str(repo / 'src'))
    from armhpc_ota.lan_publish import tools_bundle
    runtime = output / ('armhpc-ota-' + version + '-linux-runtime.tar.xz')
    signed = tools_bundle(runtime, work / 'signed', args.signing_key, args.key_id)
    maintenance = output / ('armhpc-ota-' + version + '-maintenance.tar.xz')
    shutil.copyfile(signed['bundle'], maintenance)
    (portable / 'maintenance').mkdir()
    shutil.copyfile(maintenance, portable / 'maintenance/maintenance.tar.xz')
    source_directory = portable / 'source'
    source_directory.mkdir()
    shutil.copy2(output / ('armhpc-ota-' + version + '-source.tar.xz'), source_directory)
    framework_archive = source_directory / ('armbian-hpc-' + framework_version + '-source.tar.xz')
    with (work / 'framework-source.tar').open('xb') as stream:
        subprocess.run(['git', '-C', str(frame), 'archive', '--format=tar',
                        '--prefix=armbian-hpc-' + framework_version + '/', refs['armbian-hpc']],
                       stdout=stream, check=True)
    with (work / 'framework-source.tar').open('rb') as source, lzma.open(framework_archive, 'xb', preset=6) as destination:
        shutil.copyfileobj(source, destination)
    (portable / 'BUILD-INFO.json').write_text(json.dumps({
        'version': version, 'display_version': display_version, 'source_versions': source_versions, 'source_commits': refs,
        'compatibility': compatibility, 'sdk': sdk,
        'dotnet_runtime': lock['dotnet_runtime'],
        'sources': [{'file': p.name, 'sha256': digest(p)} for p in sorted(source_directory.iterdir())]
    }, indent=2) + '\n', encoding='utf-8')
    for name in ('README.md', 'README.zh-CN.md', 'CHANGELOG.md'):
        shutil.copy2(repo / name, portable / name)
    shutil.copytree(repo / 'docs', portable / 'docs')
    binary = output / ('armhpc-ota-' + version + '-windows-win-x64.zip')
    with zipfile.ZipFile(binary, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for path in sorted(portable.rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix not in ('.pdb', '.pyc'):
                z.write(path, 'ARMHPC-OTA/' + path.relative_to(portable).as_posix())
    shutil.copy2(portable / 'DEPENDENCIES.json', output / 'DEPENDENCIES.json')
    shutil.make_archive(str(output / ('armhpc-' + version + '-licenses')), 'zip', portable, 'LICENSES')
    artifacts = [p for p in output.iterdir() if p.is_file() and p.name not in ('SHA256SUMS', 'tool-release.json')]
    report = {'version': version, 'protocol': 1, 'source_versions': source_versions,
              'source_commits': refs, 'compatibility': compatibility, 'sdk': sdk,
              'dotnet_runtime': lock['dotnet_runtime'], 'hardware_verified': False, 'system_image_built': False,
              'files': [{'file': p.name, 'size': p.stat().st_size, 'sha256': digest(p)} for p in sorted(artifacts)]}
    (output / 'tool-release.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (output / 'SHA256SUMS').write_text(''.join(item['sha256'] + '  ' + item['file'] + '\n' for item in report['files']), encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('framework-source', 'work', 'output', 'helpers', 'cache', 'signing-key'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--key-id', required=True)
    print(json.dumps(build(parser.parse_args()), indent=2))
