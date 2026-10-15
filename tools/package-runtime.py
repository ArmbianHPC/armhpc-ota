# SPDX-License-Identifier: GPL-3.0-only
"""Package committed source, architecture helpers and signed-maintenance resources."""
import argparse,ast,hashlib,json,os,subprocess,tarfile,zipfile
from pathlib import Path

def version(project):
    tree=ast.parse((project/'src/armhpc_ota/__init__.py').read_text(encoding='utf-8'))
    return next(n.value.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='__version__' for t in n.targets))

def source_files(project):
    selected=('src','boot','packaging','tools','docs','tests','windows','LICENSES','.github',
              'README.md','README.zh-CN.md','LICENSE','COPYRIGHT','VERSION','THIRD-PARTY-NOTICES.md','pyproject.toml',
              'MANIFEST.in','requirements-test.txt','LICENSE-MAP.json','REUSE.toml','global.json','DEPENDENCIES.lock.json','.gitignore','.gitattributes','CHANGELOG.md')
    for name in selected:
        base=project/name
        for path in sorted(base.rglob('*')) if base.is_dir() else [base]:
            relative=path.relative_to(project)
            if any(s in relative.parts for s in ('bin','obj','__pycache__','.git','.vs')):continue
            if any(x.endswith('.egg-info') for x in relative.parts):continue
            if not path.is_file() or path.is_symlink():continue
            if path.suffix.lower() in ('.pem','.key','.pfx','.p12','.img','.pyc','.bin','.elf','.itb','.dll','.exe','.xz','.zst'):
                raise ValueError('Generated/private file in source: '+str(relative))
            yield path,relative

def digest(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def framework_files(framework):
    frame=Path(framework);rows=[]
    scopes={'common':frame/'components/common/rootfs-overlay/usr/lib/armhpc',
            'normal':frame/'components/k3s/rootfs-overlay/usr/lib/armhpc',
            'rescue':frame/'components/rescue/rootfs-overlay/usr/lib/armhpc'}
    for scope,directory in scopes.items():
        for path in sorted(directory.glob('*.py')):
            rows.append((path,{'scope':scope,'target':'usr/lib/armhpc/'+path.name,
                        'source':'compat/framework/'+scope+'/'+path.name,'sha256':digest(path)}))
    for board in ('wxy-oect-original','wxy-oesp-v22'):
        board_overlay=frame/'adapters/boards'/board/'rootfs-overlay'
        if not board_overlay.is_dir():continue
        candidates=list((board_overlay/'usr/lib/armhpc').glob('*.py'))
        for name in ('led.json','phy-led.json','fan.json','usb-console.json','network-ports.json','initramfs-firmware'):
            resource=board_overlay/'etc/armhpc'/name
            if resource.is_file():candidates.append(resource)
        for path in sorted(candidates):
            target=path.relative_to(board_overlay).as_posix()
            rows.append((path,{'scope':'board','board':board,'target':target,
                              'source':'compat/framework/boards/'+board+'/'+target,'sha256':digest(path)}))
        if board=='wxy-oesp-v22':
            policy=json.loads((frame/'adapters/boards'/(board+'.json')).read_text())
            for firmware in policy.get('firmware',[]):
                path=frame/firmware['path']
                if not path.is_file() or digest(path)!=firmware['sha256'] or not firmware.get('redistributable') or not firmware.get('reviewed'):
                    raise ValueError('Missing or unaudited board firmware: '+firmware['id'])
                target=firmware['destination'].lstrip('/').replace('lib/firmware/','usr/lib/firmware/',1)
                rows.append((path,{'scope':'board','board':board,'target':target,
                                  'source':'compat/framework/boards/'+board+'/'+target,'sha256':digest(path)}))
                path=frame/firmware['license_file'];target='usr/share/doc/armhpc-firmware/'+path.name
                rows.append((path,{'scope':'board','board':board,'target':target,
                                  'source':'compat/framework/boards/'+board+'/'+target,'sha256':digest(path)}))
    for name in ('GPL-2.0-only','GPL-3.0-only'):
        path=frame/'LICENSES'/(name+'.txt')
        rows.append((path,{'scope':'common','target':'usr/share/doc/armhpc-framework/'+name+'.txt',
                    'source':'compat/framework/licenses/'+name+'.txt','sha256':digest(path)}))
    completion_targets = (
        'usr/lib/armhpc/completion.bash',
        'etc/profile.d/armhpc-completion.sh',
        'usr/share/bash-completion/completions/armhpc',
        'usr/share/bash-completion/completions/armhpc-rescue',
        'usr/share/bash-completion/completions/armhpc-kube',
    )
    overlay=frame/'components/common/rootfs-overlay'
    path=frame/'profiles/kernel/kubernetes.json'
    if path.is_file():
        rows.append((path,{'scope':'common','target':'usr/lib/armhpc/kernel-baseline.json',
                          'source':'compat/framework/data/kernel-baseline.json','sha256':digest(path)}))
    for name in ('armhpc-fan.service','armhpc-performance.service','armhpc-performance.timer',
                 'armhpc-state.service','armhpc-runtime.service','armhpc-swap.service','armhpc-auth-recovery.service',
                 'armhpc-management-ready.service','armhpc-health.service','armhpc-health.timer','armhpc-firewall.service'):
        service=overlay/'etc/systemd/system'/name
        if service.is_file():
            rows.append((service,{'scope':'common','target':'etc/systemd/system/'+name,
                                 'source':'compat/framework/services/'+name,'sha256':digest(service)}))
    path=overlay/'etc/tmpfiles.d/armhpc-runtime.conf'
    if path.is_file():
        rows.append((path,{'scope':'common','target':'etc/tmpfiles.d/armhpc-runtime.conf',
                          'source':'compat/framework/services/armhpc-runtime.conf','sha256':digest(path)}))
    path=overlay/'etc/systemd/journald.conf.d/40-armhpc.conf'
    if path.is_file():
        rows.append((path,{'scope':'common','target':'etc/systemd/journald.conf.d/40-armhpc.conf',
                          'source':'compat/framework/services/40-armhpc.conf','sha256':digest(path)}))
    if any((overlay/name).exists() for name in completion_targets):
        for name in completion_targets:
            path=overlay/name
            if not path.is_file() or path.is_symlink():raise ValueError('Missing or unsafe completion resource: '+name)
            rows.append((path,{'scope':'common','target':name,
                              'source':'compat/framework/completion/'+name,'sha256':digest(path)}))
    return rows

def provenance(project):
    return subprocess.check_output(['git','-C',str(project),'rev-parse','HEAD'],text=True).strip()

def add(archive,path,name,epoch):
    info=archive.gettarinfo(str(path),arcname=name);info.uid=info.gid=0;info.uname=info.gname='';info.mtime=epoch
    info.mode=0o755 if path.suffix in ('.sh','.ps1') or path.name.startswith('watchdog-guard-') else 0o644
    with path.open('rb') as stream:archive.addfile(info,stream)

def build(project,output,helpers=None,windows=None,framework=None):
    project=Path(project).resolve(strict=True);output=Path(output).resolve()
    if output.is_relative_to(project) or any((p/'.git').exists() for p in (output,*output.parents)):
        raise ValueError('Archives belong outside source repositories')
    number=version(project);output.mkdir(parents=True,exist_ok=True)
    epoch=int(os.environ.get('SOURCE_DATE_EPOCH','0'));files=list(source_files(project));created=[]
    refs={'armhpc-ota':provenance(project)}
    if framework:refs['armbian-hpc']=provenance(framework)
    shared=framework_files(framework) if framework else []
    source=output/('armhpc-ota-'+number+'-source.tar.xz')
    if source.exists():raise ValueError('Release asset already exists: '+str(source))
    with tarfile.open(source,'w:xz',preset=6) as archive:
        for path,relative in files:add(archive,path,'armhpc-ota-'+number+'/'+relative.as_posix(),epoch)
        if framework:
            for path,item in shared:
                if not path.relative_to(Path(framework)).parts[0]=='cache':
                    relative=path.relative_to(Path(framework));add(archive,path,'armhpc-ota-'+number+'/corresponding-framework/'+relative.as_posix(),epoch)
    created.append(source)
    if helpers:
        if not framework:raise ValueError('Supply matching --framework-source')
        helper_paths=[Path(helpers)/('watchdog-guard-'+a) for a in ('arm64','armhf')]
        if not all(p.is_file() for p in helper_paths):raise ValueError('Build both architecture helpers')
        runtime=output/('armhpc-ota-'+number+'-linux-runtime.tar.xz')
        if runtime.exists():raise ValueError('Release asset already exists: '+str(runtime))
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(dir=output) as temp:
            inventory=Path(temp)/'framework-files.json'
            inventory.write_text(json.dumps({'protocol':1,'framework_version':Path(framework,'VERSION').read_text().strip(),
                                             'source_commit':refs['armbian-hpc'],'files':[i for p,i in shared]},indent=2)+'\n')
            with tarfile.open(runtime,'w:xz',preset=6) as archive:
                prefix='armhpc-ota-'+number+'/'
                for path,relative in files:
                    if relative.parts[0] not in ('windows','tests'):add(archive,path,prefix+relative.as_posix(),epoch)
                for path,item in shared:add(archive,path,prefix+item['source'],epoch)
                add(archive,inventory,prefix+'compat/framework-files.json',epoch)
                add(archive,Path(framework)/'components/common/rootfs-overlay/usr/lib/armhpc/clock_floor.py',prefix+'compat/clock_floor.py',epoch)
                services=Path(framework)/'components/common/rootfs-overlay/etc/systemd/system'
                for name in ('armhpc-clock-floor.service','armhpc-clock-checkpoint.service','armhpc-clock-checkpoint.timer','armhpc-clock-shutdown.service'):
                    add(archive,services/name,prefix+'compat/clock-services/'+name,epoch)
                add(archive,services/'armhpc-firstboot.service.d/20-armhpc-clock.conf',prefix+'compat/clock-services/firstboot-clock.conf',epoch)
                for name in ('cli.py','watchdog.py'):
                    add(archive,Path(framework)/'components/common/rootfs-overlay/usr/lib/armhpc'/name,prefix+'compat/public-cli/'+name,epoch)
                for path in helper_paths:add(archive,path,prefix+'helpers/'+path.name,epoch)
        created.append(runtime)
    if windows:
        windows=Path(windows).resolve(strict=True);binary=output/('armhpc-ota-'+number+'-windows-win-x64.zip')
        if binary.exists():raise ValueError('Release asset already exists: '+str(binary))
        if not (windows/'ARMHPC-OTA.exe').is_file():raise ValueError('Publish Windows app first')
        with zipfile.ZipFile(binary,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
            for path in sorted(windows.rglob('*')):
                if path.is_file() and not path.is_symlink() and '__pycache__' not in path.parts:
                    z.write(path,'ARMHPC-OTA/'+path.relative_to(windows).as_posix())
        created.append(binary)
    report={'version':number,'source_commits':refs,'protocol':1,'system_img_included':False,
            'files':[{'file':p.name,'bytes':p.stat().st_size,'sha256':digest(p)} for p in created]}
    (output/'SHA256SUMS').write_text(''.join(x['sha256']+'  '+x['file']+'\n' for x in report['files']))
    (output/'tool-release.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--project',type=Path,default=Path(__file__).resolve().parents[1]);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--helpers',type=Path);p.add_argument('--windows',type=Path);p.add_argument('--framework-source',type=Path);a=p.parse_args()
    print(json.dumps(build(a.project,a.output,a.helpers,a.windows,a.framework_source),indent=2))
