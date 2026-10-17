# SPDX-License-Identifier: GPL-3.0-only
"""Portable publishing of prebuilt payloads; filesystem construction stays in Linux."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
from .errors import require, OTAError
from .io import atomic_bytes, atomic_json, atomic_copy, canonical, read_json, sha256, identifier, inside, writer_lock
from .metadata import sign, validate_manifest
from .publish import index
from .sources import origin


def output_root(output, key):
    output = Path(output).resolve()
    require(not any((p/'.git').exists() for p in (output, *output.parents)), 'publish_repository', 'Release data must stay outside Git')
    require(not Path(key).resolve().is_relative_to(output), 'publish_private_key', 'Signing key cannot be inside the published directory')
    output.mkdir(parents=True, exist_ok=True)
    return output


def catalog(root):
    # Exact allowlist. The server never exposes a directory or private settings.
    files = {}
    for p in (root/'releases').glob('*/manifest.json'):
        document = read_json(p); m = document['payload']
        files[p.relative_to(root).as_posix()] = {'size': p.stat().st_size, 'sha256': sha256(p)}
        for a in m['artifacts']:
            relative = 'blobs/' + a['sha256']
            q = inside(root, relative)
            require(q.is_file() and q.stat().st_size == a['size'] and sha256(q) == a['sha256'], 'publish_artifact', 'Missing or damaged published artifact')
            files[relative] = {'size': a['size'], 'sha256': a['sha256']}
    for p in (root/'tools').glob('*/maintenance.tar.xz'):
        files[p.relative_to(root).as_posix()] = {'size': p.stat().st_size, 'sha256': sha256(p)}
    if (root/'ota-index.json').is_file():
        p=root/'ota-index.json'; files[p.name]={'size':p.stat().st_size, 'sha256':sha256(p)}
    atomic_json(root/'server-catalog.json', {'protocol':1, 'files':files})


def rebuild_index(root, key, key_id, base_url, days=14):
    entries = []
    for p in sorted((root/'releases').glob('*/manifest.json')):
        m = read_json(p)['payload']
        entries.append({**{k:m[k] for k in ('release','sequence','board','architecture','distribution','layout','anchor_abi','minimum_agent')},
                        'url': base_url.rstrip('/') + '/' + p.relative_to(root).as_posix(),
                        'size':p.stat().st_size,'sha256':sha256(p)})
    index(entries, root/'ota-index.json', key, key_id, days)
    catalog(root)


def import_release(spec_path, output, key, key_id, base_url, days=14):
    spec_path=Path(spec_path).resolve(strict=True); spec=read_json(spec_path)
    root=output_root(output,key); origin(base_url)
    from urllib.parse import urlsplit
    base=urlsplit(base_url);require(base.path in ('','/') and not base.query, 'publish_base_url', 'Built-in hosting requires an origin-only base URL')
    m=copy.deepcopy(spec['manifest']); identifier(m['release'])
    private=Path(key).resolve()
    with writer_lock(root/'publish.lock'):
        require(spec.get('validated_staging') is True, 'publish_staging', 'Import a prepared, sanitized framework release descriptor')
        files=spec['files']; require(set(files)=={a['role'] for a in m['artifacts']},'publish_files','Payload list differs from release roles')
        for a in m['artifacts']:
            source=inside(spec_path.parent,files[a['role']])
            require(source.is_file() and source!=private,'publish_source','Invalid payload path')
            digest=sha256(source); size=source.stat().st_size
            require(digest==a['sha256'] and size==a['size'],'publish_hash','Payload differs from prepared descriptor',role=a['role'])
            if a.get('encoding')=='ext4.zstd':
                import zstandard
                h=hashlib.sha256(); expanded=0
                with source.open('rb') as f, zstandard.ZstdDecompressor().stream_reader(f) as reader:
                    for chunk in iter(lambda:reader.read(1024**2),b''):
                        expanded+=len(chunk); require(expanded<=a['expanded_size'],'publish_expanded','Expanded payload is larger than declared'); h.update(chunk)
                require(expanded==a['expanded_size'] and h.hexdigest()==a['expanded_sha256'],'publish_expanded','Expanded filesystem hash differs')
            elif a.get('encoding')=='squashfs':
                from .squashfs import superblock
                require(superblock(source)['bytes_used']<=size,'publish_squashfs','Invalid SquashFS size')
            a['url']=base_url.rstrip('/')+'/blobs/'+digest
            dest=root/'blobs'/digest
            if dest.exists(): require(sha256(dest)==digest,'publish_collision','Existing blob is damaged')
            else: atomic_copy(source,dest,0o644)
        validate_manifest(m)
        raw=sign(m,key,key_id); dest=root/'releases'/m['release']/'manifest.json'
        if dest.exists(): require(dest.read_bytes()==raw,'release_mutation','Published release cannot be overwritten; create a new release ID')
        else: atomic_bytes(dest,raw,0o644)
        rebuild_index(root,key,key_id,base_url,days)
    return {'release':m['release'],'feed':base_url.rstrip('/')+'/ota-index.json','directory':str(root),
            'manifest_sha256':sha256(dest),'artifacts':len(m['artifacts'])}


def inspect_runtime(runtime):
    """Read package metadata without executing input code or extracting it."""
    import ast
    import re
    from pathlib import PurePosixPath
    runtime=Path(runtime).resolve(strict=True)
    require(runtime.stat().st_size <= 256*1024**2, 'tools_archive_size',
            '输入包过大。制作维护包请选择 *-linux-runtime.tar.xz；系统 OTA 包使用版本发布入口。')
    try:
        with tarfile.open(runtime,'r:xz') as archive:
            members=archive.getmembers()
            require(len(members)<=10000 and sum(m.size for m in members)<=256*1024**2,
                    'tools_archive_size', '运行时归档超过文件数量或解包容量限制。')
            names={m.name.removeprefix('./') for m in members}
            require(not {'manifest.json','runtime.tar.xz'}.issubset(names), 'tools_already_signed',
                    '所选文件是 maintenance.tar.xz 维护包封装。请在主窗口使用“自动更新 OTA 工具”或“自动维护并升级”；制作签名包应选择 *-linux-runtime.tar.xz。')
            by_name={}
            for member in members:
                name=member.name.removeprefix('./');path=PurePosixPath(name)
                require(not path.is_absolute() and '..' not in path.parts and '\\' not in name and
                        (member.isfile() or member.isdir()), 'tools_archive_path', '运行时归档包含不安全路径或链接。')
                require(name not in by_name, 'tools_archive_duplicate', '运行时归档包含重复成员。')
                by_name[name]=member
            suffix='/src/armhpc_ota/__init__.py'
            versions=[name for name,m in by_name.items() if name.endswith(suffix) and m.isfile()]
            require(len(versions)==1, 'tools_runtime_format',
                    '没有找到唯一 OTA 运行时版本文件。请选择 *-linux-runtime.tar.xz；源码包、系统包和已封装维护包不能在此制作签名。')
            member=by_name[versions[0]];require(member.size<=64*1024, 'tools_version', '版本文件过大。')
            try:
                tree=ast.parse(archive.extractfile(member).read())
            except (SyntaxError, ValueError) as error:
                raise OTAError('tools_version','运行时版本文件无法解析。') from error
            values=[node.value.value for node in tree.body if isinstance(node,ast.Assign) and
                    any(isinstance(t,ast.Name) and t.id=='__version__' for t in node.targets) and
                    isinstance(node.value,ast.Constant) and isinstance(node.value.value,str)]
            require(len(values)==1 and re.fullmatch(r'\d+\.\d+\.\d+',values[0]),
                    'tools_version', '运行时缺少有效且唯一的 __version__ 字符串。')
            revisions=[node.value.value for node in tree.body if isinstance(node,ast.Assign) and
                       any(isinstance(t,ast.Name) and t.id=='__revision__' for t in node.targets) and
                       isinstance(node.value,ast.Constant) and isinstance(node.value.value,str)]
            require(len(revisions)<=1 and (not revisions or re.fullmatch(r'r[1-9][0-9]*',revisions[0])),
                    'tools_version','Invalid runtime build revision')
            build_metadata={'revision':revisions[0],'display_version':values[0]+'-'+revisions[0]} if revisions else {}
            prefix=versions[0][:-len(suffix)]
            required=['src/armhpc_ota/maintenance.py','packaging/fallback-health.py',
                      'boot/boot-entry.py','boot/squashfs-boot.py',
                      'helpers/watchdog-guard-arm64','helpers/watchdog-guard-armhf']
            if tuple(map(int, values[0].split('.'))) >= (0,3,2):
                required += ['compat/clock_floor.py', *['compat/clock-services/'+name for name in ('armhpc-clock-floor.service','armhpc-clock-checkpoint.service','armhpc-clock-checkpoint.timer','armhpc-clock-shutdown.service','firstboot-clock.conf')]]
            if tuple(map(int, values[0].split('.'))) >= (0,3,5):
                required += ['src/armhpc_ota/guardian_activation.py']
            if tuple(map(int, values[0].split('.'))) >= (1,0,0):
                required += ['compat/framework-files.json', 'LICENSE', 'THIRD-PARTY-NOTICES.md', 'LICENSES/GPL-3.0-only.txt', 'LICENSES/GPL-2.0-only.txt']
            missing=[name for name in required if prefix+'/'+name not in by_name or
                     not by_name[prefix+'/'+name].isfile() or by_name[prefix+'/'+name].size==0]
            require(not missing, 'tools_runtime_resources',
                    '该归档缺少运行时组件或 ARM64/ARM32 辅助程序。请使用构建生成的 *-linux-runtime.tar.xz，不要选择源码压缩包。',missing=missing)
            profile=prefix+'/src/armhpc_ota/profiles/wxy-oect-original-squashfs.json'
            require(profile in by_name and by_name[profile].isfile() and by_name[profile].size<=1024**2,
                    'tools_profile','运行时没有有效的 OECT SquashFS 适配配置。')
            try: adapter=json.load(archive.extractfile(by_name[profile]))
            except (ValueError,UnicodeError) as error:
                raise OTAError('tools_profile','OECT 适配配置不是有效 JSON。') from error
            require(isinstance(adapter,dict) and isinstance(adapter.get('anchor_abi'),str) and adapter['anchor_abi'],
                    'tools_profile','OECT 适配配置缺少引导 ABI。')
            adapters=[adapter]
            extra=prefix+'/src/armhpc_ota/profiles/wxy-oesp-v22.json'
            if extra in by_name:
                require(by_name[extra].isfile() and by_name[extra].size<=1024**2,'tools_profile','Invalid OESP profile member')
                other=json.load(archive.extractfile(by_name[extra]))
                require(other.get('id')=='wxy-oesp-v22' and other.get('layout')=='oesp-mbr-squashfs-ab-v1',
                        'tools_profile','Unexpected OESP adapter')
                adapters.append(other)
            return {'version':values[0],**build_metadata,'anchor_abi':adapter['anchor_abi'],
                    'boards':sorted({a.get('id','wxy-oect-original') for a in adapters}),'layouts':sorted({a.get('layout','oect-squashfs-ab-v2') for a in adapters}),
                    'anchor_abis':sorted({a['anchor_abi'] for a in adapters})}
    except tarfile.TarError as error:
        raise OTAError('tools_runtime_format','所选文件不是有效的 XZ 运行时归档，请选择 *-linux-runtime.tar.xz。') from error


def tools_bundle(runtime, output, key, key_id, version=None):
    runtime=Path(runtime).resolve(strict=True)
    metadata=inspect_runtime(runtime)
    detected=metadata['version']
    require(version is None or version==detected, 'tools_version', 'Runtime version differs from manifest')
    require(bool(key) and Path(key).is_file(), 'publish_signing_key',
            '制作新的签名包需要发布目录之外的 Ed25519 私钥。使用现成交付目录时直接启动发布服务。')
    output=output_root(output,key);version=detected
    m={'protocol':1,'kind':'tools','version':version,'minimum_agent':'0.2.0',
       'boards':metadata['boards'],'architectures':['arm64','armhf'],
       'layouts':metadata['layouts'],'anchor_abis':metadata['anchor_abis'],
       'artifact':{'size':runtime.stat().st_size,'sha256':sha256(runtime)}}
    if metadata.get('revision'):m.update(revision=metadata['revision'],display_version=metadata['display_version'])
    raw=sign(m,key,key_id)
    dest=output/'tools'/metadata.get('display_version',version)/'maintenance.tar.xz'
    dest.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output) as temporary:
        temp=Path(temporary); atomic_bytes(temp/'manifest.json',raw)
        archive_path=temp/'maintenance.tar.xz'
        with tarfile.open(archive_path,'w:xz') as archive:
            for name,source in [('manifest.json',temp/'manifest.json'),('runtime.tar.xz',runtime)]:
                info=tarfile.TarInfo(name);info.size=source.stat().st_size;info.mode=0o644;info.mtime=0
                with source.open('rb') as stream:archive.addfile(info,stream)
        if dest.exists(): require(dest.read_bytes()==archive_path.read_bytes(),'tools_immutable','A tool version cannot be overwritten')
        else: atomic_copy(archive_path,dest,0o644)
    catalog(output)
    return {'bundle':str(dest),'version':version,'sha256':sha256(dest),'bytes':dest.stat().st_size}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='operation',required=True)
    for name in ('import','index','tools'):
        s=sub.add_parser(name); s.add_argument('--output',required=True); s.add_argument('--key',required=True); s.add_argument('--key-id',required=True)
        if name!='tools':s.add_argument('--base-url',required=True);s.add_argument('--days',type=int,default=14)
        if name=='import':s.add_argument('--spec',required=True)
        if name=='tools':s.add_argument('--runtime',required=True)
    a=p.parse_args(argv)
    try:
        if a.operation=='import': result=import_release(a.spec,a.output,a.key,a.key_id,a.base_url,a.days)
        elif a.operation=='tools':result=tools_bundle(a.runtime,a.output,a.key,a.key_id)
        else:
            root=output_root(a.output,a.key)
            with writer_lock(root/'publish.lock'): rebuild_index(root,a.key,a.key_id,a.base_url,a.days)
            result={'directory':str(root),'index_renewed':True}
        print(json.dumps({'protocol':1,'ok':True,'data':result}));return 0
    except (OTAError,OSError,ValueError,TypeError,KeyError,tarfile.TarError) as e:
        print(json.dumps({'protocol':1,'ok':False,'error':{'code':getattr(e,'code','publish_io'),'message':str(e)}}));return 2


if __name__=='__main__':raise SystemExit(main())
