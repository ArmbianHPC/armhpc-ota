# SPDX-License-Identifier: GPL-3.0-only
"""Read locally supplied signed bundles; payload identity never uses their URL."""
import argparse
import hashlib
import json
from pathlib import Path,PurePosixPath
import tarfile
from .errors import require,OTAError
from .io import sha256,inside
from .metadata import validate_manifest


def inspect(package,output,release=None):
    package=Path(package).resolve(strict=True);output=Path(output).resolve()
    if package.is_dir():root=package
    else:
        require(package.stat().st_size<=16*1024**3,'package_size','OTA package is too large')
        digest=sha256(package);root=output/digest
        ready=root/'extracted.json'
        if not ready.is_file():
            root.mkdir(parents=True,exist_ok=True)
            with tarfile.open(package,'r:xz') as archive:
                members=archive.getmembers();require(len(members)<=10000 and sum(m.size for m in members)<=32*1024**3,'package_size','Archive limits exceeded')
                names=set()
                for member in members:
                    path=PurePosixPath(member.name)
                    require(not path.is_absolute() and '..' not in path.parts and '\\' not in member.name and (member.isfile() or member.isdir()),'package_path','Unsafe archive member')
                    require(member.name not in names,'package_path','Duplicate archive member');names.add(member.name)
                    target=inside(root,member.name)
                    if member.isdir():target.mkdir(parents=True,exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True,exist_ok=True)
                        with archive.extractfile(member) as source,target.open('wb') as dest:
                            import shutil;shutil.copyfileobj(source,dest,1024**2)
            ready.write_text(json.dumps({'sha256':digest}))
    paths=list((root/'releases').glob('*/manifest.json'))
    if (root/'manifest.json').is_file():paths.append(root/'manifest.json')
    candidates=[]
    for path in paths:
        document=json.loads(path.read_text());require(set(document)=={'schema','key_id','payload','signature'},'package_unsigned','Provide a signed release manifest')
        manifest=validate_manifest(document['payload'])
        if release is None or manifest['release']==release:candidates.append((path,manifest))
    require(len(candidates)==1,'package_release','Select a package containing one requested signed release')
    path,manifest=candidates[0];artifacts=[]
    for item in manifest['artifacts']:
        file=inside(root,'blobs/'+item['sha256'])
        require(file.is_file() and file.stat().st_size==item['size'] and sha256(file)==item['sha256'],'package_hash','Local payload differs from manifest',role=item['role'])
        artifacts.append({'role':item['role'],'sha256':item['sha256'],'size':item['size'],'path':str(file)})
    firmware=inside(root,'firmware/boot-update.tar.xz')
    extra={}
    if firmware.is_file():
        with tarfile.open(firmware,'r:xz') as archive:
            entry=archive.getmember('manifest.json')
            require(entry.isfile() and entry.size<=1024**2,'boot_manifest','Invalid firmware envelope')
            payload=json.loads(archive.extractfile(entry).read())['payload']
        require(payload.get('purpose')=='firmware-update' and payload.get('release')==manifest['release']
                and payload.get('board')==manifest['board'] and 'system-rootfs' in payload.get('files',{}),
                'boot_pair','Firmware bundle does not match the selected complete release')
        extra={'kind':'firmware-update','firmware_bundle':str(firmware),'firmware_sha256':sha256(firmware)}
    return {**extra,'release':manifest['release'],'manifest':str(path),'manifest_sha256':sha256(path),'artifacts':artifacts,
            'board':manifest['board'],'architecture':manifest['architecture'],'signature_verification':'required_on_device'}


def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--package',required=True);p.add_argument('--output',required=True);p.add_argument('--release')
    a=p.parse_args(argv)
    try:result=inspect(a.package,a.output,a.release);print(json.dumps({'protocol':1,'ok':True,'data':result}));return 0
    except (OTAError,OSError,ValueError,tarfile.TarError) as e:
        print(json.dumps({'protocol':1,'ok':False,'error':{'code':getattr(e,'code','package_io'),'message':str(e)}}));return 2

if __name__=='__main__':raise SystemExit(main())
