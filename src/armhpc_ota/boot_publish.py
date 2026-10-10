# SPDX-License-Identifier: GPL-3.0-only
"""Sign a paired BOOT/Rescue candidate; private recovery image stays on its device."""
import argparse
import hashlib
import io
from pathlib import Path
import tarfile
from .errors import require
from .io import sha256, fsync_dir
from .metadata import sign,verify,validate_manifest,identifier,anchor_digest


def build(rescue_manifest,rootfs,kernel,dtb,initramfs,recovery_initramfs,output,key,key_id,trust,sequence,original_kernel,original_dtb):
    raw=Path(rescue_manifest).read_bytes();m=validate_manifest(verify(raw,Path(trust)))
    require(m['layout']=='oect-squashfs-ab-v2','boot_layout','BOOT candidate requires direct SquashFS Rescue A/B')
    require(isinstance(sequence,int) and sequence>0,'boot_sequence','Use a new increasing BOOT sequence')
    sources={'rescue.manifest.json':Path(rescue_manifest),'rescue-rootfs':Path(rootfs),'kernel':Path(kernel),
             'dtb':Path(dtb),'initramfs':Path(initramfs),'recovery-initramfs':Path(recovery_initramfs)}
    entries={name:{'size':p.stat().st_size,'sha256':sha256(p)} for name,p in sources.items()}
    for name in ('rootfs','kernel','dtb','initramfs'):
        a=next(a for a in m['artifacts'] if a['role']=='rescue-'+name)
        file='rescue-rootfs' if name=='rootfs' else name
        require(a['size']==entries[file]['size'] and a['sha256']==entries[file]['sha256'],'boot_pair','Candidate differs from signed Rescue release',file=file)
    for name in ('initramfs','recovery-initramfs'):
        with sources[name].open('rb') as f:require(f.read(4)!=bytes.fromhex('27051956'),'raw_initramfs','Wrapped uImage initramfs is not accepted')
    files=[entries[k]['sha256'] for k in ('kernel','initramfs','dtb')]
    payload={'kind':'boot-maintenance','protocol':1,'minimum_agent':'0.3.4','release':m['release'],
             'sequence':sequence,'board':m['board'],'architecture':m['architecture'],'layout':m['layout'],
             'anchor_abi':m['anchor_abi'],'kernel_release':m['kernels']['rescue'],'files':entries,
             'requires':{'kernel_sha256':sha256(original_kernel),'dtb_sha256':sha256(original_dtb)},
             'anchor_sha256':anchor_digest([{'id':k,**entries[k]} for k in ('kernel','initramfs','dtb')])}
    output=Path(output);require(not output.exists() and not output.is_symlink(),'release_exists','Published BOOT candidates cannot be overwritten')
    output.parent.mkdir(parents=True,exist_ok=True);temporary=output.with_name('.'+output.name+'.partial')
    require(not temporary.exists(),'release_partial','Resolve the old incomplete publication before signing')
    with tarfile.open(temporary,'w:xz',preset=6) as t:
        envelope=sign(payload,Path(key),key_id);entry=tarfile.TarInfo('manifest.json');entry.size=len(envelope);entry.mode=0o644
        t.addfile(entry,io.BytesIO(envelope))
        for name,p in sources.items():t.add(p,arcname=name,recursive=False)
    with temporary.open('rb') as f:__import__('os').fsync(f.fileno())
    temporary.replace(output);fsync_dir(output.parent)
    return {'release':m['release'],'sequence':sequence,'bundle':str(output),'sha256':sha256(output),
            'hardware_verified':False,'private_boot_backup_included':False,'flashable_whole_disk_image':False}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('rescue-manifest','rootfs','kernel','dtb','initramfs','recovery-initramfs','output','key','key-id','trust','original-kernel','original-dtb'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--sequence',required=True,type=int)
    a=vars(p.parse_args(argv));a['rescue_manifest']=a.pop('rescue_manifest')
    print(__import__('json').dumps(build(**a),indent=2))


if __name__=='__main__':main()
