# SPDX-License-Identifier: GPL-3.0-only
"""Inventory publishable sources without inspecting local caches or user files."""
import argparse,hashlib,json,re
from pathlib import Path

def inventory(root):
    root=Path(root).resolve();default='GPL-3.0-only' if root.name=='armhpc-ota' or (root/'pyproject.toml').exists() else 'GPL-2.0-only'
    files=[];errors=[]
    for p in sorted(root.rglob('*')):
        q=p.relative_to(root)
        if q.parts[0] in ('.git','build','cache','sources','private','local','dist') or any(x in q.parts for x in ('bin','obj','__pycache__','.venv','.vs')):continue
        if any(x.endswith('.egg-info') or x=='.pytest_cache' for x in q.parts):continue
        if not p.is_file():continue
        if p.is_symlink():errors.append(q.as_posix()+': source link');continue
        raw=p.read_bytes()
        if p.suffix.lower() in ('.pem','.key','.pub','.pfx','.p12','.dll','.exe','.bin','.elf','.itb','.img','.xz','.zst') or raw.startswith((b'\x7fELF',b'MZ',b'version https://git-lfs.github.com/spec/')):
            errors.append(q.as_posix()+': binary/private payload')
        if re.search(rb'-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]{40,}',raw):errors.append(q.as_posix()+': private key')
        text=raw.decode('utf-8',errors='replace');m=re.search(r'SPDX-License-Identifier:\s*([^\r\n]+)',text[:800])
        expression=m.group(1).strip().removesuffix('-->').strip() if m else default
        foreign=q.parts[:5]==('adapters','boards','wxy-oect-original','armbian','kernel-6.12.111') and p.suffix=='.patch'
        dts=q.as_posix().endswith('/dts/rk3566-wxy-oec-turbo-4g.dts')
        if foreign:
            expression='GPL-2.0-only'
            if p.name=='board-oect-usb2-peripheral-power.patch':
                origin='ARMHPC local backport / Andreas Zdziarstek RFC 20260706223627.113814-2 on lore.kernel.org/linux-phy'
            elif p.name=='zz-armhpc-linux-6.12.111-driver-apis.patch':
                origin='ARMHPC driver compatibility adaptation / Linux 6.12.111 e2acc2211022246c77740d5df08265cc27eedcc5'
            else:
                origin='Armbian build 147b9a23f09fae4d5ef8e73cf07ee69652ff4976 / original patch authors / ARMHPC context backports'
        elif dts:origin='unifreq linux-6.12.y 4c0b3046f608fad852b55de1b234d43b8e178034 / Linux 53ec6d21fe1ec0677f9db56a23dda8d145eda102'
        elif q.parts[0]=='LICENSES' or q.as_posix()=='LICENSE':origin='Original license text'
        else:origin='ARMHPC contributors'
        if p.suffix in ('.py','.cs','.c','.sh','.ps1','.xaml','.csproj','.props','.dts') and not m:errors.append(q.as_posix()+': missing SPDX')
        files.append({'path':q.as_posix(),'license':expression,'origin':origin,'sha256':hashlib.sha256(raw).hexdigest()})
    return {'protocol':1,'default_license':default,'files':files,'errors':errors,'passed':not errors}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]);p.add_argument('--output',type=Path);a=p.parse_args()
    report=inventory(a.root)
    if a.output:
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':report['passed'],'files':len(report['files']),'errors':report['errors']},ensure_ascii=False));raise SystemExit(0 if report['passed'] else 1)
