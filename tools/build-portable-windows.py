# SPDX-License-Identifier: GPL-3.0-only
"""Install hash-pinned official Python/wheels and the corresponding publisher source."""
import argparse,hashlib,json,shutil,urllib.request,zipfile
from pathlib import Path

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def fetch(item,cache):
    p=cache/item['file']
    if not p.exists():
        temporary=p.with_suffix(p.suffix+'.part')
        with urllib.request.urlopen(item['url'],timeout=45) as r,temporary.open('wb') as f:shutil.copyfileobj(r,f)
        if sha(temporary)!=item['sha256']:raise ValueError('Downloaded dependency hash differs: '+item['file'])
        temporary.replace(p)
    if sha(p)!=item['sha256']:raise ValueError('Cached dependency hash differs: '+item['file'])
    return p
def unpack(p,directory):
    with zipfile.ZipFile(p) as z:
        for info in z.infolist():
            q=Path(info.filename)
            if q.is_absolute() or '..' in q.parts or '\\' in info.filename or not (directory/q).resolve().is_relative_to(directory.resolve()):raise ValueError('Unsafe dependency ZIP')
        z.extractall(directory)
def build(output,cache):
    repo=Path(__file__).resolve().parents[1];output=Path(output).resolve();cache=Path(cache).resolve()
    if output.is_relative_to(repo) or cache.is_relative_to(repo):raise ValueError('Generated dependencies belong outside source')
    lock=json.loads((repo/'DEPENDENCIES.lock.json').read_text());cache.mkdir(parents=True,exist_ok=True)
    root=output/'publisher';root.mkdir(parents=True,exist_ok=True);unpack(fetch(lock['python'],cache),root)
    (root/'python314._pth').write_text('python314.zip\n.\nLib\nimport site\n')
    library=root/'Lib';library.mkdir(exist_ok=True)
    for item in lock['wheels']:unpack(fetch(item,cache),library)
    shutil.copytree(repo/'src/armhpc_ota',library/'armhpc_ota',dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    for name in ('LICENSE','COPYRIGHT','THIRD-PARTY-NOTICES.md'):shutil.copy2(repo/name,output/('LICENSE-ARMHPC.txt' if name=='LICENSE' else name))
    shutil.copytree(repo/'LICENSES',output/'LICENSES',dirs_exist_ok=True)
    (output/'DEPENDENCIES.json').write_text(json.dumps(lock,indent=2)+'\n')
    return lock
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--cache',type=Path,required=True);a=p.parse_args();print(json.dumps(build(a.output,a.cache),indent=2))
