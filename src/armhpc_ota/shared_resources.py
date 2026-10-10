# SPDX-License-Identifier: GPL-3.0-only
"""Signed framework code resources; writable identity/configuration is excluded."""
from pathlib import Path, PurePosixPath
from .errors import require
from .io import read_json, sha256

def files(payload, role=None):
    root=Path(payload); manifest=root/'compat/framework-files.json'
    if not manifest.is_file():return {}
    value=read_json(manifest)
    require(value.get('protocol')==1 and len(value.get('files',[]))<=128,'framework_resources','Invalid framework resource inventory')
    result={}; names=set()
    for item in value['files']:
        relative=PurePosixPath(item['target']);source_name=PurePosixPath(item['source'])
        require(not relative.is_absolute() and '..' not in relative.parts and '\\' not in item['target'] and
                not source_name.is_absolute() and '..' not in source_name.parts and '\\' not in item['source'],
                'framework_resources','Unsafe framework resource path')
        library=relative.parts[:3]==('usr','lib','armhpc') and len(relative.parts)==4 and relative.suffix=='.py'
        notice=relative.parts[:4]==('usr','share','doc','armhpc-framework') and len(relative.parts)==5 and relative.suffix=='.txt'
        require(library or notice,'framework_resources','Framework resource is not code or a license')
        require(item['target'] not in names,'framework_resources','Duplicate framework target');names.add(item['target'])
        scope=item.get('scope');require(scope in ('common','board','rescue','normal'),'framework_resources','Unknown framework scope')
        source=root.joinpath(*source_name.parts)
        require(source_name.parts[:2]==('compat','framework') and source.is_file() and not source.is_symlink() and
                source.resolve().is_relative_to(root.resolve()) and sha256(source)==item['sha256'],
                'framework_resources','Framework resource checksum/path differs')
        if scope in ('common','board') or (scope=='normal' and role=='system') or (scope=='rescue' and role and role.startswith('rescue_')):
            result[item['target']]=source
    return result
