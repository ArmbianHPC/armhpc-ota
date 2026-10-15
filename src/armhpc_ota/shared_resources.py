# SPDX-License-Identifier: GPL-3.0-only
"""Signed framework code and board hardware defaults; identity and network settings are excluded."""
from pathlib import Path, PurePosixPath
from .errors import require
from .io import read_json, sha256

COMPLETION_TARGETS = frozenset((
    'usr/lib/armhpc/completion.bash',
    'etc/profile.d/armhpc-completion.sh',
    'usr/share/bash-completion/completions/armhpc',
    'usr/share/bash-completion/completions/armhpc-rescue',
    'usr/share/bash-completion/completions/armhpc-kube',
))
SERVICE_TARGETS = frozenset(('etc/systemd/system/armhpc-fan.service',
                             'etc/systemd/system/armhpc-performance.service',
                             'etc/systemd/system/armhpc-performance.timer',
                             *('etc/systemd/system/'+name for name in (
                                 'armhpc-state.service','armhpc-runtime.service','armhpc-swap.service',
                                 'armhpc-auth-recovery.service','armhpc-management-ready.service',
                                 'armhpc-health.service','armhpc-health.timer','armhpc-firewall.service'))))
NODE_TARGETS = frozenset(('etc/tmpfiles.d/armhpc-runtime.conf','etc/systemd/journald.conf.d/40-armhpc.conf'))
BOARD_TARGETS = frozenset(('etc/armhpc/led.json', 'etc/armhpc/phy-led.json',
                          'etc/armhpc/fan.json', 'etc/armhpc/usb-console.json',
                          'etc/armhpc/network-ports.json', 'etc/armhpc/initramfs-firmware',
                          'usr/lib/firmware/rtl_nic/rtl8153b-2.fw',
                          'usr/share/doc/armhpc-firmware/LICENCE.rtlwifi_firmware.txt'))

def files(payload, role=None, board=None):
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
        completion=item['target'] in COMPLETION_TARGETS
        service=item['target'] in SERVICE_TARGETS
        board_target=item['target'] in BOARD_TARGETS
        require(library or notice or completion or service or board_target or item['target'] in NODE_TARGETS,
                'framework_resources','Framework resource is not code, completion, a service, board hardware or a license')
        scope=item.get('scope');require(scope in ('common','board','rescue','normal'),'framework_resources','Unknown framework scope')
        owner=item.get('board')
        require(owner is None or (scope=='board' and owner in ('wxy-oect-original','wxy-oesp-v22')),
                'framework_resources','Invalid board resource selector')
        key=(item['target'],owner)
        require(key not in names,'framework_resources','Duplicate framework target');names.add(key)
        require(not board_target or (scope=='board' and owner is not None),
                'framework_resources','Hardware resources require an explicit board')
        require(not (completion or service or item['target'] in NODE_TARGETS) or scope=='common','framework_resources','Shared resources must use common scope')
        source=root.joinpath(*source_name.parts)
        require(source_name.parts[:2]==('compat','framework') and source.is_file() and not source.is_symlink() and
                source.resolve().is_relative_to(root.resolve()) and sha256(source)==item['sha256'],
                'framework_resources','Framework resource checksum/path differs')
        selected = scope=='common' or (scope=='board' and (owner is None or owner==board)) or (scope=='normal' and role=='system') or (scope=='rescue' and role and role.startswith('rescue_'))
        if selected:
            require(item['target'] not in result,'framework_resources','Overlapping selected framework target')
            result[item['target']]=source
    return result
