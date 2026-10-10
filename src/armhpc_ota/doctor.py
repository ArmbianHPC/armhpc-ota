# SPDX-License-Identifier: GPL-3.0-only
import shutil
import time
import subprocess
from .io import read_json
from .device import discover, layout
from .errors import OTAError
from . import sources


def inspect(engine):
    c = engine.config
    status = engine.status()
    required = ('findmnt', 'lsblk', 'blkid', 'mount', 'umount', 'losetup', 'e2fsck', 'resize2fs',
                'zstd', 'unmkinitramfs', 'chroot', 'systemctl', 'sshd')
    dependencies = {name: bool(shutil.which(name)) for name in required}
    checks = {}
    try:
        storage = layout(c, discover(c), initialized=True)
        engine._require_shared_mount(storage)
        checks['storage'] = {'ok': True, 'partitions': {k: v['path'] for k, v in storage['partitions'].items() if v}}
    except OTAError as e: checks['storage'] = {'ok': False, 'code': e.code, 'message': str(e)}
    try: checks['source'] = {'ok': True, **sources.test(engine)}
    except (OTAError, OSError) as e: checks['source'] = {'ok': False, 'code': getattr(e, 'code', 'io'), 'message': str(e)}
    clock = engine.clock.snapshot(live=True)
    return {'agent_version': status['agent_version'], 'device_id': status['device_id'], 'mode': status['mode'],
            'dependencies': dependencies, 'checks': checks, 'clock': clock,
            'source_profile': sources.show(c), 'tools': status.get('tools'),
            'watchdog': status['watchdog'], 'boot_maintenance': status['boot_maintenance'],
            'hardware_gate': status['hardware_gate'], 'hardware_verified': status['hardware_gate'].get('hardware_verified', False),
            'ready': all(dependencies.values()) and all(v['ok'] for v in checks.values())}
