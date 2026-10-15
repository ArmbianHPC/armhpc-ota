# SPDX-License-Identifier: GPL-3.0-only
"""Explicit diagnostic preparation of the existing sole watchdog guardian.

Read-only status never arms hardware. Ordinary confirmed boots may omit the
trial watchdog flag; a confirmed Rescue can opt in after all checks pass.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import time
from .errors import require, OTAError
from .io import atomic_json, read_json

OWNER_VERSION = '0.3.4'  # Guardian wire protocol.
OWNER = Path('/run/armhpc/watchdog-guardian.json')
SOCKET = Path('/run/armhpc/watchdog-control.sock')
REQUIRED = Path('/run/armhpc-ota-watchdog-required')
HEALTHY = Path('/run/armhpc-ota-healthy')
CONTEXT = Path('/run/armhpc/ota-boot.json')
PROOF = Path('/run/armhpc/watchdog-preparation-health.json')
UNIT = 'armhpc-ota-watchdog.service'


def run(*args):
    try:
        r = subprocess.run(args, text=True, capture_output=True, timeout=5)
        return {'rc': r.returncode, 'output': (r.stdout + r.stderr).strip()[-4000:]}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'rc': -1, 'output': str(error)}


def read(path):
    try: return Path(path).read_text().strip()
    except OSError: return None


def unit():
    result = run('systemctl', 'show', UNIT,
                 '--property=LoadState,ActiveState,SubState,ConditionResult,MainPID,Result')
    return {**dict(line.split('=', 1) for line in result['output'].splitlines() if '=' in line),
            'query_rc': result['rc']}


def owner():
    try: return read_json(OWNER) if OWNER.is_file() else None
    except (ValueError, OSError, OTAError): return None


def compatible(service, keeper, boot):
    try:
        return bool(keeper and keeper.get('owner') == OWNER_VERSION and keeper.get('boot_id') == boot
                    and int(keeper.get('pid', 0)) > 0 and int(service.get('MainPID', 0)) == keeper['pid']
                    and service.get('ActiveState') == 'active' and SOCKET.is_socket()
                    and SOCKET.stat().st_uid == 0 and stat.S_IMODE(SOCKET.stat().st_mode) == 0o600
                    and read('/sys/class/watchdog/watchdog0/state') == 'active')
    except (OSError, ValueError, TypeError): return False


def snapshot(boot):
    service, keeper = unit(), owner()
    good = compatible(service, keeper, boot)
    requested = REQUIRED.exists() or 'armhpc.watchdog=1' in (read('/proc/cmdline') or '').split()
    return {'guardian_unit': service, 'guardian_protocol_version': OWNER_VERSION,
            'guardian_compatible': good, 'boot_watchdog_requested': requested,
            'watchdog_required_marker': REQUIRED.exists(), 'health_marker_present': HEALTHY.exists(),
            'readiness_hint': ('ready' if good else 'ordinary_boot_requires_explicit_prepare'
                               if not requested and service.get('LoadState') == 'loaded'
                               and service.get('ActiveState') == 'inactive'
                               and read('/sys/class/watchdog/watchdog0/state') == 'inactive'
                               else 'inspect_guardian_service')}


def holders():
    """Stat proc descriptors; do not open /dev/watchdog or ioctl it."""
    numbers = set()
    for path in ('/dev/watchdog', '/dev/watchdog0'):
        try:
            info = Path(path).stat()
            if stat.S_ISCHR(info.st_mode): numbers.add(info.st_rdev)
        except FileNotFoundError: pass
    require(numbers, 'watchdog_device', 'Watchdog character device is missing')
    found = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal(): continue
        try:
            for fd in (proc / 'fd').iterdir():
                try:
                    info = fd.stat()
                    if stat.S_ISCHR(info.st_mode) and info.st_rdev in numbers:
                        found.append({'pid': int(proc.name), 'fd': fd.name})
                except FileNotFoundError: pass
        except FileNotFoundError: pass
        except PermissionError:
            raise OTAError('watchdog_owner', 'Cannot verify another process descriptor table')
    return found


def network_ready(interfaces=('eth0',), runner=None, reader=None):
    runner, reader = runner or run, reader or read
    for interface in interfaces:
        net = runner('ip','-j','address','show','dev',interface)
        try:
            ipv4=any(a.get('family')=='inet' for a in json.loads(net['output'])[0].get('addr_info',[]))
        except (ValueError,IndexError,KeyError,TypeError):
            ipv4=False
        if net['rc']==0 and ipv4 and reader('/sys/class/net/'+interface+'/carrier')=='1':
            return {'interface':interface,'link':True,'ipv4_ready':True}
    return None


def ready_record(prepared):
    require(CONTEXT.is_file(), 'test_boot_context', 'Missing current Rescue boot context')
    context = read_json(CONTEXT)
    require(context.get('target') == 'rescue' and context.get('slot') == prepared['slot']
            and context.get('release') == prepared['boot']['release'] and context.get('shared_ready'),
            'test_boot_context', 'Current Rescue context differs from the protected test target')
    net = network_ready(prepared.get('management_interfaces',('eth0',)))
    require(net
            and run('systemctl', 'is-active', 'ssh.service')['output'] == 'active',
            'test_network', 'Confirmed Rescue needs link, IPv4 and SSH before arming a test guardian')
    return {'boot_id': prepared['before_boot_id'], 'test_id': prepared['test_id'],
            'slot': prepared['slot'], 'release': prepared['boot']['release'],
            'shared_ready': True, **net, 'ssh': True}


def ensure(prepared):
    """Called only by prepare under the device writer lock, after Rescue selection is durable."""
    require(os.geteuid() == 0, 'root', 'Guardian preparation requires root')
    service, keeper = unit(), owner()
    good = compatible(service, keeper, prepared['before_boot_id'])
    require(service.get('LoadState') == 'loaded', 'guardian_unit', 'Install the signed watchdog maintenance unit first')
    if not good:
        require(read('/sys/class/watchdog/watchdog0/state') == 'inactive'
                and service.get('ActiveState') not in ('active', 'activating') and not holders(),
                'watchdog_owner', 'Another process or incompatible guardian owns the watchdog; it will not be restarted')
    require(not good or not keeper.get('armed_test'), 'guardian_consumed',
            'This guardian already accepted an experiment; inspect its original test ID and reboot normally')
    proof = ready_record(prepared)
    atomic_json(PROOF, proof)
    # The health marker is earned here by current-boot checks, never blindly fabricated.
    if not HEALTHY.exists(): atomic_json(HEALTHY, proof)
    if good: return {'started_for_test': False, 'owner': keeper, 'health': proof}
    atomic_json(REQUIRED, {'boot_id': prepared['before_boot_id'], 'test_id': prepared['test_id']})
    result = run('systemctl', 'start', UNIT)
    require(result['rc'] == 0, 'guardian_start', 'Guardian service refused to start', service_result=result['output'])
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        service, keeper = unit(), owner()
        if compatible(service, keeper, prepared['before_boot_id']):
            return {'started_for_test': True, 'owner': keeper, 'health': proof}
        if service.get('ActiveState') == 'failed': break
        time.sleep(0.1)
    raise OTAError('guardian_start', 'Guardian did not become the verified sole holder; protected Rescue selection is retained', service=service)
