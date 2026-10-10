# SPDX-License-Identifier: GPL-3.0-only
"""One-shot physical experiments. Discovery never opens a watchdog device."""
import argparse
import json
import mmap
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid
from .device import discover, layout
from .errors import require, OTAError
from .io import atomic_json, read_json, sha256
from .store import TERMINAL

SOCKET = '/run/armhpc/watchdog-control.sock'
FINAL = ('recovered-confirmed', 'manual-recovery', 'cancelled')


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def read(path):
    try: return Path(path).read_text().strip()
    except OSError: return None


def command(*args):
    r = subprocess.run(args, text=True, capture_output=True, timeout=8)
    return {'rc': r.returncode, 'output': (r.stdout + r.stderr).strip()[-6000:]}


def reset_registers():
    """Read only documented RK3566 CRU registers; never modify reset policy."""
    if b'rockchip,rk3566' not in (Path('/proc/device-tree/compatible').read_bytes().split(b'\0')
                               if Path('/proc/device-tree/compatible').exists() else []):
        return {'available': False}
    try:
        fd = os.open('/dev/mem', os.O_RDONLY | os.O_SYNC)
        try:
            with mmap.mmap(fd, mmap.PAGESIZE, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ,
                           offset=0xfdd20000) as memory:
                return {name: hex(int.from_bytes(memory[offset:offset+4], 'little'))
                        for name, offset in [('global_reset_count', 0xd0), ('global_reset_control', 0xdc),
                                             ('global_reset_status', 0xe0)]}
        finally: os.close(fd)
    except (OSError, ValueError) as error: return {'available': False, 'reason': str(error)}


def record(config, test_id=None):
    root = config.state / 'watchdog'
    if not test_id:
        latest = root / 'latest.json'
        if not latest.exists(): return None
        test_id = read_json(latest)['test_id']
    require(str(uuid.UUID(test_id)) == test_id, 'test_id', 'Use the original canonical test UUID')
    return read_json(root / (test_id + '.json'))


def idle(engine, allow_boot=True):
    job = engine.store.read()
    require(not job or job['stage'] in TERMINAL, 'job_active', 'Finish the current OTA job')
    from .maintenance import require_complete
    require_complete(engine.config)
    from .boot_maintenance import require_idle
    require_idle(engine.config, diagnostic=allow_boot)
    r = record(engine.config)
    require(not r or r['stage'] in FINAL, 'test_active', 'Resolve the previous physical experiment first')


def require_idle(config):
    r = record(config)
    require(not r or r['stage'] in FINAL, 'watchdog_test_active', 'Finish or report the watchdog experiment first')


def status(engine):
    c = engine.config
    r = record(c)
    result = {'test': r, 'hardware_verified': False,
              'acceptance_scope': 'internal-watchdog only; full kexec/handoff gate remains separate'}
    if c.simulate: return {**result, 'simulated': True}
    w = Path('/sys/class/watchdog/watchdog0')
    runtime = Path('/run/armhpc/watchdog-guardian.json')
    result.update(boot_id=boot_id(), kernel=os.uname().release,
                  watchdog={name: read(w / name) for name in
                            ('identity', 'state', 'timeout', 'timeleft', 'bootstatus', 'nowayout')},
                  guardian=read_json(runtime) if runtime.is_file() else None,
                  reset_registers=reset_registers())
    from .guardian_activation import snapshot
    result.update(snapshot(result['boot_id']))
    return result


def prepare(engine, kind='expire', sata='present', test_id=None):
    c = engine.config
    require(kind in ('expire', 'direct-restart', 'panic', 'reboot'), 'test_kind', 'Unknown physical test')
    require(sata in ('present', 'absent'), 'sata_condition', 'State the physically checked SATA condition')
    require(c.simulate or os.geteuid() == 0, 'root', 'Watchdog preparation requires root')
    with engine.store.lock():
        device = discover(c); storage = layout(c, device, initialized=True)
        engine._require_shared_mount(storage)
        require(device['mode'] == 'rescue' and device['board'] == 'wxy-oect-original',
                'test_mode', 'Run physical experiments in the OECT Rescue')
        if test_id:
            old = record(c, test_id)
            require(old['kind'] == kind and old['sata_condition'] == sata and
                    old['device_id'] == device['device_id'], 'test_conflict', 'The test ID is already bound')
            return old
        idle(engine)
        engine.clock.flush('watchdog-prepare')
        sata_seen = any(n.get('type') == 'disk' and n.get('tran') == 'sata' for n in device['blocks'])
        require(sata_seen == (sata == 'present'), 'sata_condition', 'Detected SATA differs from the stated physical condition')
        for n in device['blocks']:
            if n.get('label') in (c.board()['labels']['system'], c.board()['labels']['data']):
                require(not any(n.get('mountpoints') or []), 'test_mount',
                        'Unmount SATA root and DATA before a fault experiment')
        control = engine.store.control()
        slot = control['confirmed']['rescue']['slot']
        tested_boot=control['confirmed']['rescue']['boot']
        from .boot_maintenance import record as boot_task
        candidate=boot_task(c)
        if candidate and candidate['stage']=='awaiting-watchdog':
            require(candidate.get('ordinary_boot_healthy'),'boot_health','Candidate must pass ordinary boot first')
            slot=candidate['inactive_slot'];tested_boot=candidate['candidate_boot']
        require(device['root']==storage['partitions']['rescue_'+slot]['path'],'test_root','Enter the selected confirmed/diagnostic Rescue before a fault test')
        require(not control.get('trial'), 'trial_active', 'A boot trial is still active')
        if not c.simulate:
            require(read('/sys/class/watchdog/watchdog0/identity') == 'Synopsys DesignWare Watchdog',
                    'watchdog_driver', 'Unexpected watchdog driver')
            owner = None
            for p in ('RuntimeWatchdogUSec', 'KExecWatchdogUSec'):
                require(command('systemctl', 'show', '--property=' + p, '--value')['output'] == '0',
                        'watchdog_owner', 'Systemd owns another watchdog')
        if kind=='panic' and not c.simulate:
            require(read('/proc/sys/kernel/panic')=='0','panic_timeout','Set kernel.panic=0 for a genuine watchdog panic recovery test')
        tid = str(uuid.uuid4())
        r = {'protocol': 1, 'test_id': tid, 'kind': kind, 'device_id': device['device_id'],
             'sata_condition': sata, 'operator_checked_sata_power': False,
             'before_boot_id': 'fixture' if c.simulate else boot_id(), 'kernel': device['kernel'],
             'slot': slot, 'boot': tested_boot, 'stage': 'preparing' if not c.simulate else 'prepared',
             'created_monotonic': time.monotonic(), 'previous_next': control.get('next'),
             'previous_system_blocked': control.get('system_blocked', False),
             'guardian_before':None if c.simulate else owner, 'hardware_verified': False}
        control['next'] = {'target': 'rescue', 'slot': slot, 'trial': False}
        control['system_blocked'] = True
        engine.store.write_control(control)
        atomic_json(c.state / 'watchdog' / (tid + '.json'), r)
        atomic_json(c.state / 'watchdog/latest.json', {'test_id': tid})
        if not c.simulate:
            os.sync()
            try:
                from .guardian_activation import ensure
                activated = ensure(r)
                r.update(stage='prepared', guardian_before=activated['owner'],
                         guardian_started_for_test=activated['started_for_test'], preparation_health=activated['health'])
                atomic_json(c.state / 'watchdog' / (tid + '.json'), r)
                os.sync()
            except Exception as error:
                r.update(stage='prepare-failed', preparation_error={'code': getattr(error, 'code', 'io'), 'message': str(error)})
                atomic_json(c.state / 'watchdog' / (tid + '.json'), r)
                # A failed arm may already have activated hardware. Keep Rescue selected,
                # never kill/restart the sole holder or automatically return to SATA.
                raise OTAError('guardian_prepare', 'Guardian preparation failed; inspect or cancel this test before retrying',
                               test_id=tid, cause=r['preparation_error']) from error
        return r


def test(engine, test_id, checked_sata_power=False):
    c = engine.config
    require(c.simulate or os.geteuid() == 0, 'root', 'Fault injection requires root')
    with engine.store.lock():
        r = record(c, test_id)
        require(r['stage'] == 'prepared', 'one_shot', 'This experiment was submitted already; query it, never resubmit')
        d = discover(c); storage = layout(c, d, initialized=True); engine._require_shared_mount(storage)
        require(d['mode'] == 'rescue' and d['device_id'] == r['device_id'] and
                (c.simulate or boot_id() == r['before_boot_id']), 'test_binding', 'The prepared boot/device changed')
        job = engine.store.read()
        require(not job or job['stage'] in TERMINAL, 'job_active', 'OTA appeared after test preparation')
        from .maintenance import require_complete
        require_complete(c)
        sata_seen=any(n.get('type')=='disk' and n.get('tran')=='sata' for n in d['blocks'])
        require(sata_seen==(r['sata_condition']=='present'),'sata_condition','SATA changed after preparation')
        require(checked_sata_power, 'physical_confirmation',
                'Confirm SATA data AND power condition with --checked-sata-power')
        require(not any(any(n.get('mountpoints') or []) for n in d['blocks']
                        if n.get('label') in (c.board()['labels']['system'], c.board()['labels']['data'])),
                'test_mount', 'SATA became mounted after preparation')
        engine.clock.flush('watchdog-test')
        if not c.simulate:
            from .guardian_activation import compatible, unit, owner
            keeper = owner()
            require(compatible(unit(), keeper, r['before_boot_id'])
                    and keeper['pid'] == r['guardian_before']['pid'], 'guardian_changed',
                    'The prepared guardian changed; cancel this unsubmitted preparation and prepare again')
        r.update(stage='submitted', operator_checked_sata_power=True, submitted_monotonic=time.monotonic())
        atomic_json(c.state / 'watchdog' / (test_id + '.json'), r)
        if not c.simulate:
            os.sync()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(8); s.connect(SOCKET)
                s.sendall((r['kind'] + ' ' + test_id + ' 5\n').encode())
                answer = s.recv(4096).decode()
                require(answer.startswith('OK '), 'guardian_refused', answer.strip())
                r['guardian_ack'] = answer.strip()
        else: r['guardian_ack'] = 'SIMULATED; no physical reset'
        atomic_json(c.state / 'watchdog' / (test_id + '.json'), r)
    return r


def report(engine, test_id=None, confirmed=False, manual=False, cancel=False):
    c = engine.config
    with engine.store.lock():
        r = record(c, test_id)
        require(r, 'test_missing', 'No physical test record')
        if cancel:
            require(c.simulate or os.geteuid()==0,'root','Cancel requires root')
            require(r['stage'] in ('prepared','preparing','prepare-failed'),'one_shot','A submitted experiment cannot be cancelled')
            ctl=engine.store.control();ctl['next']=r.get('previous_next');ctl['system_blocked']=r['previous_system_blocked'];engine.store.write_control(ctl)
            r['stage']='cancelled';atomic_json(c.state/'watchdog'/(r['test_id']+'.json'),r)
        if confirmed or manual:
            require(c.simulate or os.geteuid()==0,'root','Closing a physical test requires root')
            d = discover(c); require(d['device_id'] == r['device_id'], 'test_binding', 'Device changed')
            require(r['stage'] == 'submitted', 'test_stage', 'Only a submitted experiment can be closed')
            after = 'fixture-after' if c.simulate else boot_id()
            require(after != r['before_boot_id'], 'test_no_reset', 'Still in the same boot')
            if confirmed:
                require(not c.simulate and d['mode'] == 'rescue', 'test_physical',
                        'Only a real Rescue boot can confirm physical recovery')
                evidence = c.state / 'watchdog' / ('guardian-' + r['test_id'] + '.json')
                e = read_json(evidence) if evidence.is_file() else {}
                require(e.get('test_id') == r['test_id'] and e.get('action') == r['kind'] and
                        e.get('stage') == 'triggered' and e.get('boot_id') == r['before_boot_id'],
                        'test_evidence', 'No durable guardian trigger evidence')
                net = command('ip', '-j', 'address', 'show', 'dev', 'eth0')
                addresses = json.loads(net['output'])[0].get('addr_info', []) if net['rc'] == 0 else []
                require(read('/sys/class/net/eth0/carrier') == '1' and
                        any(a['family'] == 'inet' for a in addresses) and
                        command('systemctl', 'is-active', 'ssh.service')['output'] == 'active',
                        'test_network', 'Link, IPv4 and SSH must be ready')
                boot = read_json('/run/armhpc/ota-boot.json')
                require(d['kernel']==r['boot']['kernel_release'] and boot.get('release')==r['boot']['release'],
                        'test_kernel','Returned kernel/release differs from the prepared pair')
                require(boot.get('target') == 'rescue' and boot.get('slot') == r['slot'],
                        'test_slot', 'Did not return to the prepared confirmed Rescue')
                r['trigger_evidence'] = e
            r.update(stage='manual-recovery' if manual else 'recovered-confirmed',
                     after_boot_id=after, operator_no_manual_power_reset=not manual,
                     internal_watchdog_passed=confirmed and r['kind'] == 'expire',
                     hardware_verified=False)
            atomic_json(c.state / 'watchdog' / (r['test_id'] + '.json'), r)
            ctl = engine.store.control()
            ctl['next'] = r.get('previous_next'); ctl['system_blocked'] = r['previous_system_blocked']
            engine.store.write_control(ctl)
        return {'test': r, 'hardware_verified': False,
                'scope': 'This operator-confirmed test does not sign the full OTA hardware gate'}


def main(argv=None):
    p = argparse.ArgumentParser(prog=os.environ.get('ARMHPC_WATCHDOG_PROG', 'armhpc-rescue watchdog'))
    p.add_argument('action', choices=('status', 'prepare', 'test', 'report'))
    p.add_argument('--kind', choices=('expire', 'direct-restart', 'panic', 'reboot'), default='expire')
    p.add_argument('--sata', choices=('present', 'absent'), default='present')
    p.add_argument('--test-id'); p.add_argument('--yes', action='store_true'); p.add_argument('--json', action='store_true')
    p.add_argument('--checked-sata-power', action='store_true')
    p.add_argument('--cancel-prepared',action='store_true')
    p.add_argument('--confirm-recovered', action='store_true'); p.add_argument('--manual-recovery', action='store_true')
    a = p.parse_args(argv)
    from .engine import Engine
    from .config import Config
    try:
        e = Engine(Config.load())
        if a.action in ('prepare', 'test') or a.confirm_recovered or a.manual_recovery or a.cancel_prepared:
            require(discover(e.config)['mode'] == 'rescue' and os.geteuid() == 0, 'test_mode', 'Run as root in Rescue')
            require(a.yes or (not a.json and input('This can disconnect/reset the node. Confirm? [y/N]: ').lower() in ('y','yes')),
                    'confirmation_required', 'Review and use --yes')
        if a.action == 'status': v = status(e)
        elif a.action == 'prepare': v = prepare(e, a.kind, a.sata, a.test_id)
        elif a.action == 'test':
            require(a.test_id, 'test_id', 'Supply the prepared --test-id'); v = test(e, a.test_id, a.checked_sata_power)
        else: v = report(e, a.test_id, a.confirm_recovered, a.manual_recovery,a.cancel_prepared)
        print(json.dumps({'protocol': 1, 'ok': True, 'data': v}, ensure_ascii=False)); return 0
    except (OTAError, OSError, ValueError) as error:
        print(json.dumps({'protocol': 1, 'ok': False, 'error': {'code': getattr(error, 'code', 'io'), 'message': str(error)}})); return 2


if __name__ == '__main__': raise SystemExit(main())
