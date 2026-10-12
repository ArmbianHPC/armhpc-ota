# SPDX-License-Identifier: GPL-3.0-only
"""Signed userland maintenance; no BOOT, kernel, partition or SquashFS base writes."""
from contextlib import contextmanager
import argparse
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import uuid
from . import __version__
from .device import discover, layout, ensure_unmounted, run
from .errors import require, OTAError
from .io import atomic_json, atomic_bytes, atomic_copy, read_json, sha256, identifier
from .metadata import verify, valid_sha
from .store import Store, TERMINAL, now

DONE = ('succeeded', 'rolled-back')


def record(config):
    p = config.state / 'maintenance/task.json'
    return read_json(p) if p.is_file() else None


def require_complete(config):
    r = record(config)
    require(not r or r['stage'] in DONE, 'maintenance_incomplete',
            'Finish or roll back OTA tool maintenance before creating a new upgrade')


def status(config):
    r = record(config)
    return {'agent_version': __version__, 'consistent': not r or r['stage'] in DONE,
            'maintenance': {k: r[k] for k in ('task_id', 'version', 'stage', 'completed', 'updated', 'error') if k in r} if r else None}


def safe_extract(archive, destination):
    members = archive.getmembers()
    require(len(members) <= 10000 and sum(m.size for m in members) < 256 * 1024**2,
            'tools_archive', 'Maintenance archive exceeds its limits')
    names = set()
    for m in members:
        p = PurePosixPath(m.name)
        require(m.name not in names and not p.is_absolute() and '\\' not in m.name and
                all(s not in ('', '.', '..') for s in p.parts) and (m.isfile() or m.isdir()),
                'tools_archive', 'Unsafe or duplicate archive member')
        names.add(m.name)
        target = destination.joinpath(*p.parts)
        require(target.resolve().is_relative_to(destination.resolve()) and not target.is_symlink(), 'tools_archive', 'Archive escapes staging')
    # Only regular files/directories, never archived permissions, owners or links.
    for m in members:
        target = destination.joinpath(*PurePosixPath(m.name).parts)
        if m.isdir(): target.mkdir(parents=True, exist_ok=True, mode=0o700)
        else:
            with archive.extractfile(m) as f: atomic_bytes(target, f.read())


def prepare(config, bundle):
    bundle = Path(bundle).resolve(strict=True)
    require(bundle.stat().st_size < 256 * 1024**2, 'tools_size', 'Maintenance bundle is too large')
    with tarfile.open(bundle, 'r:xz') as outer:
        members = outer.getmembers()
        require(len(members) == 2 and {m.name for m in members} == {'manifest.json', 'runtime.tar.xz'} and
                all(m.isfile() for m in members), 'tools_archive', 'Unexpected maintenance bundle entries')
        m = next(m for m in members if m.name == 'manifest.json')
        require(m.size <= 4 * 1024**2, 'tools_manifest', 'Oversize tools manifest')
        raw = outer.extractfile(m).read()
        manifest = verify(raw, config.trust)
        require(manifest.get('kind') == 'tools' and manifest.get('protocol') == 1 and
                isinstance(manifest.get('version'), str) and __import__('re').fullmatch(r'\d+\.\d+\.\d+', manifest['version']), 'tools_version', 'Invalid maintenance version')
        device = discover(config); board = config.board()
        require(device['board'] in manifest['boards'] and device['architecture'] in manifest['architectures'] and
                board['layout'] in manifest['layouts'] and board['anchor_abi'] in manifest['anchor_abis'],
                'tools_compatibility', 'Maintenance bundle is not compatible with this adapter')
        control = Store(config.state).control()
        key_id = read_json_bytes(raw)['key_id']
        require(key_id in control.get('anchor_key_ids', [key_id]), 'anchor_trust', 'Tools key is not pinned by the bootstrap')
        runtime = next(m for m in members if m.name == 'runtime.tar.xz')
        item = manifest['artifact']; valid_sha(item['sha256'])
        require(runtime.size == item['size'], 'tools_size', 'Runtime size differs from its signed manifest')
        directory = config.state / 'maintenance/releases' / identifier(manifest['version']) / item['sha256']
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        package = directory / 'runtime.tar.xz'
        with outer.extractfile(runtime) as stream: atomic_bytes(package, stream.read())
        require(sha256(package) == item['sha256'], 'tools_hash', 'Runtime hash verification failed')
        atomic_bytes(directory / 'manifest.json', raw)
    payload = directory / 'payload'
    if not (directory / 'extracted.json').is_file():
        payload.mkdir(exist_ok=True, mode=0o700)
        with tarfile.open(package, 'r:xz') as archive: safe_extract(archive, payload)
        atomic_json(directory / 'extracted.json', {'sha256': item['sha256']})
    homes = list(payload.glob('armhpc-ota-*'))
    require(len(homes) == 1 and (homes[0] / 'src/armhpc_ota/maintenance.py').is_file(), 'tools_layout', 'Missing maintenance runtime')
    import ast
    tree=ast.parse((homes[0]/'src/armhpc_ota/__init__.py').read_text())
    detected=next(n.value.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='__version__' for t in n.targets))
    require(detected==manifest['version'], 'tools_version', 'Signed tools version differs from runtime')
    if tuple(map(int, detected.split('.'))) >= (0, 3, 2):
        from .clock_resources import files as clock_files
        require((homes[0]/'compat/clock_floor.py').is_file() and clock_files(homes[0]), 'clock_resources', 'Agent 0.3.2+ maintenance requires the clock helper and all clock services')
    return manifest, homes[0]


def read_json_bytes(raw):
    from .io import parse_json
    return parse_json(raw)


def service_text(config):
    return ('[Unit]\nDescription=ARMHPC signed userland maintenance\nAfter=local-fs.target\n'
            'RequiresMountsFor=/var/lib/armhpc/ota\nConditionPathExists=/var/lib/armhpc/ota/maintenance/task.json\n'
            '[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /var/lib/armhpc/ota/maintenance/runner.py --worker\n'
            'TimeoutStartSec=30min\n[Install]\nWantedBy=multi-user.target\n')


def put_service(root, config):
    p = Path(root) / 'etc/systemd/system/armhpc-ota-tools.service'
    atomic_bytes(p, service_text(config).encode(), 0o644)
    wanted = p.parent / 'multi-user.target.wants'; wanted.mkdir(exist_ok=True)
    link = wanted / p.name
    if not link.exists(): link.symlink_to('../' + p.name)


@contextmanager
def target_root(engine, storage, device, role):
    partition = storage['partitions'][role]
    if engine.config.simulate:
        yield engine.config.simulate / 'roots' / role
    elif partition['path'] == device['root']:
        require(role.startswith('rescue_') and device['mode'] == 'rescue', 'tools_running_root', 'Normal runtime is maintained only from Rescue')
        yield Path('/')
    else:
        ensure_unmounted(engine.config, device, partition)
        with engine.backend.mount(partition, True) as root: yield root


def schedule(engine, bundle=None, rollback=False, request_id=None):
    c = engine.config
    with engine.store.lock():
        from .watchdog import require_idle as watchdog_idle
        from .boot_maintenance import require_idle as boot_idle
        watchdog_idle(c); boot_idle(c)
        from .preserve import require_network_confirmed
        require_network_confirmed(c.simulate / 'roots/system' if c.simulate else Path('/'))
        job = engine.store.read()
        require(not job or job['stage'] in TERMINAL, 'job_active', 'Finish the OTA task before tool maintenance')
        device = discover(c); storage = layout(c, device, initialized=True); engine._require_shared_mount(storage)
        old = record(c)
        if request_id:
            require(str(uuid.UUID(request_id)) == request_id, 'request_id', 'Maintenance request ID must be a canonical UUID')
        if rollback:
            require(old, 'tools_rollback', 'No maintenance record to restore')
            task = old; task['rollback'] = True
        else:
            require(bundle, 'tools_bundle', 'Supply a signed maintenance bundle')
            manifest, payload = prepare(c, bundle)
            if old and request_id and old['task_id'] == request_id:
                require(old['payload'] == str(payload) and old['device_id'] == device['device_id'], 'request_conflict', 'Maintenance request belongs to another bundle/device')
                if old['stage'] in DONE: return status(c)
            if old and old['stage'] not in DONE:
                require(not request_id or old['task_id'] == request_id, 'maintenance_active', 'Another maintenance request is active')
                require(old['payload'] == str(payload), 'maintenance_active', 'Resume the existing maintenance before selecting another bundle')
                task = old
            else:
                task = {'protocol': 1, 'task_id': request_id or str(uuid.uuid4()), 'version': manifest['version'],
                        'device_id': device['device_id'], 'payload': str(payload), 'completed': [], 'backed_up': [],
                        'roles': ['rescue_a', 'rescue_b'] + (['system'] if storage['partitions']['system'] else []),
                        'rollback': False, 'stage': 'queued'}
        task['updated'] = now(); task['stage'] = 'awaiting-rescue' if device['mode'] == 'system' else 'queued'
        atomic_json(c.state / 'maintenance/task.json', task)
        atomic_bytes(c.state / 'maintenance/pending', b'Userland maintenance in progress\n')
        for gate_role in ([] if rollback else task['roles']):
            partition = storage['partitions'][gate_role]
            if device['mode'] == 'system' and partition['path'] == device['root']:
                gate_root = c.simulate / 'roots/system' if c.simulate else Path('/')
                atomic_bytes(gate_root/'etc/systemd/system/armhpc-ota-worker.service.d/00-maintenance.conf', b'[Unit]\nConditionPathExists=!/var/lib/armhpc/ota/maintenance/pending\n', 0o644)
            else:
                with target_root(engine, storage, device, gate_role) as gate_root:
                    atomic_bytes(gate_root/'etc/systemd/system/armhpc-ota-worker.service.d/00-maintenance.conf', b'[Unit]\nConditionPathExists=!/var/lib/armhpc/ota/maintenance/pending\n', 0o644)
        entry = "import sys\nfrom pathlib import Path\nsys.path.insert(0," + repr(str(Path(task['payload'])/'src')) + ")\nfrom armhpc_ota.maintenance import main\nraise SystemExit(main())\n"
        atomic_bytes(c.state / 'maintenance/runner.py', entry.encode())
        control = engine.store.control(); role = 'rescue_' + control['confirmed']['rescue']['slot']
        with target_root(engine, storage, device, role) as root: put_service(root, c)
        if device['mode'] == 'system':
            control['next'] = {'target': 'rescue', 'slot': control['confirmed']['rescue']['slot'], 'trial': False}
            engine.store.write_control(control)
    if not c.simulate:
        run('systemctl', 'daemon-reload')
        if device['mode'] == 'system': engine.backend.request_reboot()
        else: run('systemctl', 'daemon-reload'); run('systemctl', 'start', '--no-block', 'armhpc-ota-tools.service')
    return status(c)


def runtime_files(payload, architecture, role=None):
    result = {}
    for source in (payload/'src/armhpc_ota').rglob('*.py'):
        if '__pycache__' not in source.parts: result['usr/lib/armhpc-ota/armhpc_ota/' + source.relative_to(payload/'src/armhpc_ota').as_posix()] = source
    for source in (payload/'src/armhpc_ota/profiles').glob('*.json'):
        result['usr/lib/armhpc-ota/armhpc_ota/profiles/' + source.name] = source
    for source in (payload/'packaging').iterdir():
        if source.is_file(): result['usr/lib/armhpc-ota/resources/' + source.name] = source
        if source.suffix == '.service': result['etc/systemd/system/' + source.name] = source
    for name, folder in [('fallback-health.py', 'packaging'), ('boot-entry.py', 'boot'), ('squashfs-boot.py', 'boot')]:
        result['usr/lib/armhpc-ota/' + name] = payload/folder/name
    if (payload/'compat/clock_floor.py').is_file(): result['usr/lib/armhpc/clock_floor.py'] = payload/'compat/clock_floor.py'
    result['usr/lib/armhpc-ota/watchdog-guard'] = payload/'helpers'/('watchdog-guard-' + architecture)
    from .clock_resources import files as clock_files
    result.update(clock_files(payload))
    for name in ('cli.py','watchdog.py'):
        source=payload/'compat/public-cli'/name
        if source.is_file(): result['usr/lib/armhpc/'+name]=source
    from .shared_resources import files as shared_files
    result.update(shared_files(payload, role))
    for name in ('LICENSE', 'THIRD-PARTY-NOTICES.md'):
        source = payload / name
        if source.is_file(): result['usr/share/doc/armhpc-ota/' + name] = source
    return result


def backup_and_install(engine, task, role, root, files):
    c = engine.config
    if role == 'system':
        from .preserve import require_network_confirmed
        require_network_confirmed(root)
    backup = c.state / 'maintenance/backups' / task['task_id'] / role
    inventory = backup/'files.json'
    has_clock = 'etc/systemd/system/armhpc-clock-floor.service' in files
    if has_clock:
        from .clock_resources import capture_active, prepare_rollback
        capture_active(c, root, backup)
        if task['rollback']: prepare_rollback(c, root)
    if 'etc/systemd/system/armhpc-ota-boot-diagnostics.service' in files:
        from .diagnostic_resources import capture_active
        capture_active(c,root,backup)
    if role not in task['backed_up']:
        saved = {}
        for relative in [*files, 'etc/armhpc/ota-runtime.json', 'etc/armhpc/ota.json']:
            target = root/relative
            require(not any(p.is_symlink() for p in [target, *target.parents] if p != root and p.is_relative_to(root)), 'tools_path', 'Runtime parent is a symbolic link')
            require(not target.is_symlink(), 'tools_path', 'Runtime target is a symbolic link')
            saved[relative] = {'exists': target.exists(), 'mode': (target.stat().st_mode & 0o777) if target.exists() else None}
            if target.exists(): atomic_copy(target, backup/relative)
        atomic_json(inventory, saved)
        task['backed_up'].append(role); atomic_json(c.state/'maintenance/task.json', task)
    if task['rollback']:
        for relative, previous in read_json(inventory).items():
            target = root/relative
            if previous['exists']: atomic_copy(backup/relative, target, previous['mode'])
            else: target.unlink(missing_ok=True)
    else:
        # Per-file atomic replacement, version marker last; isolated worker survives interruption.
        for relative, source in sorted(files.items(), key=lambda pair: 2 if pair[0].endswith('armhpc_ota/__init__.py') else
                                       1 if pair[0] in ('usr/lib/armhpc/cli.py', 'usr/lib/armhpc/firstboot.py', 'usr/lib/armhpc/configuration.py') else 0):
            target = root/relative
            require(not any(p.is_symlink() for p in [target, *target.parents] if p != root and p.is_relative_to(root)), 'tools_path', 'Runtime target or parent is a symbolic link')
            atomic_copy(source, target, 0o755 if relative.endswith('watchdog-guard') else 0o644)
            parent = target.parent
            while parent != root and parent.is_relative_to(root):
                parent.chmod(0o755); parent = parent.parent
        for relative, source in files.items():
            require(sha256(root/relative) == sha256(source), 'tools_install_hash', 'Installed runtime file differs from signed package')
        engine.backend.configure_shared_mount(root, layout(c, discover(c), initialized=True))
        atomic_json(root/'etc/armhpc/ota-runtime.json', {'version': task['version'], 'maintenance': task['task_id']})
    if has_clock:
        from .clock_resources import configure_links
        configure_links(root, backup, task['rollback'])
    if 'etc/systemd/system/armhpc-ota-boot-diagnostics.service' in files:
        from .diagnostic_resources import configure
        configure(root, backup, task['rollback'])
    put_service(root, c)


def worker(engine):
    c = engine.config
    if not c.simulate and Path('/run/armhpc-ota-maintenance-recovery').exists():
        return {**status(c),'paused_by_recovery_boot':True}
    with engine.store.lock():
        task = record(c)
        if not task or task['stage'] in DONE: return status(c)
        device = discover(c); storage = layout(c, device, initialized=True); engine._require_shared_mount(storage)
        require(device['mode'] == 'rescue' and task['device_id'] == device['device_id'], 'tools_mode', 'Tool worker requires the matching Rescue device')
        job = engine.store.read(); require(not job or job['stage'] in TERMINAL, 'job_active', 'OTA task appeared during tool maintenance')
        try:
            task['stage'] = 'installing'; task['updated'] = now(); atomic_json(c.state/'maintenance/task.json', task)
            payload = Path(task['payload']); directory = payload.parent.parent
            signed = verify((directory/'manifest.json').read_bytes(), c.trust)
            require(sha256(directory/'runtime.tar.xz') == signed['artifact']['sha256'], 'tools_hash', 'Staged runtime changed')
            # Re-extract from the authenticated archive, so resume never trusts modified loose code.
            with tarfile.open(directory/'runtime.tar.xz', 'r:xz') as archive: safe_extract(archive, payload.parent)
            files = runtime_files(payload, device['architecture'])
            require(all(p.is_file() for p in files.values()), 'tools_resources', 'Missing runtime/helper files')
            for role in (task['backed_up'] if task['rollback'] else task['roles']):
                checkpoint = ('rollback-' if task['rollback'] else '') + role
                if checkpoint in task['completed']: continue
                with target_root(engine, storage, device, role) as root:
                    role_files = runtime_files(payload, device['architecture'], role)
                    require(all(p.is_file() for p in role_files.values()), 'tools_resources', 'Missing role runtime resources')
                    backup_and_install(engine, task, role, root, role_files)
                task['completed'].append(checkpoint); task['updated'] = now(); atomic_json(c.state/'maintenance/task.json', task)
            if not c.simulate:
                run('systemctl', 'daemon-reload')
                if 'etc/systemd/system/armhpc-clock-floor.service' in files:
                    from .clock_resources import activate
                    running_role = next(role for role in task['roles'] if storage['partitions'][role]['path'] == device['root'])
                    if running_role in task['backed_up']:
                        activate(c, c.state/'maintenance/backups'/task['task_id']/running_role, task['rollback'])
                if 'etc/systemd/system/armhpc-ota-boot-diagnostics.service' in files:
                    from .diagnostic_resources import activate as activate_diagnostics
                    role=next(role for role in task['roles'] if storage['partitions'][role]['path']==device['root'])
                    activate_diagnostics(c,c.state/'maintenance/backups'/task['task_id']/role,task['rollback'])
                clock=Path('/usr/lib/armhpc/clock_floor.py')
                if clock.is_file(): run('python3', clock, '--checkpoint')
            task['stage'] = 'rolled-back' if task['rollback'] else 'succeeded'; task.pop('error', None)
            (c.state/'maintenance/pending').unlink(missing_ok=True)
        except Exception as e:
            task['stage'] = 'incomplete'; task['error'] = {'code': getattr(e, 'code', 'maintenance_io'), 'message': str(e)}
        task['updated'] = now(); atomic_json(c.state/'maintenance/task.json', task)
    return status(c)


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--worker', action='store_true'); parser.add_argument('--bundle'); parser.add_argument('--rollback', action='store_true'); parser.add_argument('--request-id')
    args = parser.parse_args(argv)
    from .config import Config
    from .engine import Engine
    import json
    engine = Engine(Config.load())
    result = worker(engine) if args.worker else schedule(engine, args.bundle, args.rollback, args.request_id)
    print(json.dumps({'protocol': 1, 'ok': True, 'data': result}), flush=True)
    return 1 if result.get('maintenance', {}).get('stage') == 'incomplete' else 0

def retain_installed_runtime(config, root):
    """Keep a signed, maintained agent when restoring an older OS baseline."""
    task=record(config)
    if not task or task['stage']!='succeeded':return
    import ast
    marker=Path(root)/'usr/lib/armhpc-ota/armhpc_ota/__init__.py'
    tree=ast.parse(marker.read_text())
    version=next(n.value.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='__version__' for t in n.targets))
    if tuple(map(int,version.split('.')))>=tuple(map(int,task['version'].split('.'))):return
    payload=Path(task['payload']);directory=payload.parent.parent
    m=verify((directory/'manifest.json').read_bytes(),config.trust)
    require(sha256(directory/'runtime.tar.xz')==m['artifact']['sha256'],'tools_hash','Maintained runtime changed')
    with tarfile.open(directory/'runtime.tar.xz','r:xz') as archive:safe_extract(archive,payload.parent)
    role = 'rescue_a' if (Path(root)/'etc/armhpc/rescue-environment').is_file() else 'system'
    for relative,source in runtime_files(payload,discover(config)['architecture'],role).items():
        destination=Path(root)/relative
        require(not any(p.is_symlink() for p in [destination,*destination.parents] if p!=Path(root) and p.is_relative_to(Path(root))), 'tools_path', 'Retained runtime target or parent is a symbolic link')
        atomic_copy(source,destination,0o755 if relative.endswith('watchdog-guard') else 0o644)
        parent=(Path(root)/relative).parent
        while parent!=Path(root) and parent.is_relative_to(Path(root)):parent.chmod(0o755);parent=parent.parent
    if (payload/'compat/public-cli').is_dir():
        from .diagnostic_resources import configure
        configure(root)
    if (payload/'compat/clock-services').is_dir():
        from .clock_resources import configure_links
        configure_links(root)

if __name__ == "__main__":
    raise SystemExit(main())
