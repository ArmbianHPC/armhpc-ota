# SPDX-License-Identifier: GPL-3.0-only
"""Stable JSON CLI shared by SSH terminals and the WPF client."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
from . import __version__
from .config import Config
from .engine import Engine, public_job
from .errors import OTAError, require
from . import bootstrap


def parser():
    result = argparse.ArgumentParser(prog=os.environ.get('ARMHPC_OTA_PROG', 'armhpc ota'),
                                     description='ARMHPC signed dual-system network OTA')
    result.add_argument('--version', action='version', version=__version__)
    # Shared arguments are copied to subparsers so both placements work.
    def common(target, suppress=False):
        default = argparse.SUPPRESS if suppress else None
        target.add_argument('--json', action='store_true', default=argparse.SUPPRESS if suppress else False,
                            help='Emit protocol-v1 JSON; watch uses one JSON document per line')
        target.add_argument('--config', default=default, help='Local device configuration path')
        target.add_argument('--simulate-root', default=default, help='Explicit non-block directory fixture')
        target.add_argument('--yes', action='store_true', default=argparse.SUPPRESS if suppress else False,
                            help='Accept the displayed write/reboot plan without a prompt')
    common(result)
    sub = result.add_subparsers(dest='command', required=True,
                               metavar='{bootstrap,check,plan,download,apply,status,logs,cancel,recover,source,doctor,retry,tools,receive}')
    for command in ('bootstrap', 'check', 'plan', 'download', 'apply', 'status', 'logs', 'cancel', 'recover'):
        child = sub.add_parser(command)
        common(child, True)
        if command in ('plan', 'download', 'apply', 'recover'):
            child.add_argument('--release')
            child.add_argument('--manifest', help='Signed manifest URL or local file')
            child.add_argument('--target', choices=('all', 'system', 'rescue'), default='all')
            if command == 'plan':
                child.add_argument('--recovery', action='store_true', help='Preview an explicit compatible recovery/downgrade')
        if command == 'bootstrap':
            child.add_argument('--apply', action='store_true', help='Execute the previewed migration')
            child.add_argument('--manifest', help='Signed initial complete baseline')
            child.add_argument('--anchor-manifest', help='Signed fixed-bootstrap bundle')
        if command in ('apply', 'recover'):
            child.add_argument('--local-only', action='store_true', help='Deploy verified host-uploaded payloads; never fetch URLs')
            child.add_argument('--request-id', help='Canonical UUID for safe submission retry after an SSH disconnect')
        if command in ('status', 'logs', 'cancel'):
            child.add_argument('--job')
        if command in ('status', 'logs'):
            child.add_argument('--watch', action='store_true')
            child.add_argument('--interval', type=float, default=2)
    source = sub.add_parser('source'); common(source, True)
    source.add_argument('action', choices=('show', 'set', 'test'))
    source.add_argument('--url'); source.add_argument('--tools-source'); source.add_argument('--allow-http', action='store_true')
    source.add_argument('--ca'); source.add_argument('--origin', action='append', default=[])
    doctor = sub.add_parser('doctor'); common(doctor, True)
    retry = sub.add_parser('retry'); common(retry, True); retry.add_argument('--job', required=True)
    tools = sub.add_parser('tools'); common(tools, True)
    tools.add_argument('action', choices=('status', 'update')); tools.add_argument('--bundle'); tools.add_argument('--rollback', action='store_true'); tools.add_argument('--request-id')
    receive = sub.add_parser('receive'); common(receive, True)
    receive.add_argument('--manifest',required=True); receive.add_argument('--target',choices=('all','system','rescue'),default='all')
    receive.add_argument('--request-id',required=True);receive.add_argument('--phase',choices=('prepare','commit'),default='prepare')
    boot = sub.add_parser('boot'); common(boot, True)
    boot.add_argument('action', choices=('plan', 'enter', 'apply', 'status', 'rollback', 'restore'))
    boot.add_argument('--bundle'); boot.add_argument('--request-id')
    boot.add_argument('--exported-backup-sha256'); boot.add_argument('--commit', action='store_true')
    boot.add_argument('--execute',action='store_true',help='Restore the task-bound BOOT recovery image after preview')
    # Private service operations are deliberately not extra public shell commands.
    internal = sub.add_parser('_service', help=argparse.SUPPRESS)
    common(internal, True)
    internal.add_argument('operation', choices=('worker', 'confirm', 'boot', 'trial-failed', 'boot-maintenance'))
    sub._choices_actions[:] = [action for action in sub._choices_actions if action.dest != '_service']
    return result


def emit(value, json_output):
    document = {'protocol': 1, 'ok': True, 'data': value}
    print(json.dumps(document if json_output else value, ensure_ascii=False, indent=None if json_output else 2), flush=True)


def approval(args, plan):
    if args.yes:
        return
    require(not args.json and sys.stdin.isatty(), 'confirmation_required', 'Use --yes after reviewing the JSON plan')
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    require(input('Apply this plan and reboot as needed? [y/N]: ').strip().lower() in ('y', 'yes'),
            'declined', 'Upgrade was not started')


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        config = Config.load(args.config, args.simulate_root)
        engine = Engine(config)
        if args.command == 'boot':
            from . import boot_maintenance as bm
            if args.action == 'status': result = bm.status(config)
            elif args.action == 'plan':
                require(args.bundle, 'boot_bundle', 'Supply --bundle'); result = bm.plan(engine,args.bundle)
            elif args.action == 'enter':
                require(args.bundle,'boot_bundle','Supply the verified firmware bundle before entering Rescue')
                approval(args,{'reboot_to_confirmed_rescue':True,'request_id':args.request_id})
                result=bm.enter(engine,args.bundle,args.request_id)
            elif args.action == 'restore':
                from .boot_recovery import restore
                result=restore(engine,args.request_id)
                if args.execute:
                    approval(args,result);result=restore(engine,args.request_id,True)
            else:
                approval(args, {'BOOT_maintenance':args.action,'private_recovery_export_required':True})
                result = bm.rollback(engine,args.request_id) if args.action == 'rollback' else bm.apply(engine,args.bundle,args.request_id,args.exported_backup_sha256,args.commit)
        elif args.command == 'receive':
            from .receive import receive
            result=receive(engine,args.manifest,args.target,args.request_id,args.phase)
        elif args.command == 'source':
            from . import sources
            if args.action == 'set':
                require(config.simulate or os.geteuid() == 0, 'root', 'Changing source requires root')
                require(args.url, 'source_url', 'Supply --url')
                approval(args, {'source': args.url, 'allow_http': args.allow_http, 'ca_import': bool(args.ca)})
                result = sources.set_source(engine, args.url, args.allow_http, args.ca, args.tools_source, args.origin)
            else: result = sources.show(config) if args.action == 'show' else sources.test(engine)
        elif args.command == 'doctor':
            from .doctor import inspect
            result = inspect(engine)
        elif args.command == 'retry':
            require(config.simulate or os.geteuid() == 0, 'root', 'Retry requires root')
            approval(args, {'retry_job': args.job, 'write_started': False})
            result = engine.retry(args.job)
        elif args.command == 'tools':
            from . import maintenance
            if args.action == 'status': result = maintenance.status(config)
            else:
                require(config.simulate or os.geteuid() == 0, 'root', 'Tool maintenance requires root')
                approval(args, {'bundle': args.bundle, 'rollback': args.rollback, 'normal_requires_rescue': True})
                result = maintenance.schedule(engine, args.bundle, args.rollback, args.request_id)
        elif args.command == 'bootstrap':
            plan = bootstrap.preview(config)
            if args.apply and plan.get('factory_prepartitioned'):
                require(plan['complete'], 'bootstrap_incomplete', 'Factory initialization is incomplete')
                result = plan
            elif args.apply:
                asset_dir = config.bootstrap_assets if (config.bootstrap_assets / 'baseline.manifest.json').is_file() else Path('/boot/armhpc-ota-bootstrap')
                args.manifest = args.manifest or str(asset_dir / 'baseline.manifest.json')
                args.anchor_manifest = args.anchor_manifest or str(asset_dir / 'anchor.manifest.json')
                require((Path(args.manifest).is_file() or args.manifest.startswith(('https://', 'http://'))) and
                        (Path(args.anchor_manifest).is_file() or args.anchor_manifest.startswith(('https://', 'http://'))),
                        'bootstrap_assets', 'Provide signed manifests or use the image-bundled bootstrap assets')
                approval(args, plan)
                result = bootstrap.execute(engine, engine.manifest(location=args.manifest), args.anchor_manifest)
            else:
                result = plan
        elif args.command == 'check':
            result = engine.check()
        elif args.command in ('plan', 'download', 'apply', 'recover'):
            manifest = engine.manifest(args.release, args.manifest, args.target,
                                       args.command == 'recover' or (args.command == 'plan' and args.recovery))
            if args.command == 'plan':
                result = engine.plan(manifest, args.target, args.recovery)
            elif args.command == 'download':
                result = engine.download(manifest, args.target)
            else:
                recovery = args.command == 'recover'
                existing = engine.existing_request(manifest, args.target, recovery, args.request_id,args.local_only)
                if existing:
                    result = engine.apply(manifest, args.target, recovery, args.request_id,args.local_only)
                else:
                    plan = engine.plan(manifest, args.target, recovery)
                    approval(args, plan)
                    result = engine.apply(manifest, args.target, recovery, args.request_id,args.local_only)
        elif args.command in ('status', 'logs'):
            require(args.interval >= 0.2, 'interval', 'Watch interval must be at least 0.2 seconds')
            delivered = 0
            while True:
                status = engine.status(args.job)
                result = status if args.command == 'status' else {'job_id': status['job']['job_id'] if status['job'] else None,
                           'events': (status['job']['events'][delivered:] if status['job'] else [])}
                if status['job']:
                    delivered = len(status['job']['events'])
                emit(result, args.json)
                if not args.watch or not status['job'] or status['job']['stage'] in ('succeeded', 'failed-recoverable', 'cancelled'):
                    return 0
                time.sleep(args.interval)
        elif args.command == 'cancel':
            result = engine.cancel(args.job)
        else:
            require(config.simulate or os.geteuid() == 0, 'root', 'Service operation requires root')
            if args.operation == 'boot-maintenance':
                from .boot_maintenance import worker
                result = worker(engine)
            elif args.operation == 'worker':
                result = engine.worker()
            elif args.operation == 'confirm':
                result = engine.confirm()
            elif args.operation == 'boot':
                from .boot import select
                result = select(config)
            else:
                job = engine.store.read()
                result = engine.store.fail(job, OTAError('trial_failed', 'Bootstrap detected a failed trial')) if job else None
        if result and isinstance(result, dict) and 'job_id' in result and 'manifest' in result:
            result = public_job(result)
        emit(result, args.json)
        if args.command == '_service' and args.operation in ('worker', 'confirm') and result and result.get('stage') == 'failed-recoverable':
            return 1
        return 0
    except OTAError as error:
        if args.json:
            print(json.dumps({'protocol': 1, 'ok': False, 'error': {'code': error.code, 'message': str(error),
                                                                   'details': error.details}}, ensure_ascii=False))
        else:
            print(f'OTA refused [{error.code}]: {error}', file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError) as error:
        if args.json:
            print(json.dumps({'protocol': 1, 'ok': False, 'error': {'code': 'io_or_config', 'message': str(error)}}))
        else:
            print('OTA I/O/configuration error: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
