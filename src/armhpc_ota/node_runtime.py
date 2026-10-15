# SPDX-License-Identifier: GPL-3.0-only
"""Optional framework status; older agents/images need not supply these fields."""
import json
from pathlib import Path
import sys
import time
import subprocess


def report(config):
    library=Path('/usr/lib/armhpc')
    if config.simulate or not (library/'node_state.py').is_file():return {'provided':False}
    sys.path.insert(0,str(library))
    try:
        from node_state import kernel_status
        from network_ready import inspect,policy
        health=Path('/run/armhpc/health.json')
        value=json.loads(health.read_text()) if health.is_file() else {}
        state=value.get('state',{})
        installed=state.get('installed',{})
        age=max(0,time.monotonic()-value.get('monotonic_seconds',0)) if value else None
        return {'provided':True,'kernel_capabilities':kernel_status(),'management_network':inspect(policy()),
                'state_recovery':{'installed':{'ready':installed.get('ready'),
                    'errors':installed.get('errors',[])[:16],'missing':installed.get('missing',[])[:16]},
                    'services':list(state.get('desired',{}))[:64]},'swap':value.get('swap'),
                'health':{'last_success_epoch':value.get('epoch'),'age_seconds':age,
                          'stale':age is None or age>135,'reset_cause':value.get('reset_cause','unknown')}}
    except (OSError,ValueError,RuntimeError,ImportError,AttributeError,TypeError,KeyError,subprocess.SubprocessError) as error:
        return {'provided':True,'error':str(error)}


def firmware_health(target):
    from .errors import OTAError
    try:
        _firmware_health(target)
    except OTAError:
        raise
    except (OSError,ValueError,RuntimeError,ImportError,AttributeError,TypeError,KeyError,subprocess.SubprocessError) as error:
        raise OTAError('health_node_runtime', 'Node services are not ready: '+str(error)) from error


def _firmware_health(target):
    """Called after local services have started; it does not download or repair."""
    from .errors import require
    sys.path.insert(0,'/usr/lib/armhpc')
    from node_state import kernel_status,status
    from network_ready import inspect,policy
    require(kernel_status()['ready'],'health_kernel_capabilities','The running firmware lacks required kernel capabilities')
    require(inspect(policy())['ready'],'health_management','The selected management path is not ready')
    if target=='system':
        value=status()
        require(value['installed']['ready'],'health_state','Persistent program/configuration resources need repair')
        for unit,item in value.get('desired',{}).items():
            if item['enabled']:
                running=value.get('running',{}).get(unit,{})
                completed=(unit.endswith('.service') and running.get('Type')=='oneshot' and running.get('Result')=='success'
                           and running.get('ExecMainStatus')=='0' and int(running.get('ExecMainStartTimestampMonotonic','0'))>0)
                require(running.get('ActiveState')=='active' or completed,
                        'health_service','Restored service is not active: '+unit)
        path=Path('/etc/image-framework/k3s.json')
        if path.is_file():
            policy_value=json.loads(path.read_text())
            from kube_runtime import installed,runtime
            installation=installed(policy_value)
            if installation['desired']['enabled']:
                require(installation['ready'],'health_k3s','K3s installation differs from its selected version')
                require(runtime(policy_value)['ready'],'health_k3s_runtime','K3s service, CRI or server API is not healthy')
