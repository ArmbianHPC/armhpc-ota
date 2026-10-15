# SPDX-License-Identifier: GPL-3.0-only
"""Read-only board capabilities and Linux device observations."""
import importlib.util
from pathlib import Path
import sys

def report(config, device):
    board=config.board()
    result={'board':board['id'],'layout':board['layout'],'partition_table':board.get('partition_table','gpt'),
            'boot_fstype':board.get('boot_fstype','ext4'),'kernel_ota_supported':board.get('kernel_ota_supported',True),
            'boot_maintenance_supported':__import__('armhpc_ota.boot_platform',fromlist=['supported']).supported(board),
            'kernel_update_method':'boot-maintenance' if board['id']=='wxy-oesp-v22' else 'kexec',
            'installation_medium':device.get('installation_medium',False),
            'expected':board.get('hardware',{}),'hardware_verified':False}
    if config.simulate or board['id']!='wxy-oesp-v22': return result
    from .io import read_json
    for name,path in [('performance','/run/armhpc/performance.json'),('firmware','/etc/armhpc/firmware-inventory.json')]:
        try:
            result[name]=read_json(path) if Path(path).is_file() else {'available':False}
        except Exception as error:
            result[name]={'available':False,'error':str(error)}
    sys.path.insert(0,'/usr/lib/armhpc')
    for name, action in [('network_ports',lambda m:m.report()),('fan',lambda m:m.Fan().status())]:
        try:
            path=Path('/usr/lib/armhpc')/(name+'.py')
            spec=importlib.util.spec_from_file_location('armhpc_hardware_'+name,path)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            result[name]=action(module)
        except Exception as error: result[name]={'available':False,'error':str(error)}
    return result
