# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
"""Check independently versioned source inputs using the compatibility contract."""
import argparse
import json
from pathlib import Path
import re


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value):
        raise ValueError('Expected a numeric MAJOR.MINOR.PATCH version: ' + str(value))
    return tuple(map(int, value.split('.')))


def unique_mapping(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate compatibility field: ' + key)
        result[key] = value
    return result


def source_info(root, component):
    root = Path(root)
    version = (root / 'VERSION').read_text(encoding='utf-8').strip()
    parsed = version_tuple(version)
    path = root / 'COMPATIBILITY.json'
    legacy = not path.exists()
    if legacy:
        if parsed > (1, 2, 1):
            raise ValueError(component + ' needs COMPATIBILITY.json for versions after 1.2.1')
        policy = {'schema_version': 1, 'component': component, 'source_interface': 1,
                  'ota_protocol': 1, 'minimum_companion_version': '0.0.0'}
        if component == 'armbian-hpc':
            policy['minimum_agent'] = version
    else:
        policy = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique_mapping)
    if not isinstance(policy, dict) or policy.get('component') != component:
        raise ValueError('Compatibility component differs: ' + component)
    for field in ('schema_version', 'source_interface', 'ota_protocol'):
        if type(policy.get(field)) is not int or policy[field] != 1:
            raise ValueError(component + ' has an unsupported compatibility ' + field)
    version_tuple(policy.get('minimum_companion_version'))
    if component == 'armbian-hpc':
        version_tuple(policy.get('minimum_agent'))
    return {'version': version, 'policy': policy, 'legacy_contract': legacy}


def check_sources(ota_source, framework_source):
    sources = {'armhpc-ota': source_info(ota_source, 'armhpc-ota'),
               'armbian-hpc': source_info(framework_source, 'armbian-hpc')}
    for component, companion in (('armhpc-ota', 'armbian-hpc'), ('armbian-hpc', 'armhpc-ota')):
        required = sources[component]['policy']['minimum_companion_version']
        if version_tuple(sources[companion]['version']) < version_tuple(required):
            raise ValueError(component + ' requires ' + companion + ' >= ' + required +
                             '; selected ' + sources[companion]['version'])
    minimum_agent = sources['armbian-hpc']['policy']['minimum_agent']
    if version_tuple(sources['armhpc-ota']['version']) < version_tuple(minimum_agent):
        raise ValueError('Firmware requires OTA agent >= ' + minimum_agent)
    return {'schema_version': 1, 'source_interface': 1, 'ota_protocol': 1,
            'source_versions': {name: value['version'] for name, value in sources.items()},
            'minimum_agent': minimum_agent,
            'requirements': {name: value['policy'] for name, value in sources.items()},
            'legacy_contracts': [name for name, value in sources.items() if value['legacy_contract']]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ota-source', type=Path, required=True)
    parser.add_argument('--framework-source', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(check_sources(args.ota_source, args.framework_source), indent=2))
