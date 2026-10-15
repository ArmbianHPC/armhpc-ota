# SPDX-License-Identifier: GPL-3.0-only
"""Validate tracked community/CI configuration without loading device inputs."""
import json
from pathlib import Path
import re
import subprocess
import yaml


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError('Duplicate YAML key: ' + str(key))
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def main():
    root = Path(__file__).resolve().parents[1]
    files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    documents = []
    workflows = []
    for name in filter(None, files):
        path = root / name
        if not path.is_file():
            continue
        if name.startswith('.github/') and path.suffix in ('.yml', '.yaml'):
            value = yaml.load(path.read_text(encoding='utf-8'), Loader=UniqueLoader)
            documents.append(name)
            if name.startswith('.github/workflows/'):
                workflows.append((name, value))
    if not workflows:
        raise ValueError('No tracked workflow')
    peer_file = root / '.github/companion-source.json'
    peer = json.loads(peer_file.read_text()) if peer_file.exists() else None
    peer_refs = []
    for name, workflow in workflows:
        if 'pull_request_target' in workflow.get('on', workflow.get(True, {})):
            raise ValueError('Privileged PR trigger in ' + name)
        if workflow.get('permissions', {}).get('contents') != 'read':
            raise ValueError('Workflow contents permission must be read: ' + name)
        for job in workflow['jobs'].values():
            for step in job.get('steps', []):
                action = step.get('uses')
                if action and not re.fullmatch(r'[^@]+@[0-9a-f]{40}', action):
                    raise ValueError('Action must use a full commit: ' + action)
                options = step.get('with', {})
                if peer and options.get('repository') == peer['repository']:
                    peer_refs.append(options.get('ref'))
    if peer and (not peer_refs or any(ref != peer['ref'] for ref in peer_refs)):
        raise ValueError('Workflow companion refs differ from companion-source.json')
    print(json.dumps({'passed': True, 'yaml_files': len(documents), 'workflows': len(workflows),
                      'companion_checkouts': len(peer_refs)}))


if __name__ == '__main__':
    main()
