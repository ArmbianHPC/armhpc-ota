# SPDX-License-Identifier: GPL-3.0-only
"""A durable write intent identifies partitions even after an interrupted ext4 write."""
from copy import deepcopy
from .errors import require
from .io import atomic_json, read_json, identifier, sha256

ROLES = {'system', 'rescue_a', 'rescue_b'}
PHYSICAL = ('path', 'parent', 'partuuid', 'start', 'size', 'maj:min')


def ledger(config):
    path = config.state / 'deployment-intents.json'
    value = read_json(path) if path.exists() else {'protocol': 1, 'targets': {}}
    require(value.get('protocol') == 1 and isinstance(value.get('targets'), dict),
            'deployment_intent', 'Invalid persistent partition write intent')
    return value


def begin(config, device, role, partition, job):
    require(role in ROLES and partition['label'] == config.board()['labels'][role],
            'deployment_target', 'Only system and Rescue root partitions can have write intents')
    require(partition['path'] != device['root'] and not any(partition.get('mountpoints') or []),
            'running_root', 'Cannot record a write intent for a mounted root')
    disk = next(node for node in device['blocks'] if node['path'] == partition['parent'])
    entry = {'device_id': device['device_id'], 'job_id': job['job_id'], 'release': job['release'],
             'partition': {key: partition.get(key) for key in (*PHYSICAL, 'uuid', 'label', 'fstype')},
             'disk': {key: disk.get(key) for key in ('path', 'size', 'serial', 'tran')},
             'manifest_sha256': sha256(config.state / 'manifests' / (job['release'] + '.json'))}
    value = ledger(config)
    value['targets'][role] = entry
    atomic_json(config.state / 'deployment-intents.json', value)


def _validate(config, device, role, entry):
    require(role in ROLES and entry.get('device_id') == device['device_id'],
            'deployment_identity', 'Write intent belongs to another device or protected partition')
    expected = entry['partition']
    require(expected.get('label') == config.board()['labels'][role] and expected.get('fstype') == ('ext4' if role == 'system' else config.board().get('rescue_fstype', 'ext4')),
            'deployment_target', 'Write intent does not describe a supported ext4 root')
    job_id, release = identifier(entry['job_id']), identifier(entry['release'])
    signed = config.state / 'manifests' / (release + '.json')
    require(signed.is_file() and sha256(signed) == entry['manifest_sha256'],
            'deployment_manifest', 'Write intent has lost its exact signed manifest')
    if job_id.startswith('bootstrap-'):
        journal = read_json(config.state / 'bootstrap.json')
        require(journal.get('device_id') == device['device_id'] and journal.get('initial_release') == release,
                'deployment_job', 'Bootstrap write intent has no matching migration journal')
    elif job_id.startswith('boot-'):
        journal=read_json(config.state/'boot-maintenance/task.json')
        require(journal['task_id']==job_id[5:] and journal['device_id']==device['device_id'] and
                journal['release']==release and role=='rescue_'+journal['inactive_slot'] and
                journal['stage'] in ('deploying-rescue','installing-entries','entry-switching','failed-needs-recovery','rolling-back'),
                'deployment_job','BOOT intent has no admitted diagnostic task')
    else:
        path = config.state / 'jobs'  / (job_id + '.json')
        require(path.is_file(), 'deployment_job', 'Write intent has no durable OTA task')
        job = read_json(path)
        require(job.get('write_started') is True and job.get('device_id') == device['device_id'] and
                job.get('release') == release and job.get('target') in
                ('all', 'system' if role == 'system' else 'rescue'),
                'deployment_job', 'Write intent differs from its authorized task')
    matches = [node for node in device['blocks'] if node.get('partuuid') == expected['partuuid']]
    require(len(matches) == 1, 'target_changed', 'Interrupted partition GUID is missing or ambiguous')
    actual = matches[0]
    require(actual.get('type') == 'part' and all(actual.get(key) == expected[key] for key in PHYSICAL),
            'target_changed', 'Interrupted partition path or geometry has changed')
    disks = [node for node in device['blocks'] if node['path'] == expected['parent']]
    require(len(disks) == 1 and all(disks[0].get(key) == value for key, value in entry['disk'].items()),
            'target_changed', 'Interrupted partition belongs to a different physical disk')
    require(actual.get('label') not in (config.board()['labels'][name] for name in ('boot', 'data', 'shared')),
            'protected_partition', 'Write intent now refers to a protected filesystem')
    return actual


def view(config, device):
    """Restore logical filesystem identity only for a previously admitted write target."""
    value = ledger(config)
    if not value['targets']:
        return device
    result = deepcopy(device)
    for role, entry in value['targets'].items():
        actual = _validate(config, device, role, entry)
        node = next(node for node in result['blocks'] if node['path'] == actual['path'])
        for key in ('label', 'uuid', 'fstype'):
            node[key] = entry['partition'][key]
        node['_deployment_role'] = role
    return result


def verify_target(config, device, partition):
    role = partition.get('_deployment_role')
    if role:
        value = ledger(config)
        require(role in value['targets'], 'deployment_intent', 'Interrupted write intent disappeared')
        return _validate(config, device, role, value['targets'][role])
    actual = next((node for node in device['blocks'] if node['path'] == partition['path']), None)
    require(actual and all(actual.get(key) == partition.get(key) for key in (*PHYSICAL, 'uuid', 'label', 'fstype')),
            'target_changed', 'Block target changed between planning and writing')
    return actual


def complete(config, role):
    value = ledger(config)
    if role in value['targets']:
        del value['targets'][role]
        atomic_json(config.state / 'deployment-intents.json', value)
