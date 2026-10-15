# SPDX-License-Identifier: GPL-3.0-only
from copy import deepcopy
import uuid

import pytest
import test_oesp_boot_maintenance as fixtures
from armhpc_ota import deployment
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json, read_json


@pytest.fixture
def admitted_system():
    fixture = fixtures.OespBootMaintenance()
    fixture.setUp()
    try:
        device = read_json(fixture.r / 'device.json')
        disk = next(node for node in device['blocks'] if node.get('tran') == 'sata')
        disk.update(serial=None, wwn='0x5000000000000001')
        target = next(node for node in device['blocks'] if node.get('fixture_role') == 'system')
        manifest = fixture.e.manifest(location=str(fixture.manifest_path))
        job = {'job_id': str(uuid.uuid4()), 'release': manifest['release'], 'device_id': device['device_id'],
               'target': 'system', 'stage': 'failed-recoverable', 'write_started': True,
               'plan': {'disk_identity': {disk['path']: {'serial': None, 'size': disk['size'], 'wwn': disk['wwn']}}}}
        atomic_json(fixture.c.state / 'jobs' / (job['job_id'] + '.json'), job)
        deployment.begin(fixture.c, device, 'system', target, job)
        broken = deepcopy(device)
        next(node for node in broken['blocks'] if node.get('fixture_role') == 'system').update(label=None, uuid=None, fstype=None)
        yield fixture, broken, job
    finally:
        fixture.tearDown()


def test_new_intent_saves_the_physical_wwn(admitted_system):
    fixture, _, _ = admitted_system
    assert deployment.ledger(fixture.c)['targets']['system']['disk']['wwn'] == '0x5000000000000001'


@pytest.mark.parametrize('replacement', ['0x5000000000000002', None])
def test_changed_or_missing_wwn_refuses_interrupted_target(admitted_system, replacement):
    fixture, device, _ = admitted_system
    next(node for node in device['blocks'] if node.get('tran') == 'sata')['wwn'] = replacement
    with pytest.raises(OTAError, match='Physical|physical'):
        deployment.view(fixture.c, device)


def test_unchanged_wwn_only_disk_can_resume(admitted_system):
    fixture, device, _ = admitted_system
    logical = deployment.view(fixture.c, device)
    target = next(node for node in logical['blocks'] if node.get('fixture_role') == 'system')
    assert target['_deployment_role'] == 'system'
    assert target['label'] == 'OESP_ROOT'


def test_legacy_intent_uses_original_job_wwn(admitted_system):
    fixture, device, _ = admitted_system
    ledger = deployment.ledger(fixture.c)
    ledger['targets']['system']['disk'].pop('wwn', None)
    atomic_json(fixture.c.state / 'deployment-intents.json', ledger)
    assert deployment.view(fixture.c, device)['device_id'] == device['device_id']
    next(node for node in device['blocks'] if node.get('tran') == 'sata')['wwn'] = '0x5000000000000002'
    with pytest.raises(OTAError, match='Physical|physical'):
        deployment.view(fixture.c, device)


def test_serial_only_legacy_intent_remains_readable(admitted_system):
    fixture, device, job = admitted_system
    disk = next(node for node in device['blocks'] if node.get('tran') == 'sata')
    disk.update(serial='same-sata-serial', wwn=None)
    ledger = deployment.ledger(fixture.c)
    ledger['targets']['system']['disk'].update(serial=disk['serial'])
    ledger['targets']['system']['disk'].pop('wwn', None)
    atomic_json(fixture.c.state / 'deployment-intents.json', ledger)
    job['plan']['disk_identity'][disk['path']] = {'serial': disk['serial'], 'size': disk['size']}
    atomic_json(fixture.c.state / 'jobs' / (job['job_id'] + '.json'), job)
    assert deployment.view(fixture.c, device)['device_id'] == device['device_id']


def test_ledger_wwn_cannot_override_the_original_plan(admitted_system):
    fixture, device, _ = admitted_system
    ledger = deployment.ledger(fixture.c)
    ledger['targets']['system']['disk']['wwn'] = '0x5000000000000002'
    atomic_json(fixture.c.state / 'deployment-intents.json', ledger)
    next(node for node in device['blocks'] if node.get('tran') == 'sata')['wwn'] = '0x5000000000000002'
    with pytest.raises(OTAError, match='original physical disk plan'):
        deployment.view(fixture.c, device)


def test_legacy_wwn_only_intent_without_original_identity_is_refused(admitted_system):
    fixture, device, job = admitted_system
    ledger = deployment.ledger(fixture.c)
    ledger['targets']['system']['disk'].pop('wwn', None)
    atomic_json(fixture.c.state / 'deployment-intents.json', ledger)
    job['plan']['disk_identity'].pop('/dev/sda')
    atomic_json(fixture.c.state / 'jobs' / (job['job_id'] + '.json'), job)
    with pytest.raises(OTAError, match='verifiable SATA serial number or WWN'):
        deployment.view(fixture.c, device)
