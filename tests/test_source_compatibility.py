# SPDX-FileCopyrightText: 2026 ARMHPC contributors
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'tools/compatibility.py'
spec = importlib.util.spec_from_file_location('source_compatibility', HELPER)
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)


def sources(tmp_path, ota='1.2.1', framework='1.2.1'):
    roots = []
    for component, version in (('armhpc-ota', ota), ('armbian-hpc', framework)):
        root = tmp_path / component
        root.mkdir()
        (root / 'VERSION').write_text(version)
        policy = {'schema_version': 1, 'component': component, 'source_interface': 1,
                  'ota_protocol': 1, 'minimum_companion_version': '1.2.1'}
        if component == 'armbian-hpc':
            policy['minimum_agent'] = '1.2.1'
        (root / 'COMPATIBILITY.json').write_text(json.dumps(policy))
        roots.append(root)
    return roots


def change(root, **fields):
    path = root / 'COMPATIBILITY.json'
    value = json.loads(path.read_text())
    path.write_text(json.dumps({**value, **fields}))


@pytest.mark.parametrize('ota,framework', [('1.2.2', '1.2.1'), ('1.2.1', '1.2.2'),
                                         ('1.2.10', '1.2.2'), ('2.0.0', '1.2.1')])
def test_independent_versions_preserve_explicit_agent_floor(tmp_path, ota, framework):
    result = compat.check_sources(*sources(tmp_path, ota, framework))
    assert result['source_versions'] == {'armhpc-ota': ota, 'armbian-hpc': framework}
    assert result['minimum_agent'] == '1.2.1'
    assert result['ota_protocol'] == 1


@pytest.mark.parametrize('companion', [0, 1])
def test_new_source_can_use_published_legacy_companion(tmp_path, companion):
    versions = ['1.2.2', '1.2.2']
    versions[companion] = '1.2.1'
    roots = sources(tmp_path, *versions)
    (roots[companion] / 'COMPATIBILITY.json').unlink()
    result = compat.check_sources(*roots)
    assert result['legacy_contracts'] == [roots[companion].name]


def test_both_published_sources_remain_readable(tmp_path):
    roots = sources(tmp_path)
    for root in roots:
        (root / 'COMPATIBILITY.json').unlink()
    assert len(compat.check_sources(*roots)['legacy_contracts']) == 2


@pytest.mark.parametrize('owner', [0, 1])
def test_minimum_companion_is_enforced_in_both_directions(tmp_path, owner):
    roots = sources(tmp_path, '1.2.9', '1.2.9')
    change(roots[owner], minimum_companion_version='1.2.10')
    with pytest.raises(ValueError, match='requires .* >= 1.2.10'):
        compat.check_sources(*roots)


def test_feature_requirement_can_raise_minimum_agent(tmp_path):
    roots = sources(tmp_path, '1.2.9', '1.2.2')
    change(roots[1], minimum_agent='1.2.10')
    with pytest.raises(ValueError, match='agent >= 1.2.10'):
        compat.check_sources(*roots)
    (roots[0] / 'VERSION').write_text('1.2.10')
    assert compat.check_sources(*roots)['minimum_agent'] == '1.2.10'


@pytest.mark.parametrize('field,value', [('schema_version', 2), ('source_interface', 2),
                                       ('ota_protocol', 2), ('ota_protocol', True),
                                       ('minimum_companion_version', '1.2'),
                                       ('component', 'wrong-component')])
def test_unknown_interfaces_and_invalid_contracts_are_rejected(tmp_path, field, value):
    roots = sources(tmp_path)
    change(roots[0], **{field: value})
    with pytest.raises(ValueError):
        compat.check_sources(*roots)


def test_uncontracted_future_source_is_not_assumed_compatible(tmp_path):
    roots = sources(tmp_path, '1.2.2')
    (roots[0] / 'COMPATIBILITY.json').unlink()
    with pytest.raises(ValueError, match='needs COMPATIBILITY.json'):
        compat.check_sources(*roots)


def test_duplicate_contract_field_is_rejected(tmp_path):
    roots = sources(tmp_path)
    path = roots[0] / 'COMPATIBILITY.json'
    path.write_text(path.read_text()[:-1] + ',"ota_protocol":2}')
    with pytest.raises(ValueError, match='Duplicate compatibility field'):
        compat.check_sources(*roots)


@pytest.mark.parametrize('value', ['1.2', 'v1.2.1', '1.2.1-rc1', '01.2.1', None])
def test_only_complete_numeric_versions_are_compared(value):
    with pytest.raises(ValueError):
        compat.version_tuple(value)


def test_existing_repository_contract_is_valid():
    component = 'armhpc-ota' if (ROOT / 'pyproject.toml').is_file() else 'armbian-hpc'
    assert compat.source_info(ROOT, component)['policy']['ota_protocol'] == 1
