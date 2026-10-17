# SPDX-License-Identifier: GPL-3.0-only
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest


def load():
    path = Path(__file__).resolve().parents[1] / 'tools/release-policy.py'
    spec = importlib.util.spec_from_file_location('ota_release_policy', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_id_checks_the_expected_tag():
    module = load()
    with patch.object(module.subprocess, 'check_output', return_value='{"tag_name":"v0.0.1"}') as query:
        with pytest.raises(ValueError, match='requested tag'):
            module.release('owner/repo', 'v1.2.0', 42)
    assert query.call_args.args[0][-1] == 'repos/owner/repo/releases/42'


def test_three_package_contract_and_existing_bytes_are_immutable(tmp_path):
    module = load()
    for name in module.files('1.2.0'):
        (tmp_path / name).write_bytes(b'package')
    notes = tmp_path / 'v1.2.0.md'
    notes.write_text('Changes')
    notes.with_name('v1.2.0.zh-CN.md').write_text('Changes')
    assets = [{'name': p.name, 'size': p.stat().st_size, 'digest': 'sha256:' + module.sha256(p)}
              for p in (tmp_path / name for name in module.files('1.2.0'))]
    assets[0]['digest'] = 'sha256:' + '0' * 64
    with patch.object(module, 'release', return_value={'id': 42, 'assets': assets}), patch.object(module.subprocess, 'run') as mutate:
        with pytest.raises(ValueError, match='Existing versioned package'):
            module.update('owner/repo', 'v1.2.0', tmp_path, apply=True, notes=notes, release_id=42)
    mutate.assert_not_called()


def test_metadata_and_publish_updates_preserve_version_tag(tmp_path):
    module = load()
    asset = tmp_path / 'package.tar.xz'
    asset.write_bytes(b'payload')
    notes = tmp_path / 'v1.2.0.md'
    notes.write_text('Changes')
    notes.with_name('v1.2.0.zh-CN.md').write_text('Changes')
    current = {'id': 42, 'name': 'v1.2.0', 'tag_name': 'v1.2.0', 'draft': True,
        'prerelease': False, 'upload_url': 'https://uploads.github.com/repos/owner/repo/releases/42/assets{?name,label}',
        'html_url': 'https://github.com/owner/repo/releases/tag/v1.2.0',
        'assets': [{'name': asset.name, 'size': asset.stat().st_size, 'digest': 'sha256:' + module.sha256(asset)}]}
    public = {**current, 'draft': False}
    with patch.object(module, 'release', side_effect=[current, current, current, public]), patch.object(module.subprocess, 'run') as mutate, patch.object(module, 'release_history', return_value=[]):
        result = module.publish_packages('owner/repo', 'v1.2.0', [asset], notes,
            apply=True, release_id=42, publish=True)
    updates = [json.loads(call.kwargs['input']) for call in mutate.call_args_list if 'PATCH' in call.args[0]]
    assert len(updates) == 2 and all(row['tag_name'] == 'v1.2.0' for row in updates)
    assert updates[0]['draft'] is True and updates[1]['draft'] is False
    assert result['draft'] is False


def test_revision_release_uses_distinct_immutable_asset_names(tmp_path):
    module=load()
    tag='v1.2.3-r7'
    notes=tmp_path/(tag+'.md');notes.write_text('Backup export and shared storage.')
    notes.with_name(tag+'.zh-CN.md').write_text('备份导出和共享空间。')
    for name in module.files(tag[1:]):(tmp_path/name).write_bytes(b'revision-package')
    current={'id':7,'tag_name':tag,'name':tag,'assets':[],'draft':True,'prerelease':False}
    with patch.object(module,'release',return_value=current):
        result=module.update('owner/repo',tag,tmp_path,notes=notes)
    assert result['title']==tag and len(result['packages'])==3
    assert all('1.2.3-r7' in p['file'] for p in result['packages'])


@pytest.mark.parametrize('tag,history', [
    ('v1.2.3-r9', ['v1.2.2']),
    ('v1.2.3-r17', ['v1.2.3-r1', 'v1.2.3-r9']),
    ('v1.2.4-r3', ['v1.2.3-r17']),
    ('v1.3.0-r2', ['v1.2.3-r17']),
    ('v2.0.0-r1', ['v1.3.0-r2']),
    ('v1.2.3-r9', ['v1.2.3-r9']),
])
def test_consecutive_base_and_skipped_revision_numbers(tag, history):
    module = load()
    module.check_sequence(tag, history)


@pytest.mark.parametrize('tag,history', [
    ('v1.2.5-r1', ['v1.2.3-r9']),
    ('v1.4.0-r1', ['v1.2.3-r9']),
    ('v3.0.0-r1', ['v1.2.3-r9']),
    ('v1.3.1-r1', ['v1.2.3-r9']),
    ('v2.1.0-r1', ['v1.2.3-r9']),
    ('v1.2.3-r8', ['v1.2.3-r9']),
    ('v1.2.2-r19', ['v1.2.3-r9']),
    ('v1.2.3-R9', ['v1.2.2']),
    ('v1.2.3-r0', ['v1.2.2']),
    ('v1.2.3-r09', ['v1.2.2']),
])
def test_invalid_release_order_or_revision_is_rejected(tag, history):
    module = load()
    with pytest.raises(ValueError):
        module.check_sequence(tag, history)


def test_publish_sequence_refusal_never_mutates_remote(tmp_path):
    module = load()
    asset = tmp_path / 'package.tar.xz'
    asset.write_bytes(b'payload')
    notes = tmp_path / 'v1.2.5-r1.md'
    notes.write_text('Changes')
    notes.with_name('v1.2.5-r1.zh-CN.md').write_text('Changes')
    with patch.object(module, 'release_history', return_value=['v1.2.3-r9']), patch.object(module.subprocess, 'run') as mutate:
        with pytest.raises(ValueError, match='consecutive'):
            module.publish_packages('owner/repo', 'v1.2.5-r1', [asset], notes, apply=True, publish=True)
    mutate.assert_not_called()
