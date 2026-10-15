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
    with patch.object(module, 'release', side_effect=[current, current, current, public]), patch.object(module.subprocess, 'run') as mutate:
        result = module.publish_packages('owner/repo', 'v1.2.0', [asset], notes,
            apply=True, release_id=42, publish=True)
    updates = [json.loads(call.kwargs['input']) for call in mutate.call_args_list if 'PATCH' in call.args[0]]
    assert len(updates) == 2 and all(row['tag_name'] == 'v1.2.0' for row in updates)
    assert updates[0]['draft'] is True and updates[1]['draft'] is False
    assert result['draft'] is False
