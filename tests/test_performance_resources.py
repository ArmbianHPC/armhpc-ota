# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from armhpc_ota import performance_resources as resources
from armhpc_ota.errors import OTAError


def test_original_disabled_state_survives_retry_and_rollback(tmp_path):
    root, backup = tmp_path/'root', tmp_path/'backup'
    resources.capture(SimpleNamespace(simulate=True),root,backup)
    resources.configure(root,backup)
    resources.capture(SimpleNamespace(simulate=True),root,backup)
    for unit,target in resources.UNITS.items():
        assert (root/'etc/systemd/system'/target/unit).readlink() == Path('../'+unit)
    resources.configure(root,backup,rollback=True)
    for unit,target in resources.UNITS.items():
        assert not (root/'etc/systemd/system'/target/unit).is_symlink()


def test_existing_enable_link_is_restored(tmp_path):
    link=tmp_path/'root/etc/systemd/system/timers.target.wants/armhpc-performance.timer'
    link.parent.mkdir(parents=True)
    link.symlink_to('/etc/systemd/system/armhpc-performance.timer')
    resources.capture(SimpleNamespace(simulate=True),tmp_path/'root',tmp_path/'backup')
    resources.configure(tmp_path/'root',tmp_path/'backup')
    resources.configure(tmp_path/'root',tmp_path/'backup',rollback=True)
    assert str(link.readlink()) == '/etc/systemd/system/armhpc-performance.timer'


def test_real_file_at_enable_target_is_rejected(tmp_path):
    link=tmp_path/'root/etc/systemd/system/timers.target.wants/armhpc-performance.timer'
    link.parent.mkdir(parents=True)
    link.write_text('unrelated file')
    with pytest.raises(OTAError):
        resources.capture(SimpleNamespace(simulate=True),tmp_path/'root',tmp_path/'backup')
    assert link.read_text() == 'unrelated file'


def test_enable_directory_cannot_escape_offline_root(tmp_path):
    outside=tmp_path/'outside'
    outside.mkdir()
    folder=tmp_path/'root/etc/systemd/system'
    folder.mkdir(parents=True)
    (folder/'timers.target.wants').symlink_to(outside)
    with pytest.raises(OTAError):
        resources.capture(SimpleNamespace(simulate=True),tmp_path/'root',tmp_path/'backup')
    assert list(outside.iterdir())==[]


def test_rollback_can_restore_original_absent_units(tmp_path):
    resources.capture(SimpleNamespace(simulate=True),tmp_path/'root',tmp_path/'backup')
    with patch.object(resources.subprocess,'run',return_value=SimpleNamespace(returncode=5)) as command:
        resources.activate(SimpleNamespace(simulate=False),tmp_path/'backup',rollback=True)
    assert command.call_count==2


def test_baseline_retention_enables_both_signed_units(tmp_path):
    units=tmp_path/'etc/systemd/system'
    units.mkdir(parents=True)
    for unit in resources.UNITS:
        (units/unit).write_text('signed unit')
    resources.enable(tmp_path)
    resources.enable(tmp_path)
    for unit,target in resources.UNITS.items():
        assert (units/target/unit).readlink()==Path('../'+unit)
