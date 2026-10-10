# SPDX-License-Identifier: GPL-3.0-only
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
import os
from .errors import require
from .io import read_json, parse_json, identifier


@dataclass
class Config:
    allowed_origins: list = field(default_factory=list)
    allow_http: bool = False
    ca_file: Path | None = None
    state: Path = Path('/var/lib/armhpc/ota')
    cache: Path = Path('/data/armhpc-ota/cache')
    trust: Path = Path('/etc/armhpc/ota-trust.d')
    feed: str = 'https://github.com/chens32/armbian-hpc/releases/latest/download/ota-index.json'
    tools_source: str = 'https://github.com/ArmbianHPC/armhpc-ota/releases'
    profile: str = 'wxy-oect-original'
    storage_layout: str | None = None
    simulate: Path | None = None
    reboot: bool = True
    health_timeout: int = 180
    hardware_policy: str = 'verified'
    bootstrap_assets: Path = Path('/usr/share/armhpc/ota/bootstrap')

    @classmethod
    def load(cls, path=None, simulate=None):
        config = cls()
        source = Path(path or '/etc/armhpc/ota.json')
        if source.exists():
            data = read_json(source)
            for key in ('state', 'cache', 'trust', 'bootstrap_assets'):
                if key in data:
                    require(Path(data[key]).is_absolute(), 'config', 'Config paths must be absolute')
                    setattr(config, key, Path(data[key]))
            for key in ('feed', 'tools_source', 'profile', 'health_timeout', 'hardware_policy', 'storage_layout', 'allowed_origins', 'allow_http'):
                if key in data:
                    setattr(config, key, data[key])
        require(config.hardware_policy in ('verified', 'development'), 'hardware_policy', 'Unknown hardware authorization policy')
        if simulate:
            config.simulate = Path(simulate).resolve()
            require(config.simulate.is_dir() and config.simulate != Path(config.simulate.anchor),
                    'fixture_root', 'Simulation requires an explicit non-root directory fixture')
            for name in ('roots', 'shared', 'data', 'trust'):
                candidate = config.simulate / name
                require(not candidate.is_symlink() and candidate.resolve().is_relative_to(config.simulate),
                        'fixture_path', 'Simulation directories must stay inside the explicit fixture')
            config.state = config.simulate / 'shared'
            config.cache = config.simulate / 'data/cache'
            config.trust = config.simulate / 'trust'
            config.bootstrap_assets = config.simulate / 'bootstrap-assets'
            config.reboot = False
            if (config.simulate / 'device.json').exists():
                config.profile = read_json(config.simulate / 'device.json')['board']
        elif os.name != 'nt' and config.cache == Path('/data/armhpc-ota/cache') and not Path('/data').is_mount():
            # Rescue without SATA uses the mounted shared ext4, never a hidden /data directory on its root.
            config.cache = config.state / 'cache'
        from .sources import load
        load(config)
        return config

    @property
    def global_writer_lock(self):
        return None if self.simulate else Path('/run/lock/armhpc-ota-writer.lock')

    def board(self):
        identifier(self.profile)
        suffix = '-squashfs' if self.storage_layout == 'oect-squashfs-ab-v2' else ''
        require(self.storage_layout in (None, 'oect-ext4-ab-v1', 'oect-squashfs-ab-v2'), 'config_layout', 'Unknown storage layout')
        path = files('armhpc_ota').joinpath('profiles', self.profile + suffix + '.json')
        require(path.is_file(), 'board_unknown', 'No write adapter exists for this board')
        profile = parse_json(path.read_bytes())
        require(profile.get('write_enabled') is True, 'board_disabled', 'Board write adapter is disabled')
        return profile
