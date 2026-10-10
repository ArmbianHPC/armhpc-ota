# SPDX-License-Identifier: GPL-3.0-only
"""OTA adapter for the framework clock helper; no duplicate clock policy."""
import importlib.util
import json
from pathlib import Path
import subprocess
import time
from .errors import OTAError, require
from .io import read_json, atomic_json, parse_json

HELPER = Path('/usr/lib/armhpc/clock_floor.py')
_module = None
_module_stat = None


def implementation():
    global _module, _module_stat
    signature = (HELPER.stat().st_mtime_ns, HELPER.stat().st_size) if HELPER.is_file() else None
    if signature is None:
        _module = None
        _module_stat = None
        return None
    if _module is None or signature != _module_stat:
        spec = importlib.util.spec_from_file_location('armhpc_clock_runtime', HELPER)
        _module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_module)
        _module_stat = signature
    return _module


class Clock:
    def __init__(self, config): self.config = config

    def snapshot(self, live=False):
        if self.config.simulate:
            path = self.config.simulate / 'clock.json'
            return read_json(path) if path.exists() else {'quality': 'synchronised', 'source': 'simulation',
                   'ntp_synchronised': True, 'valid_anchor': True, 'last_saved_epoch': time.time(), 'epoch': time.time()}
        try:
            helper = implementation()
            if helper: return helper.snapshot(live=live)
        except (OSError, ValueError, AttributeError): pass
        return {'quality': 'invalid', 'source': 'clock-helper-unavailable', 'ntp_synchronised': False,
                'valid_anchor': False, 'last_saved_epoch': None, 'epoch': time.time()}

    def require_valid(self):
        state = self.snapshot(live=True)
        require(state.get('valid_anchor') and state.get('quality') in ('synchronised', 'estimated'),
                'clock_state_invalid', 'No calibrated or recoverable time; synchronize chrony before starting OTA')
        return state

    def require_synchronised(self):
        state = self.snapshot(live=True)
        require(state.get('ntp_synchronised'), 'clock_unsynchronised',
                'Synchronize chrony before checking a time-limited update index; local signed push/recovery can use an estimated clock')
        return state

    def _run(self, arguments, timeout):
        try:
            result = subprocess.run(['python3', str(HELPER), *arguments], text=True, capture_output=True, timeout=timeout)
            value = parse_json(result.stdout.encode())
            if result.returncode or not value.get('ok'):
                raise OTAError('clock_persist_failed', value.get('error', {}).get('message', 'Clock checkpoint failed'))
            return value['data']
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            raise OTAError('clock_persist_failed', 'Clock helper could not complete its durable checkpoint') from error

    def flush(self, reason):
        if self.config.simulate:
            state = self.require_valid()
            if state.get('persist_failure'): raise OTAError('clock_persist_failed', 'Simulated checkpoint failure')
            atomic_json(self.config.simulate / 'last-clock-flush.json', {'reason': reason, 'clock': state})
            return state
        return self._run(['--flush', '--reason', reason], 5)

    def wait_ready(self, timeout=30):
        if self.config.simulate: return self.snapshot()
        # Never turn loss of NTP into a hardware boot failure.
        try: return self._run(['--wait-sync', '--timeout', str(min(30, max(0, timeout)))], min(30, max(0, timeout)) + 5)
        except OTAError: return self.snapshot()
