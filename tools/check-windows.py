# SPDX-License-Identifier: GPL-3.0-only
"""Run the Windows transport, controller and WPF checks using local fixtures."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(project, output):
    project = Path(project).resolve(strict=True)
    output = Path(output).resolve()
    if any((p / '.git').exists() for p in (output, *output.parents)):
        raise ValueError('Check results must be outside repositories')
    output.mkdir(parents=True, exist_ok=True)
    state = output / 'sftp-state'
    state.mkdir(exist_ok=True)
    (state / 'sftp-fixture.stop').unlink(missing_ok=True)
    (state / 'sftp-fixture.json').unlink(missing_ok=True)
    fixture = subprocess.Popen([sys.executable, '-X', 'utf8', str(project / 'tools/test-sftp-server.py'), str(state)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    env = os.environ.copy()
    try:
        deadline = time.monotonic() + 10
        while not (state / 'sftp-fixture.json').exists():
            if fixture.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('The local SSH/SFTP fixture did not start')
            time.sleep(.1)
        env['ARMHPC_SFTP_FIXTURE'] = str(state / 'sftp-fixture.json')
        converted = subprocess.check_output(['wsl', 'wslpath', '-a', (project / 'windows/ArmHpc.Ota.Tests/Fixtures/serial-console-pty.py').as_posix()], text=True).strip()
        env['ARMHPC_SERIAL_PTY_SCRIPT'] = converted
        for name, arguments in [('ArmHpc.Ota.Tests', []), ('ArmHpc.Ota.UiTests', [str(output / 'gui.png')])]:
            with (output / (name + '.txt')).open('w', encoding='utf-8') as log:
                subprocess.run(['dotnet', 'run', '--project', str(project / 'windows' / name / (name + '.csproj')),
                                '-c', 'Release', '--', *arguments], cwd=project, env=env,
                               stdout=log, stderr=subprocess.STDOUT, check=True)
            print((output / (name + '.txt')).read_text(encoding='utf-8')[-3500:], flush=True)
    finally:
        (state / 'sftp-fixture.stop').write_text('stop', encoding='utf-8')
        try:
            fixture.wait(timeout=5)
        except subprocess.TimeoutExpired:
            fixture.terminate()
            fixture.wait(timeout=3)
        (state / 'sftp-fixture.json').unlink(missing_ok=True)
    (output / 'windows-checks.json').write_text(json.dumps({'passed': True, 'local_ssh_sftp': True,
                'serial_pty': True, 'wpf': True, 'physical_devices_accessed': False}, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.project, args.output)
