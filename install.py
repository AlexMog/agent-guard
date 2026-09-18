#!/usr/bin/env python3
"""Reviewable installer. Requires local administrator authentication."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parent
DEST = Path('/usr/local/lib/agent-guard')
CONFIG = Path('/etc/agent-guard.json')
UNIT = Path('/etc/systemd/system/agent-guard.service')


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def copy(source, destination, mode=0o644):
    if source.is_symlink() or not source.is_file():
        raise RuntimeError(f'non-regular source refused: {source}')
    if destination.is_symlink():
        raise RuntimeError(f'symlink destination refused: {destination}')
    shutil.copyfile(source, destination)
    os.chown(destination, 0, 0)
    os.chmod(destination, mode)


def write_new(path, content, mode):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def wait_status(mode, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data = json.loads(Path('/var/lib/agent-guard/status.json').read_text())
            if (data['mode'] == mode and data['running'] and data['events_connected']
                    and time.time() - data['updated_at'] < 3):
                return data
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.5)
    raise RuntimeError('service did not produce a fresh healthy status; check journalctl -u agent-guard')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, default=1000)
    parser.add_argument('--enforce-new', action='store_true', help='enable limits for verified new work after initial observation')
    parser.add_argument('--check-only', action='store_true', help='run privileged event integration without installing')
    parser.add_argument('--update', action='store_true', help='replace code and unit, preserving configuration and provenance')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run with sudo from your terminal; never send your password to an agent')
    if args.uid <= 0:
        parser.error('target UID must be non-root')
    pwd.getpwuid(args.uid)
    if str(SOURCE) not in sys.path:
        sys.path.insert(0, str(SOURCE))
    # Kernel event subscription must work before any system installation is attempted.
    test_env = dict(os.environ, AGENT_GUARD_PROC_INTEGRATION='1')
    run('/usr/bin/python3', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_events.py', '-v', cwd=SOURCE, env=test_env)
    if args.check_only:
        return
    from agent_guard.runtime import Config
    from dataclasses import asdict
    command = Path('/usr/local/bin/agent-guard')
    if args.update:
        import stat
        for path in (CONFIG, UNIT, DEST, DEST / 'agent_guard', command):
            st = path.lstat()
            expected_type = stat.S_ISDIR(st.st_mode) if path in (DEST, DEST / 'agent_guard') else stat.S_ISREG(st.st_mode)
            if not expected_type or st.st_uid != 0 or st.st_mode & 0o022:
                raise RuntimeError(f'unsafe existing installation: {path}')
        config = Config(**json.loads(CONFIG.read_text()))
        run('systemctl', 'stop', 'agent-guard.service')
        for source in (SOURCE / 'agent_guard').glob('*.py'):
            copy(source, DEST / 'agent_guard' / source.name)
        copy(SOURCE / 'packaging/main.py', DEST / 'main.py')
        copy(SOURCE / 'packaging/agent-guard.service', UNIT)
        run('systemd-analyze', 'verify', str(UNIT))
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', 'agent-guard.service')
        wait_status(config.mode)
        print('Updated; configuration, existing workloads and provenance retained.', flush=True)
        return
    if any(p.exists() or p.is_symlink() for p in (CONFIG, UNIT, DEST, command)):
        raise RuntimeError('existing installation found; use documented update procedure instead of overwriting')
    DEST.mkdir(mode=0o755)
    (DEST / 'agent_guard').mkdir(mode=0o755)
    for source in (SOURCE / 'agent_guard').glob('*.py'):
        copy(source, DEST / 'agent_guard' / source.name)
    copy(SOURCE / 'packaging/main.py', DEST / 'main.py')
    copy(SOURCE / 'packaging/agent-guard.service', UNIT)
    write_new(command, '#!/bin/sh\nexec /usr/bin/python3 -I /usr/local/lib/agent-guard/main.py "$@"\n', 0o755)
    write_new(CONFIG, json.dumps(asdict(Config(uid=args.uid)), indent=2) + '\n', 0o644)
    run('systemd-analyze', 'verify', str(UNIT))
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'agent-guard.service')
    observed = wait_status('observe')
    print(f"Observation: {len(observed['jobs'])} work groups; {observed['memory_bytes'] / 1024**3:.2f} GiB PSS", flush=True)
    if args.enforce_new:
        config = asdict(Config(uid=args.uid, mode='enforce'))
        CONFIG.write_text(json.dumps(config, indent=2) + '\n')
        run('systemctl', 'restart', 'agent-guard.service')
        wait_status('enforce')
        print('Enforcement enabled. Existing jobs protected; startup grace 60 seconds. CPU quota active.', flush=True)
    else:
        print('Observation mode active: no process migration, throttling, or termination.', flush=True)
    print('Inspect with: agent-guard status; agent-guard explain PID', flush=True)


if __name__ == '__main__':
    main()
