"""Opt-in integration test restricted to children in a fresh disposable service.

From the project directory, run the command printed by this script with no args.
No root privileges are needed; systemd must delegate cpu, memory and pids.
The module is deliberately excluded from normal unittest discovery.
"""

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import select
import shlex
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_guard.cgroups import Cgroups
from agent_guard.model import Job, Member, Registry
from agent_guard.policy import choose_victim
from agent_guard.procfs import ProcFS


UNIT = 'agent-guard-integration-test.service'
CHILD_CODE = r'''
import json, signal, sys, time
mode = sys.argv[1]
if mode == 'ignore':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
memory = None
if mode == 'memory':
    memory = bytearray(64 * 1024 * 1024)
    for index in range(0, len(memory), 4096):
        memory[index] = 1
print('READY', flush=True)
command = sys.stdin.readline()
if mode == 'burn' and command == 'go\n':
    wall_start, cpu_start = time.monotonic(), time.process_time()
    value = 1
    while time.monotonic() - wall_start < 2.0:
        value = (value * 17 + 1) % 10000019
    print(json.dumps({'wall_seconds': time.monotonic() - wall_start,
                      'cpu_seconds': time.process_time() - cpu_start}), flush=True)
'''


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def fields(path):
    return dict(line.split() for line in path.read_text().splitlines())


def line_from(child, timeout=5):
    require(select.select([child.stdout], [], [], timeout)[0],
            f'test child {child.pid} did not respond within {timeout}s')
    line = child.stdout.readline()
    require(bool(line), f'test child {child.pid} closed its output early')
    return line.strip()


def preflight(proc):
    require(os.geteuid() != 0, 'run in a delegated user service, not as root')
    require(bool(os.environ.get('INVOCATION_ID')), 'a fresh systemd service is required')
    own = proc.read(os.getpid())
    require(own is not None, 'cannot read own process identity')
    require(Path(own.cgroup).name == UNIT,
            f'refusing to mutate cgroup outside the disposable {UNIT}')
    root = Path('/sys/fs/cgroup') / own.cgroup.lstrip('/')
    require((root / 'cgroup.procs').read_text().split() == [str(os.getpid())],
            'disposable service must contain only the integration runner')
    require(not any(path.is_dir() for path in root.iterdir()),
            'disposable service must have no pre-existing child cgroups')
    controllers = (root / 'cgroup.controllers').read_text().split()
    require({'cpu', 'memory', 'pids'}.issubset(controllers),
            f'missing delegated controllers; available: {controllers}')
    return own


def run():
    proc = ProcFS()
    own = preflight(proc)
    # Cgroups interprets its fraction across all online CPUs. Limit the test to
    # 25% of one CPU, independently of machine size, for an observable throttle.
    cg = Cgroups.delegated(proc, 0.25 / (os.cpu_count() or 1))
    registry = Registry(os.getuid(), 'integration-only', 0)
    sid = f'a-{own.pid}-{own.start}'
    children = []
    paths = []
    audit = []

    def spawn(mode):
        child = subprocess.Popen([sys.executable, '-u', '-c', CHILD_CODE, mode],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=None, text=True, bufsize=1)
        children.append(child)
        require(line_from(child) == 'READY', 'unexpected child readiness message')
        identity = proc.read(child.pid)
        require(identity is not None and identity.ppid == os.getpid(),
                'new child identity could not be verified')
        return child, identity

    def attach(identity):
        jid = f'j-{identity.pid}-{identity.start}'
        job = Job(jid, sid, identity.pid, identity.start, False, identity.cwd, identity.exe)
        registry.jobs[jid] = job
        registry.members[identity.key] = Member(sid, jid)
        path = cg.job_path(jid)
        paths.append(path)
        require(cg.attach(identity, path), 'attachment rejected the freshly verified child')
        after = proc.read(identity.pid)
        require(after is not None and after.key == identity.key,
                'child identity changed during migration')
        require(after.cgroup == f'{cg.relative}/work/{jid}', 'child did not migrate')
        require(cg.pids(path) == [identity.pid], 'job contains an unexpected process')
        return job, path, after

    def record(action, **details):
        # This callback runs immediately before Cgroups sends a signal. Assert
        # the concrete victim set is solely a still-owned subprocess.
        expected = {child.pid for child in children if child.poll() is None}
        require(set(details['pids']).issubset(expected), 'attempt to signal a non-test process')
        path = cg.job_path(details['job'])
        require(fields(path / 'cgroup.events').get('frozen') == '1',
                'termination audit was called without a frozen cgroup')
        audit.append({'action': action, **details})

    try:
        manual, manual_identity = spawn('manual')
        worker, worker_identity = spawn('memory')

        # Simulate PID reuse without waiting for actual reuse. The deliberately
        # wrong start time must reject migration before a target group is made.
        stale = replace(worker_identity, start=worker_identity.start + 1)
        stale_path = cg.job_path(f'j-{stale.pid}-{stale.start}')
        require(not cg.attach(stale, stale_path), 'reused PID identity was accepted')
        require(not stale_path.exists(), 'rejected identity created a cgroup')
        require(proc.read(worker.pid).cgroup == worker_identity.cgroup,
                'rejected identity nevertheless migrated the process')
        print('PASS: stale PID/start identity rejected before migration', flush=True)

        job, path, migrated = attach(worker_identity)
        memory = proc.memory(migrated)
        require(memory is not None and memory[0] >= 60 * 1024 * 1024,
                f'64 MiB pre-migration allocation missing from post-migration PSS: {memory}')
        job.pss, job.swap = memory
        print(f'PASS: attachment and post-migration PSS ({job.pss} bytes)', flush=True)

        quota = (cg.root / 'cpu.max').read_text().split()
        require(quota == ['25000', '100000'], f'unexpected cpu.max: {quota}')
        burner, burner_identity = spawn('burn')
        _, burner_path, _ = attach(burner_identity)
        before = fields(cg.root / 'cpu.stat')
        burner.stdin.write('go\n')
        burner.stdin.flush()
        measurement = json.loads(line_from(burner, timeout=6))
        require(burner.wait(timeout=2) == 0, 'CPU burner failed')
        after = fields(cg.root / 'cpu.stat')
        require(int(after['nr_throttled']) > int(before['nr_throttled']),
                'cpu.stat recorded no quota throttling')
        require(int(after['throttled_usec']) > int(before['throttled_usec']),
                'cpu.stat recorded no throttled time')
        require(1.8 <= measurement['wall_seconds'] <= 5,
                f'CPU workload exceeded its bounded duration: {measurement}')
        require(measurement['cpu_seconds'] / measurement['wall_seconds'] < 0.6,
                f'CPU quota did not constrain actual process CPU time: {measurement}')
        print(f'PASS: cpu.max and effective throttling ({measurement})', flush=True)

        # Use the already allocated worker as the older job. Wait beyond a
        # kernel clock tick so newest selection cannot accidentally rely on PID
        # ordering when both children have the same /proc start timestamp.
        time.sleep(max(0.03, 2 / os.sysconf('SC_CLK_TCK')))
        newer, newer_identity = spawn('memory')
        require(newer_identity.start > worker_identity.start,
                'test children must have distinct, ordered birth timestamps')
        newer_job, newer_path, newer_migrated = attach(newer_identity)
        older_memory = proc.memory(migrated)
        newer_memory = proc.memory(newer_migrated)
        require(older_memory is not None and newer_memory is not None,
                'cannot obtain complete PSS samples for both test jobs')
        job.pss, job.swap = older_memory
        newer_job.pss, newer_job.swap = newer_memory
        require(min(job.pss, newer_job.pss) >= 60 * 1024 * 1024,
                'both test children must retain their touched 64 MiB allocations')
        test_budget = 100 * 1024 * 1024
        total_pss = job.pss + newer_job.pss
        require(total_pss > test_budget, 'controlled combined PSS did not exceed the test budget')

        def select_over_budget():
            return choose_victim([job, newer_job], total_pss, test_budget,
                                 complete=True, min_bytes=1)

        require(select_over_budget() is newer_job, 'budget policy did not select the newest job')
        newer_job.baseline = True
        require(select_over_budget() is job, 'baseline exemption did not protect the newest job')
        newer_job.baseline = False
        victim = select_over_budget()
        require(victim is newer_job, 'restored candidate did not become the newest victim')
        audit_before_budget = len(audit)
        cg.terminate(victim, registry, record)
        require(newer.wait(timeout=3) == -signal.SIGTERM,
                'budget-selected newest job did not exit from targeted TERM')
        require(len(audit) == audit_before_budget + 1
                and audit[-1]['action'] == 'terminate'
                and audit[-1]['job'] == newer_job.id
                and audit[-1]['pids'] == [newer.pid],
                'budget path signaled a process other than its selected test child')
        require(fields(newer_path / 'cgroup.events').get('frozen') == '0',
                'budget termination left its group frozen')
        older_after = proc.read(worker.pid)
        manual_after = proc.read(manual.pid)
        require(worker.poll() is None and older_after is not None
                and older_after.key == worker_identity.key,
                'older job was affected by newest-job budget termination')
        require(manual.poll() is None and manual_after is not None
                and manual_after.key == manual_identity.key,
                'manual sibling was affected by newest-job budget termination')
        print(f'PASS: {total_pss} bytes PSS > 100 MiB test budget, newest selection, '
              'baseline exemption, targeted TERM, older job and manual sibling alive', flush=True)

        cg.freeze(path, True)
        require(fields(path / 'cgroup.events').get('frozen') == '1', 'freeze not acknowledged')
        require(worker.poll() is None, 'freeze unexpectedly ended the worker')
        cg.freeze(path, False)
        cg.terminate(job, registry, record)
        require(worker.wait(timeout=3) == -signal.SIGTERM, 'worker did not exit from targeted TERM')
        require(fields(path / 'cgroup.events').get('frozen') == '0', 'TERM left the group frozen')
        require(manual.poll() is None and proc.read(manual.pid).key == manual_identity.key,
                'manual sibling was affected by targeted TERM')
        print('PASS: freeze, audited TERM and untouched manual sibling', flush=True)

        stubborn, stubborn_identity = spawn('ignore')
        stubborn_job, stubborn_path, _ = attach(stubborn_identity)
        cg.terminate(stubborn_job, registry, record)
        time.sleep(0.15)
        require(stubborn.poll() is None, 'TERM-ignoring child unexpectedly exited')
        cg.terminate(stubborn_job, registry, record, force=True)
        require(stubborn.wait(timeout=3) == -signal.SIGKILL, 'forced group kill did not end its child')
        require(fields(stubborn_path / 'cgroup.events').get('frozen') == '0', 'KILL left group frozen')
        require(manual.poll() is None and proc.read(manual.pid).key == manual_identity.key,
                'manual sibling was affected by targeted KILL')
        require([item['action'] for item in audit] == ['terminate', 'terminate', 'terminate', 'kill'],
                'unexpected termination audit sequence')
        print('PASS: TERM refusal, forced KILL and untouched manual sibling', flush=True)
        return 0
    finally:
        # Thaw only known test-created groups. Kill only unreaped Popen children:
        # their PIDs cannot have been reused while we retain parenthood.
        for path in paths:
            if (path / 'cgroup.freeze').exists():
                try:
                    cg.freeze(path, False)
                except OSError:
                    pass
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            child.stdin.close()
            child.stdout.close()
        cg.prune_empty()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='run only inside the dedicated service')
    args = parser.parse_args()
    if not args.run:
        command = ['systemd-run', '--user', '--unit=' + UNIT, '--collect',
                   '-p', 'Delegate=yes', '-p', 'RuntimeMaxSec=30', '--wait', '--pipe',
                   sys.executable, str(Path(__file__).resolve()), '--run']
        print(shlex.join(command))
        return 0
    try:
        return run()
    except (AssertionError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
