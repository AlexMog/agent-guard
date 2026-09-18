"""Opt-in kernel check in a fresh root-owned agent-guard-cpu-test.service.

Run with systemd-run --unit=agent-guard-cpu-test.service --collect --wait
--pipe -p Delegate=yes -p RuntimeMaxSec=30 python3 THIS_FILE --run.
Only the runner and its own children enter or leave test cgroups.
"""
import json
import os
from pathlib import Path
import select
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_guard.cgroups import Cgroups
from agent_guard.procfs import ProcFS


CHILD = r'''
import json, os, sys, time
allowed = set(json.loads(sys.argv[1]))
os.sched_setaffinity(0, allowed)
print(json.dumps(sorted(os.sched_getaffinity(0))), flush=True)
sys.stdin.readline()
start = time.monotonic()
while time.monotonic() - start < 2:
    pass
'''


def main():
    assert sys.argv[1:] == ['--run'] and os.geteuid() == 0
    assert os.environ.get('INVOCATION_ID')
    proc = ProcFS()
    own = proc.read(os.getpid())
    assert own.cgroup == '/system.slice/agent-guard-cpu-test.service'
    root = Path('/sys/fs/cgroup') / own.cgroup.lstrip('/')
    assert (root / 'cgroup.procs').read_text().split() == [str(os.getpid())]
    assert not any(p.is_dir() for p in root.iterdir())
    original_affinity = os.sched_getaffinity(0)
    (root / 'supervisor').mkdir()
    (root / 'supervisor/cgroup.procs').write_text(str(os.getpid()))
    (root / 'cgroup.subtree_control').write_text('+cpuset +cpu')
    for area in ('work', 'control'):
        (root / area).mkdir()
    cg = Cgroups(root, proc)
    children = []
    try:
        cg.configure_cpu(0.25 / os.cpu_count())
        assert len(os.sched_getaffinity(0)) == 1
        expected = os.sched_getaffinity(0)
        cg.configure_cpu(0.25 / os.cpu_count())
        assert os.sched_getaffinity(0) == expected
        # Spawn while in control: children inherit the limit before any per-job
        # discovery/migration, including attempted affinity widening.
        (root / 'control/cgroup.procs').write_text(str(os.getpid()))
        for i in range(4):
            child = subprocess.Popen([sys.executable, '-u', '-c', CHILD,
                                      json.dumps(sorted(original_affinity))],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            children.append(child)
            assert select.select([child.stdout], [], [], 5)[0]
            assert set(json.loads(child.stdout.readline())) == expected
            assert proc.read(child.pid).cgroup == own.cgroup + '/control'
            if i % 2:
                identity = proc.read(child.pid)
                assert cg.attach(identity, root / 'work')
        (root / 'supervisor/cgroup.procs').write_text(str(os.getpid()))
        def stat():
            return {k: int(v) for k, v in (x.split() for x in (root / 'cpu.stat').read_text().splitlines())}
        import time
        before = stat()
        start = time.monotonic()
        for child in children:
            child.stdin.write('go\n')
            child.stdin.flush()
        for child in children:
            assert child.wait(timeout=8) == 0
        elapsed = time.monotonic() - start
        after = stat()
        cores_used = (after['usage_usec'] - before['usage_usec']) / 1e6 / elapsed
        assert cores_used < 0.5, (cores_used, elapsed)
        assert after['nr_throttled'] > before['nr_throttled']
        cg.release_cpu()
        assert os.sched_getaffinity(0) == original_affinity
        print(json.dumps({'passed': True, 'inherited_affinity_count': len(expected),
                          'shared_control_work_cpu_cores': round(cores_used, 3),
                          'throttled_periods': after['nr_throttled'] - before['nr_throttled'],
                          'affinity_widening_blocked': True, 'release_restored': True}), flush=True)
    finally:
        cg.release_cpu()
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            child.stdin.close()
            child.stdout.close()


if __name__ == '__main__':
    main()
