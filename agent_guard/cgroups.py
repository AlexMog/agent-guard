"""Root-owned cgroups. Only this module can attach or terminate processes."""
import os
from pathlib import Path
import re
import select
import signal
import time
from .model import is_agent, is_helper


class UnsafeAction(RuntimeError):
    pass


def validate_location(relative, uid):
    if uid == 0:
        if relative != '/system.slice/agent-guard.service':
            raise UnsafeAction('production requires exactly /system.slice/agent-guard.service')
    elif not (relative.startswith('/user.slice/') and Path(relative).name == 'agent-guard-integration-test.service'):
        raise UnsafeAction('non-root operation allowed only in the isolated integration test unit')


def validate_members(processes, registry, job):
    if not processes or job.baseline or job.tainted:
        raise UnsafeAction('empty, grandfathered or quarantined job')
    for p in processes:
        m = registry.members.get(p.key)
        if (p.uid != registry.uid or p.state == 'Z' or is_agent(p) or is_helper(p)
                or not m or m.job != job.id or m.protected or m.agent):
            raise UnsafeAction(f'unverified or protected group member {p.pid}:{p.start}')
    return processes


class Cgroups:
    def __init__(self, root, proc):
        self.root = Path(root)
        self.proc = proc

    @classmethod
    def delegated(cls, proc, cpu_fraction):
        own = proc.read(os.getpid())
        if not own:
            raise RuntimeError('cannot identify supervisor')
        # On restart the supervisor initially enters the service root again.
        relative = own.cgroup.removesuffix('/supervisor')
        validate_location(relative, os.geteuid())
        root = Path('/sys/fs/cgroup') / relative.lstrip('/')
        if (Path(relative).name not in ('agent-guard.service', 'agent-guard-integration-test.service')
                or not root.is_dir()):
            raise RuntimeError('a dedicated delegated systemd service is required')
        st = root.stat()
        if st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise UnsafeAction('delegation root is not exclusively writable by supervisor owner')
        result = cls(root, proc)
        supervisor = root / 'supervisor'
        supervisor.mkdir(exist_ok=True)
        (supervisor / 'cgroup.procs').write_text(str(os.getpid()))
        # No tasks may remain in the delegation root before enabling controllers.
        if (root / 'cgroup.procs').read_text().strip():
            raise RuntimeError('unexpected processes in delegation root')
        controllers = '+cpu +memory +pids'
        if 'cpuset' in (root / 'cgroup.controllers').read_text().split():
            controllers += ' +cpuset'
        (root / 'cgroup.subtree_control').write_text(controllers)
        for name in ('control', 'work'):
            group = root / name
            group.mkdir(exist_ok=True)
            (group / 'cgroup.subtree_control').write_text(controllers)
        (supervisor / 'cpu.weight').write_text('10000')
        result.configure_cpu(cpu_fraction, require_cpuset=os.geteuid() == 0)
        # Intentionally no memory.max on the shared tree: no arbitrary OOM victim.
        return result

    def configure_cpu(self, cpu_fraction, require_cpuset=True):
        cpuset = self.root / 'cpuset.cpus'
        if require_cpuset and not cpuset.exists():
            raise RuntimeError('cpuset delegation required for the shared CPU boundary')
        capacity = (os.cpu_count() or 1) * cpu_fraction
        settings = {}
        if cpuset.exists():
            # Read the parent, not our previous restriction, on restart.
            available = set()
            for item in (self.root.parent / 'cpuset.cpus.effective').read_text().strip().split(','):
                bounds = [int(x) for x in item.split('-')]
                available.update(range(bounds[0], bounds[-1] + 1))
            chosen = sorted(available)[:max(1, int(capacity))]
            if not chosen:
                raise RuntimeError('no online CPUs available in parent cgroup')
            settings[cpuset] = ','.join(map(str, chosen))
        quota = max(1000, round(capacity * 100000))
        # The common ancestor covers new children still in control, too.
        settings[self.root / 'cpu.max'] = f'{quota} 100000'
        # Remove the old work-only limit during upgrades.
        settings[self.root / 'work' / 'cpu.max'] = 'max 100000'
        original = {path: path.read_text() for path in settings}
        try:
            for path, value in settings.items():
                path.write_text(value)
        except OSError:
            for path, value in original.items():
                try:
                    # Some kernels reject clearing an occupied cpuset. Restore
                    # its inherited CPUs explicitly in that case.
                    if path == cpuset and not value.strip():
                        value = (self.root.parent / 'cpuset.cpus.effective').read_text()
                    path.write_text(value)
                except OSError:
                    pass
            raise

    @property
    def relative(self):
        return '/' + str(self.root.relative_to('/sys/fs/cgroup'))

    def job_path(self, jid):
        if not re.fullmatch(r'j-\d+-\d+', jid):
            raise ValueError('invalid job ID')
        return self.root / 'work' / jid

    def session_path(self, sid):
        if not re.fullmatch(r'a-\d+-\d+', sid):
            raise ValueError('invalid session ID')
        return self.root / 'control' / sid

    def attach(self, expected, target):
        """Identity checked around numeric cgroup attachment; mismatch quarantines caller."""
        try:
            fd = os.pidfd_open(expected.pid)
        except ProcessLookupError:
            return False
        try:
            current = self.proc.read(expected.pid)
            if not current or current.key != expected.key or current.uid != expected.uid:
                return False
            if current.exe != expected.exe or current.argv != expected.argv:
                return False  # exec raced classification; retry on a fresh observation
            if select.select([fd], [], [], 0)[0]:
                return False
            target.mkdir(exist_ok=True)
            (target / 'cgroup.procs').write_text(str(expected.pid))
            after = self.proc.read(expected.pid)
            if not after or after.key != expected.key:
                raise UnsafeAction('process exited/reused during attachment; quarantine required')
            return True
        finally:
            os.close(fd)

    def pids(self, path):
        try:
            return [int(x) for x in (path / 'cgroup.procs').read_text().split()]
        except FileNotFoundError:
            return []

    def members(self, path):
        result = []
        for pid in self.pids(path):
            p = self.proc.read(pid)
            if p:
                result.append(p)
            elif (Path('/proc') / str(pid)).exists():
                raise UnsafeAction(f'cannot inspect live group member {pid}')
        return result

    def freeze(self, path, frozen):
        (path / 'cgroup.freeze').write_text('1' if frozen else '0')
        if frozen:
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                events = dict(line.split() for line in (path / 'cgroup.events').read_text().splitlines())
                if events.get('frozen') == '1':
                    return
                time.sleep(0.005)
            raise UnsafeAction('group did not freeze; no signals sent')

    def terminate(self, job, registry, record, force=False, authorize=None):
        """Freeze creates stable membership; pidfds bind TERM to the checked identities."""
        path = self.job_path(job.id)
        handles = []
        try:
            self.freeze(path, True)
            members = validate_members(self.members(path), registry, job)
            for p in members:
                fd = os.pidfd_open(p.pid)
                handles.append((p, fd))
                current = self.proc.read(p.pid)
                if not current or current.key != p.key or current.exe != p.exe:
                    raise UnsafeAction('identity or executable changed before signal')
            # Durable audit callback must succeed before the first signal.
            record('kill' if force else 'terminate', job=job.id,
                   session=job.session, reason='memory-budget-exceeded',
                   pids=[p.pid for p in members], job_pss_bytes=job.pss, phase='intent')
            if authorize is not None and not authorize():
                raise UnsafeAction('event stream became unhealthy before signal; action aborted')
            for p, fd in handles:
                try:
                    # Never cgroup.kill: its recursive scope could exceed inspected members.
                    signal.pidfd_send_signal(fd, signal.SIGKILL if force else signal.SIGTERM)
                except ProcessLookupError:
                    pass
        finally:
            for _, fd in handles:
                os.close(fd)
            self.freeze(path, False)

    def thaw_all(self):
        for path in (self.root / 'work').glob('j-*'):
            if (path / 'cgroup.freeze').exists():
                (path / 'cgroup.freeze').write_text('0')

    def release_cpu(self):
        (self.root / 'work' / 'cpu.max').write_text('max 100000')
        (self.root / 'cpu.max').write_text('max 100000')
        if (self.root / 'cpuset.cpus').exists():
            (self.root / 'cpuset.cpus').write_text(
                (self.root.parent / 'cpuset.cpus.effective').read_text())

    def prune_empty(self):
        for parent in ('work', 'control'):
            for path in (self.root / parent).iterdir():
                if path.is_dir() and not self.pids(path):
                    try:
                        path.rmdir()
                    except OSError:
                        pass
