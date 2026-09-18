"""Event-driven discovery, periodic sampling and conservative intervention."""
from dataclasses import asdict
import fcntl
import os
from pathlib import Path
import signal
import time
from .cgroups import Cgroups, UnsafeAction
from .events import EventPump, EventLoss
from .model import is_agent
from .policy import Gate, choose_victim
from .procfs import ProcFS
from .runtime import measure, restore_registry
from .storage import Store


class Daemon:
    def __init__(self, config, state_dir='/var/lib/agent-guard'):
        self.config = config
        self.store = Store(Path(state_dir))
        self.lock = os.open(Path(state_dir) / 'daemon.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.proc = ProcFS()
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        cutoff = int(float(Path('/proc/uptime').read_text().split()[0]) * os.sysconf('SC_CLK_TCK'))
        self.registry = restore_registry(self.store.load('state.json'), config, boot, cutoff)
        self.events = None
        self.cg = None
        self.running = True
        self.event_ok = False
        self.cache = {}
        self.pending = None
        self.pending_attachments = {}
        self.started = time.monotonic()
        self.gate = Gate(config.observation_seconds, config.consecutive_samples, config.cooldown_seconds, self.started)
        self.total = self.swap = 0
        self.complete = False
        self.last_scan = self.last_save = self.last_retry = float('-inf')
        self.last_message = ''

    def connect(self):
        if self.events:
            self.events.close()
        self.events = None
        self.event_ok = False
        self.last_retry = time.monotonic()
        try:
            self.events = EventPump()
            self.event_ok = True
            self.store.record('events-connected')
        except (OSError, TimeoutError, EventLoss, ValueError) as exc:
            self.store.record('events-unavailable', error=str(exc), action='memory-intervention-paused')

    def state(self):
        return {'registry': self.registry.export(), 'mode': self.config.mode,
                'pending_attachments': self.pending_attachments}

    def save(self):
        self.store.save('state.json', self.state())
        active_jobs = {m.job for m in self.registry.members.values() if m.job}
        self.store.save('status.json', {
            'updated_at': time.time(), 'supervisor_pid': os.getpid(), 'running': self.running,
            'mode': self.config.mode, 'events_connected': self.event_ok and bool(self.events and self.events.healthy),
            'memory_bytes': self.total, 'swap_bytes': self.swap, 'measurement_complete': self.complete,
            'limit_bytes': self.config.memory_bytes, 'cpu_fraction': self.config.cpu_fraction,
            'cpu_cap_active': bool(self.cg) and self.running, 'cgroup': str(self.cg.root) if self.cg else None,
            'observation_remaining_seconds': max(0, round(self.config.observation_seconds - (time.monotonic() - self.started))),
            'sessions': self.registry.sessions,
            'jobs': [asdict(j) for j in self.registry.jobs.values() if j.id in active_jobs],
            'members': {k: asdict(m) for k, m in self.registry.members.items()},
            'last_message': self.last_message,
        })
        self.last_save = time.monotonic()

    def refresh(self, pids):
        for pid in set(pids):
            p = self.proc.read(pid)
            if p and p.uid == self.config.uid:
                self.cache[pid] = p
            else:
                self.cache.pop(pid, None)

    def reconcile(self, full=False):
        if full:
            self.cache = {p.pid: p for p in self.proc.scan(self.config.uid)}
            self.last_scan = time.monotonic()
        # Owned groups also recover children whose parent has already exited.
        if self.cg:
            pids = []
            for section in ('work', 'control'):
                for group in (self.cg.root / section).iterdir():
                    if group.is_dir():
                        pids.extend(self.cg.pids(group))
            self.refresh(pids)
        self.refresh([int(k.split(':')[0]) for k in self.registry.members])
        previous = set(self.registry.jobs)
        self.registry.reconcile(self.cache.values())
        for jid in set(self.registry.jobs) - previous:
            job = self.registry.jobs[jid]
            self.store.record('job-discovered', job=jid, session=job.session, pid=job.root_pid,
                              start=job.start, baseline=job.baseline, exe=job.exe, cwd=job.cwd)
        if self.cg:
            items = sorted(self.registry.processes.values(), key=lambda p: (not is_agent(p), p.start))
            moves = []
            for p in items:
                m = self.registry.members.get(p.key)
                if not m:
                    continue
                target = self.cg.job_path(m.job) if m.job else self.cg.session_path(m.session)
                relative = '/' + str(target.relative_to('/sys/fs/cgroup'))
                if p.cgroup == relative:
                    continue
                moves.append((p, m, target))
            # A crash at any point in numeric migration quarantines the entire unfinished batch.
            if moves:
                self.pending_attachments = {
                    'jobs': sorted({m.job for _, m, _ in moves if m.job}),
                    'sessions': sorted({m.session for _, m, _ in moves if not m.job}),
                }
                self.store.save('state.json', self.state())
            for p, m, target in moves:
                try:
                    if self.cg.attach(p, target):
                        fresh = self.proc.read(p.pid)
                        if fresh:
                            self.cache[p.pid] = fresh
                except (OSError, UnsafeAction) as exc:
                    # Any ambiguous attachment inhibits automatic termination for the job.
                    if m.job:
                        self.registry.jobs[m.job].tainted = True
                    else:
                        # A session attachment race could affect later inherited attribution.
                        self.registry.sessions[m.session]['tainted'] = True
                        for job in self.registry.jobs.values():
                            if job.session == m.session:
                                job.tainted = True
                        self.event_ok = False
                    self.store.record('attachment-rejected', pid=p.pid, start=p.start, error=str(exc))
            if moves:
                self.pending_attachments = {}
                self.store.save('state.json', self.state())
            self.cg.prune_empty()
        # Bound metadata growth; live groups retain all identities and provenance.
        active = {m.job for m in self.registry.members.values() if m.job}
        dead = sorted((j for j in self.registry.jobs.values() if j.id not in active), key=lambda j: j.start)
        for j in dead[:-256]:
            self.registry.jobs.pop(j.id, None)
        sessions = {m.session for m in self.registry.members.values()} | {j.session for j in self.registry.jobs.values()}
        self.registry.sessions = {k: v for k, v in self.registry.sessions.items() if k in sessions}

    def sample(self):
        self.total, self.complete, self.swap = measure(self.registry, self.proc)
        if self.cg:
            # Unreadable or not-yet-discovered live group members prohibit action.
            for jid in self.registry.jobs:
                for pid in self.cg.pids(self.cg.job_path(jid)):
                    p = self.proc.read(pid)
                    if p and p.state == 'Z':
                        continue
                    if not p or p.key not in self.registry.members:
                        self.complete = False
        now = time.monotonic()
        if self.config.mode != 'enforce' or not self.event_ok or not getattr(self.events, 'healthy', False):
            self.gate.count = 0
            return
        if self.pending:
            jid, deadline = self.pending
            if now >= deadline:
                job = self.registry.jobs.get(jid)
                try:
                    if job and self.cg.pids(self.cg.job_path(jid)):
                        self.cg.terminate(job, self.registry, self.store.record, force=True,
                                          authorize=lambda: self.event_ok and self.events.healthy)
                except (OSError, UnsafeAction) as exc:
                    self.store.record('kill-aborted', job=jid, error=str(exc))
                self.pending = None
            return
        if not self.gate.ready(now, self.total > self.config.memory_bytes, self.complete):
            return
        job = choose_victim(self.registry.jobs.values(), self.total, self.config.memory_bytes,
                            self.complete, self.config.minimum_job_bytes)
        self.gate.acted(now)
        if not job:
            self.last_message = 'Budget exceeded; no eligible new verified job. Existing work remains protected.'
            self.store.record('over-budget-no-safe-victim', total_bytes=self.total, limit_bytes=self.config.memory_bytes)
            return
        try:
            self.store.record('memory-decision', job=job.id, total_bytes=self.total,
                              limit_bytes=self.config.memory_bytes, policy='newest-verified-nonbaseline-job')
            self.cg.terminate(job, self.registry, self.store.record,
                              authorize=lambda: self.event_ok and self.events.healthy)
            self.pending = (job.id, now + self.config.terminate_grace_seconds)
            self.last_message = f'{job.id}: TERM sent because shared work PSS exceeded budget'
        except (OSError, UnsafeAction) as exc:
            self.last_message = f'{job.id}: action aborted: {exc}'
            self.store.record('termination-aborted', job=job.id, error=str(exc))

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, 'running', False))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, 'running', False))
        self.connect()
        if self.config.mode == 'enforce' and not self.event_ok:
            raise RuntimeError('enforce mode requires a working kernel event subscription')
        try:
            if self.config.mode == 'enforce':
                self.cg = Cgroups.delegated(self.proc, self.config.cpu_fraction)
                self.registry.group_prefix = self.cg.relative
                self.cg.thaw_all()
            self.reconcile(full=True)
            self.store.record('started', mode=self.config.mode, cutoff=self.registry.cutoff,
                              memory_budget_bytes=self.config.memory_bytes, cpu_fraction=self.config.cpu_fraction)
            next_sample = time.monotonic()
            while self.running:
                now = time.monotonic()
                if self.events:
                    try:
                        events = self.events.receive(min(0.25, max(0, next_sample - now)))
                        if events:
                            pids = {e.pid for e in events if e.pid}
                            pids.update(e.parent_pid for e in events if e.parent_pid)
                            self.refresh(pids)
                            # Batch event handling; expensive reconciliation is bounded by sample rate.
                    except (OSError, EventLoss, ValueError) as exc:
                        self.event_ok = False
                        self.gate.count = 0
                        self.events.close()
                        self.events = None
                        self.store.record('event-loss', error=str(exc), action='pause-and-reconcile')
                        self.reconcile(full=True)
                else:
                    time.sleep(0.1)
                    if now - self.last_retry >= 10:
                        self.connect()
                        if self.event_ok:
                            self.reconcile(full=True)
                now = time.monotonic()
                if now >= next_sample:
                    self.reconcile(full=now - self.last_scan >= self.config.reconcile_seconds)
                    self.sample()
                    self.save()
                    next_sample = time.monotonic() + self.config.sample_seconds
        finally:
            self.running = False
            if self.events:
                self.events.close()
            if self.cg:
                self.cg.thaw_all()
                self.cg.release_cpu()
            self.save()
            self.store.record('stopped', action='workloads-retained-cpu-quota-released')
            os.close(self.lock)
