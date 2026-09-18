"""Configuration and sampling, separated from privileged side effects."""
from dataclasses import dataclass
from .model import Registry


@dataclass(frozen=True)
class Config:
    uid: int = 1000
    mode: str = 'observe'
    memory_bytes: int = 15 * 1024 ** 3
    cpu_fraction: float = 0.5
    observation_seconds: float = 60
    sample_seconds: float = 1
    reconcile_seconds: float = 30
    consecutive_samples: int = 3
    cooldown_seconds: float = 10
    minimum_job_bytes: int = 64 * 1024 ** 2
    terminate_grace_seconds: float = 3

    def __post_init__(self):
        if not isinstance(self.uid, int) or self.uid <= 0:
            raise ValueError('target must be an explicit non-root UID')
        if self.mode not in ('observe', 'enforce'):
            raise ValueError('mode must be observe or enforce')
        if not 0 < self.cpu_fraction <= 1 or self.memory_bytes <= 0:
            raise ValueError('invalid resource budget')
        if (self.observation_seconds < 10 or self.sample_seconds < 0.1 or self.reconcile_seconds < 1
                or self.consecutive_samples < 2 or self.cooldown_seconds < 1
                or self.minimum_job_bytes < 1 or self.terminate_grace_seconds < 1):
            raise ValueError('unsafe sampling or grace configuration')


def restore_registry(data, config, boot, cutoff):
    registry = Registry.restore(data.get('registry', {}), config.uid, boot, cutoff)
    pending = data.get('pending_attachments', {})
    for sid in pending.get('sessions', []):
        if sid in registry.sessions:
            registry.sessions[sid]['tainted'] = True
    for job in registry.jobs.values():
        if job.id in pending.get('jobs', []) or registry.sessions.get(job.session, {}).get('tainted'):
            job.tainted = True
    if data.get('mode') != 'enforce' and config.mode == 'enforce':
        registry.cutoff = cutoff
        for job in registry.jobs.values():
            job.baseline = True
    return registry


def measure(registry, proc):
    total, complete, swap = 0, True, 0
    for job in registry.jobs.values():
        job.pss = job.swap = 0
    for p in registry.processes.values():
        member = registry.members.get(p.key)
        if not member or not member.job:
            continue
        reading = proc.memory(p)
        if reading is None:
            if proc.identity(p.pid) == p.start:
                complete = False
            continue
        resident, swapped = reading
        job = registry.jobs[member.job]
        job.pss += resident
        job.swap += swapped
        total += resident
        swap += swapped
    return total, complete, swap
