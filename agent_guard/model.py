"""Pure identity and provenance model. Heuristics never establish ownership."""
from dataclasses import asdict, dataclass
import re


@dataclass(frozen=True)
class Process:
    pid: int
    ppid: int
    start: int
    uid: int
    exe: str
    argv: tuple[str, ...]
    cgroup: str
    cwd: str
    state: str
    rss: int

    @property
    def key(self):
        return f'{self.pid}:{self.start}'


def is_agent(p):
    exe = p.exe.removesuffix(' (deleted)')
    return bool(
        re.fullmatch(r'/home/[^/]+/\.local/share/claude/versions/[0-9][^/]*', exe)
        or re.fullmatch(r'/home/[^/]+/\.nvm/versions/node/[^/]+/lib/node_modules/@openai/(?:codex|\.codex-[^/]+)/node_modules/@openai/codex-linux-[^/]+/vendor/[^/]+/bin/codex', exe)
    )


def _shell_command_index(p):
    if p.exe.rsplit('/', 1)[-1] not in ('sh', 'bash', 'dash', 'zsh', 'ksh', 'fish'):
        return None
    for i, arg in enumerate(p.argv[1:], 1):
        if arg in ('--noprofile', '--norc', '--login'):
            continue
        # Stop at a script filename or uncertain option syntax/operands.
        if not re.fullmatch(r'-[abcefhiklmnprstuvxBCEHPT]+', arg):
            return None
        if 'c' in arg[1:]:
            return i + 1 if i + 1 < len(p.argv) else None
    return None


def _helper_match(p, argv):
    # Conservative false exclusions are preferable to stopping agent plumbing.
    labels = (p.exe, *argv[:12])
    return (any(re.search(r'(?i)(?:mcp|codex-code-mode|chrome-native-host|claude-in-chrome|--stdio)', x) for x in labels)
            or any(re.search(r'/\.(?:claude[^/]*|codex)/plugins/', x) for x in (*labels, p.cwd)))


def is_helper(p):
    # A shell program can mention plugins/tests without executing a helper.
    # Classify its actual child executable when it appears, not its script text.
    script = _shell_command_index(p)
    return _helper_match(p, tuple(x for i, x in enumerate(p.argv) if i != script))


@dataclass
class Member:
    session: str
    job: str | None
    protected: bool = False
    agent: bool = False


@dataclass
class Job:
    id: str
    session: str
    root_pid: int
    start: int
    baseline: bool
    cwd: str
    exe: str
    pss: int = 0
    swap: int = 0
    tainted: bool = False
    reason: str = ''


class Registry:
    def __init__(self, uid, boot, cutoff):
        self.uid, self.boot, self.cutoff = uid, boot, cutoff
        self.members = {}
        self.jobs = {}
        self.sessions = {}
        self.processes = {}
        self.group_prefix = ''

    def reconcile(self, processes):
        current = {p.pid: p for p in processes if p.uid == self.uid and p.state != 'Z'}
        self.processes = current
        live_keys = {p.key for p in current.values()}
        # Existing keys survive reparenting, but a reused PID never matches.
        self.members = {k: m for k, m in self.members.items() if k in live_keys}
        repaired = self._repair_shell_false_positives(current)
        pending = sorted(current.values(), key=lambda p: (p.start, p.pid))
        for _ in range(len(pending) + 1):
            progress = False
            remaining = []
            for p in pending:
                parent = current.get(p.ppid)
                pm = self.members.get(parent.key) if parent and parent.start <= p.start else None
                old = self.members.get(p.key)
                if is_agent(p):
                    sid = f'a-{p.pid}-{p.start}'
                    self.sessions.setdefault(sid, {'pid': p.pid, 'start': p.start, 'exe': p.exe, 'cwd': p.cwd})
                    self.members[p.key] = Member(sid, None, False, True)
                elif old and not old.agent:
                    if old.protected or is_helper(p) or (pm and pm.protected):
                        self.members[p.key] = Member(old.session, None, True)
                    elif pm and pm.session != old.session:
                        if pm.job:
                            previous = self.jobs.get(old.job)
                            if previous:
                                self.jobs[pm.job].baseline |= previous.baseline
                                self.jobs[pm.job].tainted |= previous.tainted
                            self.members[p.key] = Member(pm.session, pm.job)
                        else:
                            self._new_job(p, pm.session)
                    # A child adopting a new agent role is handled above; ordinary exec preserves jobs.
                elif pm:
                    if pm.protected or is_helper(p):
                        self.members[p.key] = Member(pm.session, None, True)
                    elif pm.job:
                        self.members[p.key] = Member(pm.session, pm.job)
                    else:
                        self._new_job(p, pm.session)
                else:
                    # Only root-owned dedicated cgroups created by this daemon are proof.
                    inherited = self._from_cgroup(p)
                    if inherited:
                        self.members[p.key] = inherited
                    else:
                        remaining.append(p)
                        continue
                progress = True
            if not progress:
                break
            pending = remaining
        # Previously protected work must never become a new memory victim.
        for key in repaired:
            member = self.members.get(key)
            if member and member.job:
                self.jobs[member.job].baseline = True

    def _repair_shell_false_positives(self, current):
        """Recover only proven shell-text false positives from older state."""
        repaired = set()
        for p in current.values():
            old = self.members.get(p.key)
            parent = current.get(p.ppid)
            if (old and old.protected and parent and parent.start <= p.start
                    and is_agent(parent) and old.session == f'a-{parent.pid}-{parent.start}'
                    and _shell_command_index(p) is not None
                    and _helper_match(p, p.argv) and not is_helper(p)):
                repaired.add(p.key)
        # Preserve genuine helpers, unknown orphans and their descendants.
        while True:
            added = set()
            for p in current.values():
                parent = current.get(p.ppid)
                old = self.members.get(p.key)
                if (old and old.protected and parent and parent.start <= p.start
                        and parent.key in repaired and p.key not in repaired
                        and not is_agent(p) and not is_helper(p)
                        and old.session == self.members[parent.key].session):
                    added.add(p.key)
            if not added:
                break
            repaired.update(added)
        for key in repaired:
            del self.members[key]
        return repaired

    def _new_job(self, p, session):
        jid = f'j-{p.pid}-{p.start}'
        old = self.members.get(p.key)
        old_job = self.jobs.get(old.job) if old and old.job else None
        baseline = p.start <= self.cutoff or bool(old_job and old_job.baseline)
        tainted = bool(old_job and old_job.tainted) or self.sessions.get(session, {}).get('tainted', False)
        self.jobs.setdefault(jid, Job(jid, session, p.pid, p.start, baseline, p.cwd, p.exe))
        self.jobs[jid].baseline |= baseline
        self.jobs[jid].tainted |= tainted
        self.jobs[jid].session = session
        self.members[p.key] = Member(session, jid)

    def _from_cgroup(self, p):
        if not self.group_prefix:
            return None
        parts = p.cgroup.removeprefix(self.group_prefix + '/').split('/')
        if not p.cgroup.startswith(self.group_prefix + '/') or len(parts) != 2:
            return None
        area, ident = parts
        if area == 'work' and ident in self.jobs and not self.jobs[ident].tainted:
            j = self.jobs[ident]
            return Member(j.session, None if is_helper(p) else j.id, is_helper(p))
        if area == 'control' and ident in self.sessions and not self.sessions[ident].get('tainted'):
            # Could be an MCP child whose parent vanished before discovery.
            # Session provenance is known; safe work/helper boundary is not.
            return Member(ident, None, True)
        return None

    def export(self):
        return {'version': 1, 'uid': self.uid, 'boot': self.boot, 'cutoff': self.cutoff,
                'members': {k: asdict(v) for k, v in self.members.items()},
                'jobs': {k: asdict(v) for k, v in self.jobs.items()}, 'sessions': self.sessions}

    @classmethod
    def restore(cls, data, uid, boot, cutoff):
        result = cls(uid, boot, cutoff)
        if data.get('boot') != boot or data.get('uid') != uid or data.get('version') != 1:
            return result
        result.cutoff = int(data['cutoff'])
        result.members = {k: Member(**v) for k, v in data['members'].items()}
        result.jobs = {k: Job(**v) for k, v in data['jobs'].items()}
        result.sessions = data['sessions']
        # Never construct paths from unvalidated persisted identifiers.
        if any(not re.fullmatch(r'j-\d+-\d+', k) for k in result.jobs):
            raise ValueError('invalid persisted job ID')
        if any(not re.fullmatch(r'a-\d+-\d+', k) for k in result.sessions):
            raise ValueError('invalid persisted session ID')
        return result
