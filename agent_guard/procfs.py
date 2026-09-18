"""Read process identities without exporting commands or environment secrets."""
import os
from pathlib import Path
from .model import Process


class ProcFS:
    def __init__(self, root='/proc'):
        self.root = Path(root)

    def identity(self, pid):
        try:
            raw = (self.root / str(pid) / 'stat').read_text()
            fields = raw[raw.rfind(')') + 2:].split()
            return int(fields[19])
        except (OSError, ValueError, IndexError):
            return None

    def read(self, pid):
        d = self.root / str(pid)
        try:
            raw = (d / 'stat').read_text()
            fields = raw[raw.rfind(')') + 2:].split()
            start = int(fields[19])
            status = dict(line.split(':', 1) for line in (d / 'status').read_text().splitlines() if ':' in line)
            exe = os.readlink(d / 'exe').removesuffix(' (deleted)') if fields[0] != 'Z' else ''
            args = (d / 'cmdline').read_bytes()[:65536].decode('utf-8', 'replace').split('\0')
            cg = next((line[3:] for line in (d / 'cgroup').read_text().splitlines() if line.startswith('0::')), '')
            try:
                cwd = os.readlink(d / 'cwd')
            except OSError:
                cwd = ''
            p = Process(pid, int(fields[1]), start, int(status['Uid'].split()[0]), exe, tuple(args), cg, cwd, fields[0], int(status.get('VmRSS', '0').split()[0]) * 1024)
            return p if self.identity(pid) == start else None
        except (OSError, ValueError, IndexError, KeyError):
            return None

    def scan(self, uid):
        result = []
        for d in self.root.iterdir():
            if not d.name.isdigit():
                continue
            try:
                if d.stat().st_uid != uid:
                    continue
            except OSError:
                continue
            p = self.read(int(d.name))
            if p and p.uid == uid:
                result.append(p)
        return result

    def memory(self, p):
        if self.identity(p.pid) != p.start:
            return None
        try:
            data = dict(line.split(':', 1) for line in (self.root / str(p.pid) / 'smaps_rollup').read_text().splitlines() if ':' in line)
            pss = int(data['Pss'].split()[0]) * 1024
            swap = int(data['SwapPss'].split()[0]) * 1024
            return (pss, swap) if self.identity(p.pid) == p.start else None
        except (OSError, ValueError, KeyError):
            return None

    def orphan_hints(self, known, uid):
        candidates = []
        for p in self.scan(uid):
            if p.key in known or p.state == 'Z':
                continue
            hints = []
            for fd in (1, 2):
                try:
                    target = os.readlink(self.root / str(p.pid) / 'fd' / str(fd))
                    if target.startswith(f'/tmp/claude-{uid}/'):
                        hints.append(target)
                except OSError:
                    pass
            if hints:
                candidates.append({'pid': p.pid, 'start': p.start, 'exe': p.exe, 'cwd': p.cwd,
                                   'evidence': sorted(set(hints)), 'action': 'report-only'})
        return candidates
