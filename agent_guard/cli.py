import argparse
import json
import os
from pathlib import Path
import sys
import time
from .model import Registry
from .procfs import ProcFS
from .runtime import Config, measure


STATE = Path('/var/lib/agent-guard')


def main():
    parser = argparse.ArgumentParser(prog='agent-guard')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('status')
    explain = sub.add_parser('explain')
    explain.add_argument('pid', type=int)
    audit = sub.add_parser('audit')
    audit.add_argument('--uid', type=int, default=os.getuid())
    audit.add_argument('--orphans', action='store_true')
    daemon = sub.add_parser('daemon')
    daemon.add_argument('--config', default='/etc/agent-guard.json')
    args = parser.parse_args()
    if args.command == 'daemon':
        if os.geteuid() != 0:
            parser.error('daemon requires root; audit/status do not')
        from .storage import Store
        from .daemon import Daemon
        path = Path(args.config)
        # Config cannot be controlled through a user-owned writable file or symlink.
        st = path.lstat()
        import stat
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            parser.error('configuration must be a root-owned non-writable regular file')
        Daemon(Config(**json.loads(path.read_text()))).run()
    elif args.command == 'audit':
        fs = ProcFS()
        ticks = int(float(Path('/proc/uptime').read_text().split()[0]) * os.sysconf('SC_CLK_TCK'))
        r = Registry(args.uid, Path('/proc/sys/kernel/random/boot_id').read_text().strip(), ticks)
        r.reconcile(fs.scan(args.uid))
        total, complete, swap = measure(r, fs)
        from dataclasses import asdict
        report = {'mode': 'read-only', 'sessions': r.sessions, 'jobs': [asdict(j) for j in r.jobs.values()],
                  'work_processes': sum(bool(m.job) for m in r.members.values()),
                  'protected_processes': sum(not m.job for m in r.members.values()),
                  'work_pss_bytes': total, 'work_swap_bytes': swap, 'measurement_complete': complete}
        if args.orphans:
            report['orphan_candidates'] = fs.orphan_hints(r.members, args.uid)
        print(json.dumps(report, indent=2))
    elif args.command == 'status':
        path = STATE / 'status.json'
        if not path.exists():
            print('Agent Guard is not installed or has not produced a status report.')
            return 1
        report = json.loads(path.read_text())
        report['status_age_seconds'] = round(time.time() - report['updated_at'], 1)
        report['status_stale'] = report['status_age_seconds'] > 10
        print(json.dumps(report, indent=2))
    else:
        rows = []
        for name in ('events.jsonl.2', 'events.jsonl.1', 'events.jsonl'):
            path = STATE / name
            if path.exists():
                for line in path.read_text().splitlines():
                    try:
                        row = json.loads(line)
                        if args.pid in row.get('pids', []) or row.get('pid') == args.pid or str(row.get('job', '')).startswith(f'j-{args.pid}-'):
                            rows.append(row)
                    except json.JSONDecodeError:
                        continue
        print(json.dumps({'pid': args.pid, 'records': rows,
                          'note': 'PIDs may be reused; compare job start ticks and timestamps.'}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
