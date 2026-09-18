"""Atomic state and durable bounded audit records in a trusted directory."""
import datetime
import json
import os
from pathlib import Path
import stat
import tempfile


class Store:
    def __init__(self, root, owner=0, max_log=2 * 1024 * 1024):
        self.root, self.owner, self.max_log = Path(root), owner, max_log
        self._check(self.root, directory=True)

    def _check(self, path, directory=False):
        st = path.lstat()
        valid_type = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
        if not valid_type or st.st_uid != self.owner or st.st_mode & 0o022:
            raise ValueError(f'unsafe ownership, permissions or symlink: {path}')

    def path(self, name):
        if name not in ('state.json', 'status.json', 'events.jsonl', 'events.jsonl.1', 'events.jsonl.2'):
            raise ValueError('invalid state filename')
        return self.root / name

    def load(self, name):
        path = self.path(name)
        if not path.exists() and not path.is_symlink():
            return {}
        self._check(path)
        return json.loads(path.read_text())

    def save(self, name, value):
        path = self.path(name)
        if path.exists() or path.is_symlink():
            self._check(path)
        fd, tmp = tempfile.mkstemp(prefix='.new-', dir=self.root)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(value, stream, sort_keys=True)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o644)
            os.replace(tmp, path)
            dirfd = os.open(self.root, os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def record(self, event, **details):
        path = self.path('events.jsonl')
        if path.exists() or path.is_symlink():
            self._check(path)
            if path.stat().st_size > self.max_log:
                for index in (1, 0):
                    source = self.path('events.jsonl' + (f'.{index}' if index else ''))
                    dest = self.path(f'events.jsonl.{index + 1}')
                    if source.exists():
                        self._check(source)
                        os.replace(source, dest)
        row = {'time': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'event': event, **details}
        encoded = (json.dumps(row, sort_keys=True) + '\n').encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o644)
        try:
            view = memoryview(encoded)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        print(json.dumps(row), flush=True)
