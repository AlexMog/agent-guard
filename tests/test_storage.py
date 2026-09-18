import json
import os
import tempfile
import unittest
from pathlib import Path
from agent_guard.storage import Store


class StorageTests(unittest.TestCase):
    def test_atomic_state_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d), owner=os.getuid())
            store.save('state.json', {'boot': 'test'})
            self.assertEqual(store.load('state.json'), {'boot': 'test'})

    def test_symlink_state_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)
            (path / 'state.json').symlink_to('/etc/passwd')
            store = Store(path, owner=os.getuid())
            with self.assertRaises(ValueError):
                store.load('state.json')

    def test_group_writable_directory_refused(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o777)
            with self.assertRaises(ValueError):
                Store(Path(d), owner=os.getuid())

    def test_audit_log_has_reason_and_rotates(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d), owner=os.getuid(), max_log=150)
            for i in range(10):
                store.record('terminate', reason='budget', pid=i)
            self.assertTrue((Path(d) / 'events.jsonl.1').exists())
            row = json.loads((Path(d) / 'events.jsonl').read_text().splitlines()[-1])
            self.assertEqual(row['reason'], 'budget')


if __name__ == '__main__':
    unittest.main()
