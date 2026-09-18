import tempfile
import unittest
from pathlib import Path
from install import write_new


class InstallerSafetyTests(unittest.TestCase):
    def test_dangling_symlink_never_followed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)
            (path / 'config').symlink_to(path / 'victim')
            with self.assertRaises(FileExistsError):
                write_new(path / 'config', 'unsafe', 0o644)
            self.assertFalse((path / 'victim').exists())

    def test_existing_regular_file_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'config'
            path.write_text('keep')
            with self.assertRaises(FileExistsError):
                write_new(path, 'replace', 0o644)
            self.assertEqual(path.read_text(), 'keep')
