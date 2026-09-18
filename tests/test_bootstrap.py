"""Exercise the Bash installer with real archives and isolated system commands."""
import io
import os
import pwd
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'install.sh'


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.config = self.root / 'config.json'
        self.runtime = self.root / 'systemd'
        self.runtime.mkdir()
        self.cgroup = self.root / 'cgroup'
        self.cgroup.mkdir()
        (self.cgroup / 'cgroup.controllers').write_text('cpuset cpu memory pids')
        self.log = self.root / 'calls'
        self.archive = self.root / 'source.tar.gz'
        self.make_archive()
        self.target_uid = os.getuid() or pwd.getpwnam('nobody').pw_uid
        self.stub('uname', 'echo "${TEST_OS:-Linux}"')
        self.stub('systemctl', 'echo "systemd ${TEST_SYSTEMD:-255}"')
        self.stub('id', 'echo "${TEST_UID:-' + str(self.target_uid) + '}"')
        self.stub('curl', '''printf 'download\n' >> "$TEST_LOG"
if [[ ${TEST_DOWNLOAD_FAIL:-0} == 1 ]]; then exit 22; fi
while (( $# )); do
  if [[ $1 == --output ]]; then cp "$TEST_ARCHIVE" "$2"; exit; fi
  shift
done
exit 1''')
        self.stub('sudo', '''printf 'sudo' >> "$TEST_LOG"
printf ' <%s>' "$@" >> "$TEST_LOG"
printf '\n' >> "$TEST_LOG"
/usr/bin/python3 -c 'import os,sys; from pathlib import Path; p=Path(sys.argv[1]); p.mkdir(mode=0o755); os.close(os.open(p/"command", os.O_CREAT|os.O_WRONLY, 0o755))' "$TEST_INSTALL_ROOT"
exit "${TEST_INSTALL_EXIT:-0}"''')

    def stub(self, name, body):
        p = self.bin / name
        p.write_text('#!/bin/bash\nset -eu\n' + body + '\n')
        p.chmod(0o755)

    def make_archive(self, unsafe=None):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name in ('install.py', 'agent_guard/__init__.py', 'packaging/agent-guard.service', 'tests/test_events.py'):
                info = tarfile.TarInfo('source/' + name)
                data = b'# fixture\n'
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            if unsafe:
                archive.addfile(unsafe)

    def run_script(self, *args, **overrides):
        self.assertTrue(SCRIPT.is_file(), 'install.sh has not been implemented')
        script = self.root / 'install.sh'
        source = SCRIPT.read_text().replace('/etc/agent-guard.json', str(self.config))
        source = source.replace('/run/systemd/system', str(self.runtime))
        source = source.replace('/sys/fs/cgroup', str(self.cgroup))
        script.write_text(source)
        env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'],
                   TMPDIR=str(self.root), TEST_LOG=str(self.log), TEST_ARCHIVE=str(self.archive),
                   TEST_INSTALL_ROOT=str(self.root / 'installed'))
        env.pop('SUDO_UID', None)
        env.update(overrides)
        return subprocess.run(['bash', str(script), *args], env=env, text=True,
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=15)

    def calls(self):
        return self.log.read_text() if self.log.exists() else ''

    def assert_clean(self):
        self.assertEqual(list(self.root.glob('agent-guard.*')), [])

    def test_default_installs_and_enables_for_current_user(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'<--uid> <{self.target_uid}> <--enforce-new>', self.calls())
        self.assert_clean()

    def test_observation_option_does_not_enable_limits(self):
        result = self.run_script('--observe')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'<--uid> <{self.target_uid}>', self.calls())
        self.assertNotIn('--enforce-new', self.calls())

    def test_installed_launcher_and_directory_are_accessible_to_target_user(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in (self.root / 'installed', self.root / 'installed/command'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)

    def test_existing_installation_updates_without_changing_mode(self):
        self.config.write_text('{}')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('<--update>', self.calls())
        self.assertNotIn('--enforce-new', self.calls())

    def test_observe_option_rejected_for_existing_installation(self):
        self.config.write_text('{}')
        result = self.run_script('--observe')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('sudo', self.calls())

    def test_download_failure_never_elevates_and_cleans_up(self):
        result = self.run_script(TEST_DOWNLOAD_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('sudo', self.calls())
        self.assert_clean()

    def test_installer_failure_propagates_and_cleans_up(self):
        result = self.run_script(TEST_INSTALL_EXIT='9')
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assert_clean()

    def test_path_traversal_archive_never_elevates(self):
        self.make_archive(tarfile.TarInfo('../outside'))
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('sudo', self.calls())
        self.assertFalse((self.root / 'outside').exists())
        self.assert_clean()

    def test_symlink_archive_never_elevates(self):
        link = tarfile.TarInfo('source/linked')
        link.type = tarfile.SYMTYPE
        link.linkname = '/etc'
        self.make_archive(link)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('sudo', self.calls())

    def test_check_downloads_and_validates_without_elevation(self):
        result = self.run_script('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('download', self.calls())
        self.assertNotIn('sudo', self.calls())
        self.assert_clean()

    def test_bad_arguments_fail_before_download(self):
        for args in (('--uid',), ('--uid', '0'), ('--uid', 'oops'), ('--unknown',)):
            with self.subTest(args=args):
                result = self.run_script(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), '')

    def test_unsupported_system_fails_before_download(self):
        for env in ({'TEST_OS': 'Darwin'}, {'TEST_SYSTEMD': '249'}, {'TEST_UID': '0'}):
            with self.subTest(env=env):
                result = self.run_script(**env)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), '')

    def test_help_does_not_download(self):
        result = self.run_script('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--observe', result.stdout)
        self.assertEqual(self.calls(), '')


if __name__ == '__main__':
    unittest.main()
