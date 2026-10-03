import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from agent_guard.cgroups import Cgroups, UnsafeAction, validate_members, validate_location
from agent_guard.model import Process, Registry


def process(pid, ppid=1, exe='/usr/bin/bash', start=None):
    return Process(pid, ppid, start or pid * 10, 1000, exe, (), '', '/work', 'S', 0)


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.r = Registry(1000, 'boot', 10)
        self.agent = process(10, exe='/home/developer/.local/share/claude/versions/2.1.0')
        self.work = process(20, 10)
        self.r.reconcile([self.agent, self.work])
        self.job = next(iter(self.r.jobs.values()))

    def test_unknown_member_aborts_whole_group(self):
        with self.assertRaises(UnsafeAction):
            validate_members([self.work, process(30)], self.r, self.job)

    def test_changed_identity_aborts(self):
        with self.assertRaises(UnsafeAction):
            validate_members([process(20, start=999)], self.r, self.job)

    def test_agent_in_job_aborts(self):
        with self.assertRaises(UnsafeAction):
            validate_members([self.agent, self.work], self.r, self.job)

    def test_managed_codex_daemon_aborts_even_with_stale_workload_membership(self):
        from dataclasses import replace
        daemon = replace(self.work, exe='/home/developer/.codex/packages/app-server-daemon/releases/0.160.0-x86_64-unknown-linux-musl/bin/codex')
        with self.assertRaises(UnsafeAction):
            validate_members([daemon], self.r, self.job)

    def test_empty_group_aborts(self):
        with self.assertRaises(UnsafeAction):
            validate_members([], self.r, self.job)

    def test_root_refuses_user_owned_lookalike_service_path(self):
        with self.assertRaises(UnsafeAction):
            validate_location('/user.slice/user-1000.slice/agent-guard.service', 0)
        with self.assertRaises(UnsafeAction):
            validate_location('/system.slice/agent-guard-integration-test.service', 0)
        validate_location('/system.slice/agent-guard.service', 0)

    def test_valid_members_accepted(self):
        self.assertEqual(validate_members([self.work], self.r, self.job), [self.work])

    def test_unsafe_job_identifier_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as d:
            cg = Cgroups(Path(d), Mock())
            with self.assertRaises(ValueError):
                cg.job_path('../../etc')

    def test_pid_reuse_prevents_cgroup_write(self):
        with tempfile.TemporaryDirectory() as d:
            fs = Mock()
            fs.read.return_value = process(20, start=999)
            cg = Cgroups(Path(d), fs)
            target = Path(d) / 'destination'
            target.mkdir()
            f = target / 'cgroup.procs'
            f.write_text('original')
            with patch('os.pidfd_open', return_value=123), patch('os.close'):
                self.assertFalse(cg.attach(self.work, target))
            self.assertEqual(f.read_text(), 'original')

    def test_invalid_members_never_signaled_and_group_is_thawed(self):
        with tempfile.TemporaryDirectory() as d:
            cg = Cgroups(Path(d), Mock())
            with patch.object(cg, 'freeze') as freeze, patch.object(cg, 'members', return_value=[self.agent]), patch('signal.pidfd_send_signal') as send:
                with self.assertRaises(UnsafeAction):
                    cg.terminate(self.job, self.r, Mock())
                send.assert_not_called()
                self.assertEqual(freeze.call_args_list[-1].args[1], False)

    def test_loss_detected_during_audit_aborts_before_first_signal(self):
        with tempfile.TemporaryDirectory() as d:
            fs = Mock()
            fs.read.return_value = self.work
            cg = Cgroups(Path(d), fs)
            healthy = [True]
            def record(*args, **kwargs):
                healthy[0] = False
            with patch.object(cg, 'freeze'), patch.object(cg, 'members', return_value=[self.work]), patch('os.pidfd_open', return_value=123), patch('os.close'), patch('signal.pidfd_send_signal') as send:
                with self.assertRaises(UnsafeAction):
                    cg.terminate(self.job, self.r, record, authorize=lambda: healthy[0])
                send.assert_not_called()


class CpuBoundaryTests(unittest.TestCase):
    def test_shared_parent_caps_control_and_work_without_shrinking_on_restart(self):
        with tempfile.TemporaryDirectory() as d:
            parent = Path(d)
            (parent / 'cpuset.cpus.effective').write_text('0-15')
            root = parent / 'guard'
            (root / 'work').mkdir(parents=True)
            (root / 'cpu.max').write_text('max 100000')
            (root / 'work/cpu.max').write_text('800000 100000')
            (root / 'cpuset.cpus').write_text('0-7')
            cg = Cgroups(root, Mock())
            with patch('os.cpu_count', return_value=16):
                cg.configure_cpu(0.5)
                cg.configure_cpu(0.5)
            self.assertEqual((root / 'cpu.max').read_text(), '800000 100000')
            self.assertEqual((root / 'work/cpu.max').read_text(), 'max 100000')
            self.assertEqual((root / 'cpuset.cpus').read_text(), '0,1,2,3,4,5,6,7')
            cg.release_cpu()
            self.assertEqual((root / 'cpu.max').read_text(), 'max 100000')
            self.assertEqual((root / 'cpuset.cpus').read_text().strip(), '0-15')

    def test_sparse_parent_cpu_set_is_respected(self):
        with tempfile.TemporaryDirectory() as d:
            parent = Path(d)
            (parent / 'cpuset.cpus.effective').write_text('2-3,8,10-12')
            root = parent / 'guard'
            (root / 'work').mkdir(parents=True)
            (root / 'cpu.max').write_text('max 100000')
            (root / 'work/cpu.max').write_text('max 100000')
            (root / 'cpuset.cpus').touch()
            with patch('os.cpu_count', return_value=8):
                Cgroups(root, Mock()).configure_cpu(0.5)
            self.assertEqual((root / 'cpuset.cpus').read_text(), '2,3,8,10')

    def test_failed_configuration_restores_preexisting_limits(self):
        with tempfile.TemporaryDirectory() as d:
            parent = Path(d)
            (parent / 'cpuset.cpus.effective').write_text('0-15')
            root = parent / 'guard'
            (root / 'work').mkdir(parents=True)
            original = {root / 'cpu.max': 'max 100000',
                        root / 'work/cpu.max': '800000 100000', root / 'cpuset.cpus': '0-15'}
            for p, text in original.items():
                p.write_text(text)
            write = Path.write_text
            def fail_work(path, text, *args, **kwargs):
                if path == root / 'work/cpu.max':
                    raise OSError('injected write failure')
                return write(path, text, *args, **kwargs)
            with patch.object(Path, 'write_text', fail_work), patch('os.cpu_count', return_value=16):
                with self.assertRaises(OSError):
                    Cgroups(root, Mock()).configure_cpu(0.5)
            self.assertEqual({p:p.read_text() for p in original}, original)

    def test_missing_cpuset_refuses_silent_production_downgrade(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'work').mkdir()
            with self.assertRaises(RuntimeError):
                Cgroups(root, Mock()).configure_cpu(0.5)


UNIT = '/system.slice/agent-guard.service'


class CappedSubgroupTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.fs = Path(temp.name)
        (self.fs / 'system.slice').mkdir()
        (self.fs / 'system.slice/cpuset.cpus.effective').write_text('0-15\n')
        self.unit = self.fs / UNIT.lstrip('/')
        self.capped = self.unit / 'capped'
        (self.capped / 'work').mkdir(parents=True)
        self.unit.chmod(0o755)
        files = {'cgroup.procs': '', 'cgroup.controllers': 'cpuset cpu memory pids\n', 'cpu.max': 'max 100000\n',
                 'cpuset.cpus.effective': '0-15\n', 'capped/cpu.max': 'max 100000\n',
                 'capped/cpuset.cpus': '\n', 'capped/work/cpu.max': 'max 100000\n'}
        for name, text in files.items():
            (self.unit / name).write_text(text)
        patcher = patch('agent_guard.cgroups.CGROUP_FS', self.fs)
        patcher.start()
        self.addCleanup(patcher.stop)

    def delegated(self):
        proc = Mock()
        proc.read.return_value = Process(1, 0, 1, 0, '/usr/bin/python3', (), UNIT + '/supervisor', '/', 'S', 0)
        with patch('agent_guard.cgroups.validate_location'), patch('os.cpu_count', return_value=16):
            return Cgroups.delegated(proc, 0.5)

    def test_cap_lives_on_owned_subgroup_with_supervisor_outside(self):
        cg = self.delegated()
        self.assertEqual(cg.root, self.capped)
        self.assertEqual(cg.relative, UNIT + '/capped')
        self.assertEqual((self.capped / 'cpu.max').read_text(), '800000 100000')
        self.assertEqual((self.capped / 'cpuset.cpus').read_text(), '0,1,2,3,4,5,6,7')
        self.assertEqual((self.unit / 'cpu.max').read_text(), 'max 100000\n')
        self.assertEqual((self.unit / 'supervisor/cpu.weight').read_text(), '10000')
        for group in (self.unit, self.capped, self.capped / 'control', self.capped / 'work'):
            self.assertIn('+cpu', (group / 'cgroup.subtree_control').read_text())
        self.assertFalse((self.unit / 'control').exists())
        self.assertFalse((self.unit / 'work').exists())
        self.assertEqual(cg.job_path('j-2-20'), self.capped / 'work/j-2-20')
        self.assertEqual(cg.session_path('a-1-10'), self.capped / 'control/a-1-10')

    def test_stale_limits_on_unit_cgroup_are_reset_to_systemd_defaults(self):
        (self.unit / 'cpu.max').write_text('800000 100000\n')
        (self.unit / 'cpuset.cpus').write_text('0-7\n')
        (self.unit / 'work').mkdir()
        (self.unit / 'work/cpu.max').write_text('800000 100000\n')
        self.delegated()
        self.assertEqual((self.unit / 'cpu.max').read_text(), 'max 100000')
        self.assertEqual((self.unit / 'cpuset.cpus').read_text(), '0-15\n')
        self.assertEqual((self.unit / 'work/cpu.max').read_text(), 'max 100000')

    def test_inherited_unit_cpuset_is_left_to_systemd(self):
        (self.unit / 'cpu.max').write_text('max 100000\n')
        (self.unit / 'cpuset.cpus').write_text('\n')
        self.delegated()
        self.assertEqual((self.unit / 'cpu.max').read_text(), 'max 100000\n')
        self.assertEqual((self.unit / 'cpuset.cpus').read_text(), '\n')

    def test_previous_layout_groups_move_under_capped_with_identity_checks(self):
        session = self.unit / 'control/a-1-10'
        job = self.unit / 'work/j-2-20'
        for group, pids in ((session, '10\n'), (job, '20\n21\n')):
            group.mkdir(parents=True)
            (group / 'cgroup.procs').write_text(pids)
            (group / 'cgroup.freeze').write_text('1')
        members = {10: Process(10, 1, 100, 1000, '/x', (), UNIT + '/control/a-1-10', '/', 'S', 0),
                   20: Process(20, 1, 200, 1000, '/x', (), UNIT + '/work/j-2-20', '/', 'S', 0),
                   21: Process(21, 1, 210, 1000, '/x', (), '/user.slice/reused', '/', 'S', 0)}
        cg = Cgroups(self.capped, Mock(read=members.get))
        groups = cg.legacy_groups()
        self.assertEqual(sorted(groups), [session, job])
        with patch.object(cg, 'attach', side_effect=[True, UnsafeAction('exited during attachment')]) as attach:
            ambiguous = cg.adopt(groups)
        self.assertEqual(ambiguous, {'j-2-20': 'exited during attachment'})
        self.assertEqual([c.args for c in attach.call_args_list],
                         [(members[10], self.capped / 'control/a-1-10'), (members[20], self.capped / 'work/j-2-20')])
        self.assertEqual((job / 'cgroup.freeze').read_text(), '0')
        self.assertEqual((session / 'cgroup.freeze').read_text(), '0')

    def test_previous_layout_directories_with_unexpected_names_are_left_alone(self):
        for name in ('control/j-2-20', 'control/other', 'work/a-1-10', 'work/other'):
            (self.unit / name).mkdir(parents=True)
        (self.unit / 'work/j-2-20').mkdir()
        self.assertEqual(Cgroups(self.capped, Mock()).legacy_groups(), [self.unit / 'work/j-2-20'])

    def test_fresh_layout_has_no_previous_groups(self):
        self.assertEqual(Cgroups(self.capped, Mock()).legacy_groups(), [])

    def test_cap_status_reads_the_kernel_value_back(self):
        cg = Cgroups(self.capped, Mock())
        self.assertFalse(cg.cpu_capped)
        with patch('os.cpu_count', return_value=16):
            cg.configure_cpu(0.5)
        self.assertTrue(cg.cpu_capped)
        (self.capped / 'cpu.max').write_text('max 100000\n')
        self.assertFalse(cg.cpu_capped)
        (self.capped / 'cpu.max').unlink()
        self.assertFalse(cg.cpu_capped)


if __name__ == '__main__':
    unittest.main()
