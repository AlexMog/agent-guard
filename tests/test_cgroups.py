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


if __name__ == '__main__':
    unittest.main()
