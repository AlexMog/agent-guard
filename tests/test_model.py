import unittest
from agent_guard.model import Process, Registry, is_agent, is_helper
from agent_guard.policy import choose_victim, Gate


AGENT = '/home/developer/.local/share/claude/versions/2.1.257'


def proc(pid, ppid=1, start=None, exe='/usr/bin/bash', argv=(), cgroup=''):
    return Process(pid, ppid, start or pid * 10, 1000, exe, tuple(argv), cgroup, '/work', 'S', 0)


class ModelTests(unittest.TestCase):
    def registry(self):
        return Registry(1000, 'boot', 5000)

    def test_real_executable_not_comm_or_argument(self):
        self.assertTrue(is_agent(proc(10, exe=AGENT)))
        self.assertFalse(is_agent(proc(10, argv=('claude',))))
        self.assertFalse(is_agent(proc(10, exe='/tmp/claude')))

    def test_mcp_helper_and_descendants_never_jobs(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT), proc(20, 10, argv=('node', '/x/mcp-server/main.js')), proc(30, 20)])
        self.assertEqual(len(r.jobs), 0)
        self.assertTrue(r.members['30:300'].protected)

    def test_agent_plugin_runtime_is_protected_even_without_mcp_in_argv(self):
        from dataclasses import replace
        plugin = replace(proc(20, 10, exe='/home/developer/.bun/bin/bun'),
                         cwd='/home/developer/.claude-example/plugins/cache/claude-plugins-official/discord/0.0.4')
        self.assertTrue(is_helper(plugin))

    def test_ancestry_groups_whole_work_and_ignores_manual_sibling(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT), proc(20, 10), proc(30, 20), proc(40, 1)])
        self.assertEqual(len(r.jobs), 1)
        self.assertEqual(r.members['20:200'].job, r.members['30:300'].job)
        self.assertNotIn('40:400', r.members)

    def test_pid_reuse_never_inherits_provenance(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT), proc(20, 10)])
        r.reconcile([proc(20, 1, start=9999)])
        self.assertNotIn('20:9999', r.members)

    def test_known_orphan_retains_identity_and_job(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT), proc(20, 10)])
        job = r.members['20:200'].job
        r.reconcile([proc(20, 1)])
        self.assertEqual(r.members['20:200'].job, job)

    def test_unknown_orphan_with_claude_path_is_not_adopted(self):
        r = self.registry()
        r.reconcile([proc(20, argv=('/tmp/claude-1000/task',))])
        self.assertFalse(r.members)

    def test_nested_agent_is_protected(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT), proc(20, 10), proc(30, 20, exe=AGENT), proc(40, 30)])
        self.assertIsNone(r.members['30:300'].job)
        self.assertNotEqual(r.members['20:200'].job, r.members['40:400'].job)

    def test_existing_work_and_later_descendants_are_grandfathered(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT), proc(20, 10)])
        r.reconcile([proc(10, exe=AGENT), proc(20, 10), proc(30, 20, start=6000), proc(40, 10, start=7000)])
        self.assertTrue(r.jobs[r.members['30:6000'].job].baseline)
        self.assertFalse(r.jobs[r.members['40:7000'].job].baseline)

    def test_state_roundtrip_and_boot_mismatch(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT), proc(20, 10)])
        restored = Registry.restore(r.export(), 1000, 'boot', 8000)
        self.assertEqual(restored.cutoff, 5000)
        self.assertTrue(next(iter(restored.jobs.values())).baseline)
        fresh = Registry.restore(r.export(), 1000, 'different', 8000)
        self.assertFalse(fresh.jobs)

    def test_uid_boundary_and_future_parent_rejected(self):
        r = self.registry()
        r.reconcile([proc(10, start=6000, exe=AGENT), proc(20, 10, start=100)])
        self.assertNotIn('20:100', r.members)

    def test_inherited_group_of_tainted_session_never_adopted(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT)])
        r.group_prefix = '/agent-guard.service'
        r.sessions['a-10-100']['tainted'] = True
        r.reconcile([proc(30, cgroup='/agent-guard.service/control/a-10-100')])
        self.assertNotIn('30:300', r.members)

    def test_child_reassigned_when_parent_execs_nested_agent(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT), proc(20, 10), proc(30, 20)])
        r.reconcile([proc(10, exe=AGENT), proc(20, 10, exe=AGENT), proc(30, 20)])
        self.assertEqual(r.members['30:300'].session, 'a-20-200')

    def test_orphan_in_control_could_be_helper_child_and_is_protected(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT)])
        r.group_prefix = '/agent-guard.service'
        r.reconcile([proc(30, cgroup='/agent-guard.service/control/a-10-100')])
        self.assertTrue(r.members['30:300'].protected)
        self.assertIsNone(r.members['30:300'].job)

    def test_late_child_of_baseline_keeps_protection_after_nested_exec(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT), proc(20, 10), proc(30, 20, start=6000)])
        r.reconcile([proc(10, exe=AGENT), proc(20, 10, exe=AGENT), proc(30, 20, start=6000)])
        self.assertTrue(r.jobs[r.members['30:6000'].job].baseline)

    def test_protected_descendant_keeps_protection_after_parent_agent_exec(self):
        r = self.registry()
        r.reconcile([proc(10, exe=AGENT), proc(20, 10, argv=('mcp-server',)), proc(30, 20)])
        r.reconcile([proc(10, exe=AGENT), proc(20, 10, exe=AGENT), proc(30, 20)])
        self.assertTrue(r.members['30:300'].protected)

    def test_reparenting_into_other_session_cannot_remove_taint(self):
        r = Registry(1000, 'boot', 10)
        r.reconcile([proc(10, exe=AGENT), proc(20, 10), proc(30, 20), proc(40, exe=AGENT), proc(50, 40)])
        r.jobs[r.members['30:300'].job].tainted = True
        r.reconcile([proc(10, exe=AGENT), proc(30, 50, start=600), proc(40, exe=AGENT), proc(50, 40)])
        # New PID identity above must never carry its predecessor's flags or provenance.
        self.assertNotIn('30:300', r.members)
        r = Registry(1000, 'boot', 10)
        r.reconcile([proc(10, exe=AGENT), proc(20, 10), proc(30, 20, start=600), proc(40, exe=AGENT), proc(50, 40)])
        r.jobs[r.members['30:600'].job].tainted = True
        r.reconcile([proc(10, exe=AGENT), proc(30, 50, start=600), proc(40, exe=AGENT), proc(50, 40)])
        self.assertTrue(r.jobs[r.members['30:600'].job].tainted)


class PolicyTests(unittest.TestCase):
    def jobs(self):
        r = Registry(1000, 'boot', 100)
        r.reconcile([proc(1, start=10, exe=AGENT), proc(20, 1), proc(30, 1)])
        jobs = list(r.jobs.values())
        for job in jobs:
            job.pss = 100
        return jobs

    def test_newest_eligible_only(self):
        jobs = self.jobs()
        self.assertEqual(choose_victim(jobs, total=200, limit=150, complete=True, min_bytes=50).root_pid, 30)

    def test_baseline_protected_and_tainted_never_selected(self):
        jobs = self.jobs()
        jobs[1].baseline = True
        self.assertEqual(choose_victim(jobs, 200, 150, True, 50).root_pid, 20)
        jobs[0].tainted = True
        self.assertIsNone(choose_victim(jobs, 200, 150, True, 50))

    def test_no_termination_with_incomplete_measurements_or_below_limit(self):
        jobs = self.jobs()
        self.assertIsNone(choose_victim(jobs, 200, 150, False, 50))
        self.assertIsNone(choose_victim(jobs, 100, 150, True, 50))

    def test_gate_requires_grace_and_consecutive_complete_samples(self):
        gate = Gate(grace=60, samples=3, cooldown=10, started=0)
        self.assertFalse(gate.ready(59, True, True))
        self.assertFalse(gate.ready(60, True, True))
        self.assertFalse(gate.ready(61, True, False))
        self.assertFalse(gate.ready(62, True, True))
        self.assertFalse(gate.ready(63, True, True))
        self.assertTrue(gate.ready(64, True, True))
        gate.acted(64)
        self.assertFalse(gate.ready(65, True, True))


if __name__ == '__main__':
    unittest.main()
