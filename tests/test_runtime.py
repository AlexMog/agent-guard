import unittest
from unittest.mock import Mock
from agent_guard.runtime import Config, measure, restore_registry
from agent_guard.model import Process, Registry


class RuntimeTests(unittest.TestCase):
    def registry(self):
        r = Registry(1000, 'boot', 10)
        r.reconcile([
            Process(10, 1, 10, 1000, '/home/developer/.local/share/claude/versions/2.1.0', (), '', '', 'S', 0),
            Process(20, 10, 20, 1000, '/usr/bin/bash', (), '', '', 'S', 0),
        ])
        return r

    def test_missing_memory_disables_action(self):
        r = self.registry()
        fs = Mock()
        fs.memory.return_value = None
        fs.identity.return_value = 20
        total, complete, swap = measure(r, fs)
        self.assertFalse(complete)

    def test_memory_uses_pss_and_excludes_agent(self):
        r = self.registry()
        fs = Mock()
        fs.memory.return_value = (1024, 2048)
        self.assertEqual(measure(r, fs), (1024, True, 2048))
        fs.memory.assert_called_once()

    def test_observe_to_enforce_grandfathers_live_jobs(self):
        r = self.registry()
        data = {'registry': r.export(), 'mode': 'observe'}
        new = restore_registry(data, Config(mode='enforce'), 'boot', 999)
        self.assertTrue(next(iter(new.jobs.values())).baseline)
        self.assertEqual(new.cutoff, 999)

    def test_enforce_restart_does_not_reset_policy(self):
        r = self.registry()
        new = restore_registry({'registry': r.export(), 'mode': 'enforce'}, Config(mode='enforce'), 'boot', 999)
        self.assertFalse(next(iter(new.jobs.values())).baseline)
        self.assertEqual(new.cutoff, 10)

    def test_crash_during_attachment_quarantines_pending_groups(self):
        r = self.registry()
        jid = next(iter(r.jobs))
        data = {'registry': r.export(), 'mode': 'enforce', 'pending_attachments': {'jobs': [jid], 'sessions': []}}
        new = restore_registry(data, Config(mode='enforce'), 'boot', 999)
        self.assertTrue(new.jobs[jid].tainted)

    def test_cleanup_snapshot_cannot_erase_inflight_attachment_marker(self):
        from agent_guard.daemon import Daemon
        d = object.__new__(Daemon)
        d.registry = self.registry()
        d.config = Config(mode='enforce')
        jid = next(iter(d.registry.jobs))
        d.pending_attachments = {'jobs': [jid], 'sessions': []}
        restored = restore_registry(d.state(), d.config, 'boot', 999)
        self.assertTrue(restored.jobs[jid].tainted)

    def test_event_loss_during_sampling_blocks_termination(self):
        from agent_guard.daemon import Daemon
        d = object.__new__(Daemon)
        d.config = Config(mode='enforce', memory_bytes=100, minimum_job_bytes=1)
        d.registry = self.registry()
        d.proc = Mock()
        d.events = Mock(healthy=True)
        def read_memory(_):
            d.events.healthy = False
            return 200, 0
        d.proc.memory.side_effect = read_memory
        d.cg = Mock()
        d.cg.pids.return_value = []
        d.event_ok = True
        d.pending = None
        d.gate = Mock()
        d.gate.ready.return_value = True
        d.store = Mock()
        d.sample()
        d.cg.terminate.assert_not_called()

    def test_config_rejects_dangerous_or_unknown_options(self):
        for config in ({'uid': 0}, {'mode': 'kill-all'}, {'memory_bytes': 0}, {'cpu_fraction': 2}, {'observation_seconds': 0}, {'unexpected': True}):
            with self.subTest(config=config), self.assertRaises((ValueError, TypeError)):
                Config(**config)


if __name__ == '__main__':
    unittest.main()
