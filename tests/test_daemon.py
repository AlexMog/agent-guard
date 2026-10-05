import json
import os
import threading
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from agent_guard.cgroups import Cgroups, UnsafeAction
from agent_guard.daemon import Daemon
from agent_guard.events import EventPump
from agent_guard.model import Process, Registry
from agent_guard.policy import Gate
from agent_guard.runtime import Config
from agent_guard.storage import Store


AGENT = Process(10, 1, 100, 1000, '/home/developer/.local/share/claude/versions/2.1.0', (),
                '/user.slice/terminal.scope', '/home/developer', 'S', 0)


class Clock:
    """Fake daemon time; a real deadline turns a stuck loop into a failure instead of a hang."""

    def __init__(self):
        self.now = 0.0
        self.deadline = time.monotonic() + 10

    def monotonic(self):
        if time.monotonic() > self.deadline:
            raise AssertionError('daemon loop never recovered its event subscription')
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    def time(self):
        return 1_000_000 + self.now


class IdleStream:
    def receive(self, timeout):
        time.sleep(min(timeout, 0.01))
        return []

    def close(self):
        pass


class ExitingStream(IdleStream):
    def receive(self, timeout):
        raise SystemExit


class DaemonEventHealthTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name)
        for target, value in (('agent_guard.daemon.time', Clock()), ('agent_guard.daemon.signal', Mock()),
                              ('builtins.print', Mock())):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def daemon(self, config):
        with patch('agent_guard.daemon.Store', lambda root: Store(root, owner=os.getuid())):
            d = Daemon(config, self.state)
        d.proc = Mock()
        d.proc.scan.return_value = []
        d.proc.read.return_value = None
        return d

    def run_with_streams(self, d, *streams):
        pumps = []

        def subscribe():
            pumps.append(EventPump(stream=streams[len(pumps)]))
            self.addCleanup(pumps[-1].close)
            if len(pumps) == len(streams):
                d.running = False
            return pumps[-1]

        with patch('agent_guard.daemon.EventPump', side_effect=subscribe):
            d.run()
        return pumps

    def records(self):
        return [json.loads(line) for line in (self.state / 'events.jsonl').read_text().splitlines()]

    def test_silently_stopped_reader_is_recorded_and_resubscribed(self):
        d = self.daemon(Config())
        pumps = self.run_with_streams(d, ExitingStream(), IdleStream())
        self.assertEqual(len(pumps), 2)
        rows = self.records()
        self.assertEqual([r['event'] for r in rows],
                         ['events-connected', 'started', 'event-loss', 'events-connected', 'stopped'])
        self.assertEqual(rows[2]['error'], 'process event reader exited without reporting a loss')
        self.assertTrue(d.event_ok)

    def test_ambiguous_session_attachment_pause_ends_with_a_fresh_subscription(self):
        d = self.daemon(Config(mode='enforce'))
        d.proc.scan.return_value = [AGENT]
        d.proc.read.side_effect = lambda pid: AGENT if pid == AGENT.pid else None
        d.proc.memory.return_value = (0, 0)
        cg = Mock()
        cg.root = self.state / 'owned'
        for section in ('work', 'control'):
            (cg.root / section).mkdir(parents=True)
        cg.relative = '/test'
        cg.session_path.return_value = Path('/sys/fs/cgroup/test/control/a-10-100')
        cg.legacy_groups.return_value = []
        cg.attach.side_effect = [UnsafeAction('process exited during attachment')] + [True] * 100
        with patch('agent_guard.daemon.Cgroups', Mock(delegated=Mock(return_value=cg))):
            self.run_with_streams(d, IdleStream(), IdleStream())
        rows = self.records()
        events = [r['event'] for r in rows]
        self.assertEqual(events, ['events-connected', 'attachment-rejected', 'started', 'event-loss',
                                  'events-connected', 'stopped'])
        self.assertEqual(rows[3]['error'], 'memory decisions paused after an ambiguous session attachment')
        self.assertTrue(d.registry.sessions['a-10-100']['tainted'])
        self.assertTrue(d.event_ok)

    def owned_cgroup(self):
        cg = Mock(root=self.state / 'owned', relative='/test')
        for section in ('work', 'control'):
            (cg.root / section).mkdir(parents=True)
        cg.legacy_groups.return_value = []
        return cg

    def run_enforcing(self, cg):
        d = self.daemon(Config(mode='enforce'))
        with patch('agent_guard.daemon.Cgroups', Mock(delegated=Mock(return_value=cg))):
            self.run_with_streams(d, IdleStream())
        return d

    def test_memory_brake_reclaims_beside_startup_and_is_released_on_stop(self):
        cg = self.owned_cgroup()
        braking, reclaiming = threading.Event(), threading.Event()
        cg.configure_memory.side_effect = lambda _: braking.set() or reclaiming.wait(5)
        started = time.monotonic()
        self.run_enforcing(cg)
        self.assertLess(time.monotonic() - started, 4)
        self.assertTrue(braking.wait(2))
        reclaiming.set()
        cg.configure_memory.assert_called_once_with(Config().brake_bytes)
        cg.release_memory.assert_called_once_with()
        self.assertIn('started', [r['event'] for r in self.records()])

    def test_memory_brake_failure_is_reported_in_status(self):
        d = self.daemon(Config(mode='enforce'))
        d.cg = Mock(configure_memory=Mock(side_effect=OSError('memory.high: permission denied')))
        d.apply_memory_brake()
        d.save()
        status = json.loads((self.state / 'status.json').read_text())
        self.assertEqual(status['memory_brake_error'], 'memory.high: permission denied')
        self.assertEqual(status['memory_brake_bytes'], Config().brake_bytes)

    def test_failed_cpu_release_still_releases_memory_and_records_the_stop(self):
        cg = self.owned_cgroup()
        cg.release_cpu.side_effect = OSError('cpu.max: device busy')
        self.run_enforcing(cg)
        cg.release_memory.assert_called_once_with()
        rows = self.records()
        failed = [r for r in rows if r['event'] == 'release-failed']
        self.assertEqual([(r['step'], r['error']) for r in failed], [('release_cpu', 'cpu.max: device busy')])
        self.assertEqual(rows[-1]['event'], 'stopped')

    def test_repeated_failure_for_a_quarantined_session_keeps_the_subscription(self):
        d = self.daemon(Config(mode='enforce'))
        d.registry = Registry(1000, d.registry.boot, 0)
        d.registry.reconcile([AGENT])
        d.event_ok = True
        d.quarantine('a-10-100')
        self.assertFalse(d.event_ok)
        d.event_ok = True
        d.quarantine('a-10-100')
        self.assertTrue(d.event_ok)
        self.assertTrue(d.registry.sessions['a-10-100']['tainted'])

    def test_full_reconcile_moves_previous_layout_first_marks_it_and_quarantines_ambiguity(self):
        d = self.daemon(Config(mode='enforce'))
        d.registry = Registry(1000, d.registry.boot, 0)
        d.registry.reconcile([AGENT, Process(20, 10, 200, 1000, '/usr/bin/bash', (), '', '/work', 'S', 0)])
        jid = next(iter(d.registry.jobs))
        groups = [Path('/unit/control/a-10-100'), Path('/unit/work') / jid]
        markers = []
        steps = []

        def adopt(given):
            self.assertEqual(given, groups)
            markers.append(d.store.load('state.json')['pending_attachments'])
            steps.append('adopt')
            return {jid: 'process exited during attachment'}

        d.proc.scan.side_effect = lambda uid: steps.append('scan') or []
        owned = self.state / 'owned'
        for section in ('work', 'control'):
            (owned / section).mkdir(parents=True)
        d.cg = Mock(root=owned, legacy_groups=Mock(return_value=groups), adopt=Mock(side_effect=adopt))
        d.reconcile(full=True)
        self.assertEqual(steps, ['adopt', 'scan'])
        self.assertEqual(markers, [{'jobs': [jid], 'sessions': ['a-10-100']}])
        self.assertTrue(d.registry.jobs[jid].tainted)
        self.assertFalse(d.registry.sessions['a-10-100'].get('tainted', False))
        self.assertEqual(d.store.load('state.json')['pending_attachments'], {})
        self.assertEqual(self.records()[-1]['event'], 'attachment-rejected')
        self.assertEqual(self.records()[-1]['group'], jid)


WORKER = Process(20, 10, 200, 1000, '/usr/bin/bash', (), '', '/work', 'S', 0)
NEWER_WORKER = Process(30, 10, 300, 1000, '/usr/bin/bash', (), '', '/work', 'S', 0)

class MemoryDecisionTests(unittest.TestCase):
    """Kernel group accounting decides; a busy machine must not keep the measurement incomplete."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.registry = Registry(1000, 'boot', 0)
        self.registry.reconcile([AGENT, WORKER, NEWER_WORKER])
        self.older, self.newer = sorted(self.registry.jobs.values(), key=lambda j: j.start)

    def charge(self, job, anon, swap=0, pids=None):
        group = self.root / 'work' / job.id
        group.mkdir(parents=True)
        (group / 'memory.stat').write_text(f'anon {anon}\nfile 999999\nshmem 777777\nswapcached 0\n')
        (group / 'memory.swap.current').write_text(f'{swap}\n')
        (group / 'cgroup.procs').write_text(pids or f'{job.root_pid}\n')

    def decide(self, budget=1000):
        d = object.__new__(Daemon)
        d.config = Config(mode='enforce', memory_bytes=budget, minimum_job_bytes=1)
        d.registry = self.registry
        known = {p.pid: p for p in (AGENT, WORKER, NEWER_WORKER)}
        d.proc = Mock(read=known.get, memory=Mock(return_value=(0, 0)))
        d.cg = Cgroups(self.root, d.proc)
        d.events = Mock(healthy=True)
        d.event_ok = True
        d.pending = None
        d.gate = Gate(grace=0, samples=3, cooldown=10, started=0)
        d.store = Mock()
        d.last_message = ''
        d.cache = dict(known)
        self.daemon = d
        with patch.object(d.cg, 'terminate') as terminate:
            for _ in range(3):
                d.sample()
        return terminate

    def victim(self, terminate):
        terminate.assert_called_once()
        return terminate.call_args.args[0]

    def test_workload_forked_since_the_last_scan_does_not_block_the_decision(self):
        self.charge(self.older, 600, pids='20\n4242\n')
        self.charge(self.newer, 600, pids='30\n4343\n')
        self.victim(self.decide())

    def test_largest_workload_is_terminated(self):
        self.charge(self.older, 800)
        self.charge(self.newer, 400)
        self.assertIs(self.victim(self.decide()), self.older)
        decision = next(c for c in self.daemon.store.record.call_args_list if c.args == ('memory-decision',))
        self.assertEqual(decision.kwargs['job_bytes'], 800)

    def test_termination_classifies_children_forked_since_the_last_scan(self):
        self.charge(self.older, 1200)
        classify = self.decide().call_args.kwargs['classify']
        newborn = Process(40, 20, 400, 1000, '/usr/bin/node', (), '', '/work', 'S', 0)
        self.daemon.proc.read = {p.pid: p for p in (AGENT, WORKER, NEWER_WORKER, newborn)}.get
        classify([20, 40])
        self.assertEqual(self.registry.members[newborn.key].job, self.older.id)

    def test_swap_counts_toward_the_budget(self):
        self.charge(self.older, 300, swap=300)
        self.charge(self.newer, 300, swap=300)
        self.victim(self.decide())

    def test_resident_and_swapped_memory_within_budget_keeps_everything(self):
        self.charge(self.older, 300, swap=100)
        self.charge(self.newer, 300, swap=100)
        self.decide().assert_not_called()

    def test_workload_not_yet_in_its_group_counts_as_empty(self):
        self.charge(self.older, 1200)
        self.assertIs(self.victim(self.decide()), self.older)

    def test_unreadable_group_suspends_decisions(self):
        self.charge(self.older, 1200)
        (self.root / 'work' / self.newer.id / 'memory.stat').mkdir(parents=True)
        self.decide().assert_not_called()

if __name__ == '__main__':
    unittest.main()
