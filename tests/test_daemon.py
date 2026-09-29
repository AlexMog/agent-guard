import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from agent_guard.cgroups import UnsafeAction
from agent_guard.daemon import Daemon
from agent_guard.events import EventPump
from agent_guard.model import Process, Registry
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


if __name__ == '__main__':
    unittest.main()
