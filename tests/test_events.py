import errno
import os
import queue
import socket
import struct
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

from agent_guard import events


def netlink(payload, kind=3):
    size = 16 + len(payload)
    return struct.pack('=IHHII', size, kind, 0, 0, 0) + payload + bytes((-size) % 4)


def message(what, body=b'', *, seq=0, cpu=0, ack=0, index=1):
    payload = struct.pack('=IIQ', what, cpu, 123456) + body.ljust(24, b'\0')
    connector = struct.pack('=IIIIHH', index, 1, seq, ack, len(payload), 0)
    return netlink(connector + payload)


def exec_message(pid=123, **kwargs):
    return message(2, struct.pack('=ii', pid, pid), **kwargs)


def ack_message(**kwargs):
    return message(0, struct.pack('=I', 0), ack=42, **kwargs)


class DecodeTests(unittest.TestCase):
    def test_fork_uses_parent_group_and_child_group(self):
        data = message(1, struct.pack('=iiii', 101, 100, 200, 200))
        self.assertEqual(events.decode(data), [events.Event('fork', 200, 100, 123456)])

    def test_ignores_thread_fork_and_thread_exit(self):
        fork = message(1, struct.pack('=iiii', 100, 100, 201, 200))
        exit_event = message(0x80000000, struct.pack('=iiIIii', 201, 200, 0, 0, 100, 100))
        self.assertEqual(events.decode(fork + exit_event), [])

    def test_exec_and_leader_exit(self):
        execution = message(2, struct.pack('=ii', 201, 200))
        exit_event = message(0x80000000, struct.pack('=iiIIii', 200, 200, 0, 0, 100, 100))
        self.assertEqual(events.decode(execution + exit_event), [
            events.Event('exec', 200, None, 123456),
            events.Event('exit', 200, None, 123456),
        ])

    def test_success_ack_and_valid_irrelevant_messages(self):
        self.assertEqual(events.decode(ack_message()), [events.Event('ack', 0, None, 123456)])
        self.assertEqual(events.decode(message(4) + message(2, index=99) + netlink(b'', 1)), [])

    def test_negative_ack_and_netlink_error(self):
        for data in [message(0, struct.pack('=I', errno.EPERM)),
                     netlink(struct.pack('=i', -errno.EPERM), 2), netlink(b'', 4)]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                events.decode(data)

    def test_netlink_transport_ack_is_not_subscription_ack(self):
        self.assertEqual(events.decode(netlink(struct.pack('=i', 0), 2)), [])

    def test_rejects_every_truncation_and_invalid_lengths(self):
        data = exec_message()
        bad = [data[:end] for end in range(len(data))]
        bad += [struct.pack('=I', 15) + data[4:],
                data[:32] + struct.pack('=H', 1000) + data[34:],
                data + b'\0',
                netlink(struct.pack('=IIIIHH', 1, 1, 0, 0, 16, 0) + bytes(16))]
        for packet in bad:
            with self.subTest(length=len(packet)), self.assertRaises(ValueError):
                events.decode(packet)


class FakeSocket:
    def __init__(self, packets):
        self.packets = list(packets)
        self.sent = []
        self.closed = False
        self.options = []

    def bind(self, address):
        self.address = address

    def getsockname(self):
        return (999, 1)

    def setsockopt(self, *args):
        self.options.append(args)

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendto(self, data, address):
        self.sent.append((data, address))
        return len(data)

    def recvmsg(self, size):
        if not self.packets:
            raise socket.timeout()
        result = self.packets.pop(0)
        if isinstance(result, Exception):
            raise result
        if isinstance(result, tuple):
            return result
        return result, [], 0, (0, 1)

    def close(self):
        self.closed = True


class ReaderTests(unittest.TestCase):
    def open_reader(self, packets):
        fake = FakeSocket(packets)
        with patch.object(events.socket, 'socket', return_value=fake) as factory, \
                patch.object(events.secrets, 'randbits', return_value=41):
            reader = events.ProcEvents()
        factory.assert_called_once_with(socket.AF_NETLINK, socket.SOCK_DGRAM, 11)
        self.addCleanup(reader.close)
        return reader, fake

    def test_subscription_buffers_early_events_and_sends_legacy_all_event_request(self):
        reader, fake = self.open_reader([exec_message(seq=8), ack_message(seq=9)])
        self.assertEqual(reader.receive(0), [events.Event('exec', 123, None, 123456)])
        request, destination = fake.sent[0]
        self.assertEqual(destination, (0, 0))
        self.assertEqual(struct.unpack_from('=IIIIHH', request, 16), (1, 1, 41, 41, 4, 0))
        self.assertEqual(struct.unpack_from('=I', request, 36)[0], 1)
        self.assertEqual(fake.address, (0, 1))

    def test_ack_in_same_packet_keeps_all_events(self):
        reader, _ = self.open_reader([ack_message(seq=0) + exec_message(seq=1)])
        self.assertEqual(len(reader.receive(0)), 1)

    def test_attempts_four_mib_forced_receive_buffer(self):
        _, fake = self.open_reader([ack_message()])
        self.assertEqual(fake.options, [(socket.SOL_SOCKET, 33, 4 * 1024 * 1024)])

    def test_forced_receive_buffer_permission_failure_falls_back(self):
        fake = FakeSocket([ack_message()])
        original = fake.setsockopt

        def set_option(level, option, size):
            original(level, option, size)
            if option == 33:
                raise OSError(errno.EPERM, 'CAP_NET_ADMIN unavailable')

        with patch.object(fake, 'setsockopt', side_effect=set_option), \
                patch.object(events.socket, 'socket', return_value=fake), \
                patch.object(events.secrets, 'randbits', return_value=41):
            reader = events.ProcEvents()
        self.addCleanup(reader.close)
        self.assertEqual(fake.options, [(socket.SOL_SOCKET, 33, 4 * 1024 * 1024),
                                       (socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)])

    def test_subscription_requires_correlated_proc_ack(self):
        for packets in [[], [message(0, ack=99)], [netlink(struct.pack('=i', 0), 2)],
                        [message(0, struct.pack('=I', errno.EPERM), ack=42)]]:
            fake = FakeSocket(packets)
            with self.subTest(packets=packets), patch.object(events.socket, 'socket', return_value=fake), \
                    patch.object(events.secrets, 'randbits', return_value=41):
                with self.assertRaises((OSError, events.EventLoss, TimeoutError)):
                    events.ProcEvents()
                self.assertTrue(fake.closed)

    def test_old_kernel_ack_with_sentinel_cpu(self):
        reader, _ = self.open_reader([ack_message(cpu=0xffffffff, seq=41), exec_message(seq=500)])
        self.assertEqual(len(reader.receive(0)), 1)

    def test_receive_timeout_returns_empty(self):
        reader, _ = self.open_reader([ack_message()])
        self.assertEqual(reader.receive(0.01), [])

    def test_loss_and_untrusted_sender_fail_closed(self):
        faults = [OSError(errno.ENOBUFS, 'overflow'),
                  (exec_message(seq=1), [], socket.MSG_TRUNC, (0, 1)),
                  (exec_message(seq=1), [], 0, (1000, 1)), b'bad']
        for fault in faults:
            with self.subTest(fault=fault):
                reader, _ = self.open_reader([ack_message(), fault])
                with self.assertRaises(events.EventLoss):
                    reader.receive(0.1)

    def test_sequence_gap_detected_even_with_irrelevant_events(self):
        reader, _ = self.open_reader([ack_message(seq=5), message(4, seq=6), exec_message(seq=8)])
        self.assertEqual(reader.receive(0.1), [])
        with self.assertRaises(events.EventLoss):
            reader.receive(0.1)

    def test_sequences_per_cpu_and_wraparound(self):
        reader, _ = self.open_reader([ack_message(cpu=0xffffffff),
                                     exec_message(cpu=0, seq=0xffffffff),
                                     exec_message(cpu=1, seq=40),
                                     exec_message(cpu=0, seq=0)])
        for _ in range(3):
            self.assertEqual(len(reader.receive(0.1)), 1)

    def test_close_unsubscribes_and_is_idempotent(self):
        reader, fake = self.open_reader([ack_message()])
        reader.close()
        reader.close()
        self.assertTrue(fake.closed)
        self.assertEqual(len(fake.sent), 2)
        self.assertEqual(struct.unpack_from('=I', fake.sent[-1][0], 36)[0], 2)


class FakeStream:
    """Queue-backed stream with barriers that never depend on thread sleeps."""

    def __init__(self):
        self.queue = queue.Queue()
        self.close_count = 0
        self.in_receive = threading.Event()
        self.concurrent_close = False

    def receive(self, timeout):
        self.in_receive.set()
        try:
            try:
                item = self.queue.get(timeout=timeout)
            except queue.Empty:
                return []
            if isinstance(item, threading.Event):
                item.set()
                return []
            if isinstance(item, Exception):
                raise item
            return item
        finally:
            self.in_receive.clear()

    def close(self):
        self.concurrent_close |= self.in_receive.is_set()
        self.close_count += 1

    def drained(self, testcase):
        barrier = threading.Event()
        self.queue.put(barrier)
        testcase.assertTrue(barrier.wait(3), 'reader did not drain the queued stream')


class PumpTests(unittest.TestCase):
    def open_pump(self):
        self.assertTrue(hasattr(events, 'EventPump'), 'dedicated EventPump is missing')
        stream = FakeStream()
        pump = events.EventPump(stream=stream)
        self.addCleanup(pump.close)
        return pump, stream

    def test_burst_duplicates_keep_draining_without_consumer_and_include_parents(self):
        pump, stream = self.open_pump()
        batch = [events.Event('fork', 20, 10, 1), events.Event('exec', 20, None, 2),
                 events.Event('exit', 30, None, 3), events.Event('ack', 0, None, 4)]
        for _ in range(1000):
            stream.queue.put(batch)
        stream.drained(self)
        self.assertTrue(pump.healthy)
        self.assertEqual(set(pump.receive(0)), {events.Event('refresh', pid, None, 0)
                                              for pid in (10, 20, 30)})
        self.assertEqual(pump.receive(0.01), [])

    def test_loss_has_priority_is_latched_and_reader_keeps_draining(self):
        pump, stream = self.open_pump()
        stream.queue.put([events.Event('exec', 20, None, 1)])
        stream.queue.put(events.EventLoss('lost before consumer was ready'))
        stream.queue.put([events.Event('fork', 40, 30, 2)])
        stream.drained(self)
        self.assertFalse(pump.healthy)
        for _ in range(2):
            with self.assertRaisesRegex(events.EventLoss, 'lost before consumer was ready'):
                pump.receive(0)

    def test_transport_failure_cannot_silently_end_reader(self):
        pump, stream = self.open_pump()
        stream.queue.put(OSError(errno.EBADF, 'stream failure'))
        stream.drained(self)
        with self.assertRaisesRegex(events.EventLoss, 'stream failure'):
            pump.receive(0)

    def test_pending_pid_limit_overflow_is_latched_and_reader_keeps_draining(self):
        pump, stream = self.open_pump()
        stream.queue.put([events.Event('exec', pid, None, 0) for pid in range(1, 65538)])
        stream.drained(self)
        with self.assertRaisesRegex(events.EventLoss, '65536'):
            pump.receive(0)

    def test_exact_pending_limit_is_accepted(self):
        pump, stream = self.open_pump()
        stream.queue.put([events.Event('exec', pid, None, 0) for pid in range(1, 65537)])
        stream.drained(self)
        self.assertEqual(len(pump.receive(0)), 65536)

    def test_close_is_idempotent_and_does_not_race_receive(self):
        pump, stream = self.open_pump()
        self.assertTrue(stream.in_receive.wait(1))
        started = time.monotonic()
        pump.close()
        pump.close()
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(stream.close_count, 1)
        self.assertFalse(stream.concurrent_close)
        self.assertFalse(pump.healthy)
        self.assertEqual(pump.receive(0), [])

    def test_default_constructs_proc_stream(self):
        self.assertTrue(hasattr(events, 'EventPump'), 'dedicated EventPump is missing')
        stream = FakeStream()
        with patch.object(events, 'ProcEvents', return_value=stream) as factory:
            pump = events.EventPump()
        self.addCleanup(pump.close)
        factory.assert_called_once_with()
        stream.queue.put([events.Event('exec', 99, None, 0)])
        self.assertEqual(pump.receive(1), [events.Event('refresh', 99, None, 0)])

    def test_concurrent_closes_join_once_and_wake_waiting_consumer(self):
        pump, stream = self.open_pump()
        results = []
        failures = []
        consumer = threading.Thread(target=lambda: results.append(pump.receive(30)), daemon=True)
        consumer.start()
        barrier = threading.Barrier(3)

        def close_concurrently():
            try:
                barrier.wait(timeout=1)
                pump.close()
            except Exception as exc:
                failures.append(exc)

        closers = [threading.Thread(target=close_concurrently, daemon=True) for _ in range(2)]
        for closer in closers:
            closer.start()
        barrier.wait(timeout=1)
        for thread in [*closers, consumer]:
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(results, [[]])
        self.assertEqual(stream.close_count, 1)
        self.assertFalse(stream.concurrent_close)


@unittest.skipUnless(os.environ.get('AGENT_GUARD_PROC_INTEGRATION') == '1',
                     'set AGENT_GUARD_PROC_INTEGRATION=1 as root for real kernel events')
class KernelIntegrationTests(unittest.TestCase):
    """Opt-in: observe only a newly spawned child; never signal other tasks.

    From the project directory:
      sudo env AGENT_GUARD_PROC_INTEGRATION=1 python3 -m unittest discover \
          -s tests -p test_events.py -v
    Requires CONFIG_CONNECTOR and CONFIG_PROC_EVENTS in the initial namespaces.
    """

    def test_real_kernel_subscription_fork_exec_exit(self):
        self.assertEqual(os.geteuid(), 0, 'integration test requires root')
        reader = events.ProcEvents()
        self.addCleanup(reader.close)
        # Force fork/exec, including on Python builds that support posix_spawn.
        child = subprocess.Popen(['/bin/sleep', '0.2'], close_fds=True,
                                 preexec_fn=lambda: None)
        seen = set()
        deadline = time.monotonic() + 5
        try:
            while time.monotonic() < deadline and seen != {'fork', 'exec', 'exit'}:
                for event in reader.receive(0.2):
                    if event.pid == child.pid:
                        seen.add(event.kind)
                        if event.kind == 'fork':
                            self.assertEqual(event.parent_pid, os.getpid())
            self.assertEqual(child.wait(timeout=2), 0)
            self.assertEqual(seen, {'fork', 'exec', 'exit'})
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()

    def test_real_event_pump_drains_burst_while_consumer_is_busy(self):
        self.assertEqual(os.geteuid(), 0, 'integration test requires root')
        reader = events.EventPump()
        self.addCleanup(reader.close)
        children = set()
        # The main consumer deliberately does not read during this burst.
        for _ in range(500):
            child = subprocess.Popen(['/bin/true'])
            children.add(child.pid)
            self.assertEqual(child.wait(timeout=2), 0)
        seen = set()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not children.issubset(seen):
            seen.update(e.pid for e in reader.receive(0.1))
        self.assertTrue(reader.healthy)
        self.assertTrue(children.issubset(seen), 'some test child refreshes were lost')


if __name__ == '__main__':
    unittest.main()
