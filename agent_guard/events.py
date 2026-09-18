"""Linux process connector transport. Missing events invalidate ancestry tracking.

The wire ABI is defined by linux/{netlink,connector,cn_proc}.h. Subscribe to
all events: selective filters create sequence gaps and, on Linux 6.17, also
drop PROC_EVENT_NONE subscription acknowledgements.
"""

from dataclasses import dataclass
import errno
import secrets
import socket
import struct
import threading
import time


NETLINK_CONNECTOR = 11
CN_IDX_PROC = CN_VAL_PROC = 1
_NL = struct.Struct('=IHHII')
_CN = struct.Struct('=IIIIHH')
_PROC = struct.Struct('=IIQ')


@dataclass(frozen=True)
class Event:
    kind: str
    pid: int
    parent_pid: int | None
    timestamp_ns: int


class EventLoss(RuntimeError):
    """The event stream cannot safely support process ancestry decisions."""


def _parse(data):
    """Yield (event or None, CPU, sequence, acknowledgement) records."""
    if not data:
        raise ValueError('empty netlink datagram')
    offset = 0
    while offset < len(data):
        if len(data) - offset < _NL.size:
            raise ValueError('truncated netlink header')
        length, kind, flags, _, _ = _NL.unpack_from(data, offset)
        if length < _NL.size or length > len(data) - offset:
            raise ValueError('invalid netlink message length')
        body = data[offset + _NL.size:offset + length]
        end = offset + length
        offset += (length + 3) & ~3
        if offset > len(data) and end != len(data):
            raise ValueError('truncated netlink alignment')
        if flags & 0x10:  # NLM_F_DUMP_INTR
            raise ValueError('interrupted netlink dump')
        if kind == 1:  # NLMSG_NOOP
            continue
        if kind == 2:  # NLMSG_ERROR; zero is only a transport ACK.
            if len(body) < 4:
                raise ValueError('truncated netlink error')
            error, = struct.unpack_from('=i', body)
            if error:
                raise ValueError(f'netlink error {error}')
            continue
        if kind == 4:  # NLMSG_OVERRUN
            raise ValueError('netlink overrun')
        if kind != 3:  # Connector uses NLMSG_DONE as its message type.
            continue
        if len(body) < _CN.size:
            raise ValueError('truncated connector header')
        index, value, sequence, ack, size, _ = _CN.unpack_from(body)
        if size != len(body) - _CN.size:
            raise ValueError('invalid connector payload length')
        if (index, value) != (CN_IDX_PROC, CN_VAL_PROC):
            continue
        payload = body[_CN.size:]
        if len(payload) < _PROC.size:
            raise ValueError('truncated process event header')
        what, cpu, timestamp = _PROC.unpack_from(payload)
        fields = payload[_PROC.size:]
        minimum = {0: 4, 1: 16, 2: 8, 4: 16, 0x40: 16, 0x80: 8,
                   0x100: 16, 0x200: 24, 0x40000000: 16, 0x80000000: 24}
        if len(fields) < minimum.get(what, 0):
            raise ValueError('truncated process event data')
        event = None
        if what == 0:
            error, = struct.unpack_from('=I', fields)
            if error:
                raise ValueError(f'process connector acknowledgement error {error}')
            event = Event('ack', 0, None, timestamp)
        elif what == 1:
            _, parent_tgid, child_pid, child_tgid = struct.unpack_from('=iiii', fields)
            if child_pid == child_tgid:
                event = Event('fork', child_tgid, parent_tgid, timestamp)
        elif what == 2:
            _, tgid = struct.unpack_from('=ii', fields)
            event = Event('exec', tgid, None, timestamp)
        elif what == 0x80000000:
            pid, tgid = struct.unpack_from('=ii', fields)
            if pid == tgid:
                # A leader can exit before its other threads. The consumer must
                # verify process liveness before removing its tracked identity.
                event = Event('exit', tgid, None, timestamp)
        yield event, cpu, sequence, ack


def decode(data: bytes) -> list[Event]:
    """Decode a complete datagram, rejecting corruption and negative ACKs."""
    return [event for event, _, _, _ in _parse(data) if event is not None]


class ProcEvents:
    """Subscribe and require a kernel acknowledgement before becoming usable.

    Constructor errors are fatal to startup. Any EventLoss during receive
    requires rebuilding the stream and all ancestry state from a fresh snapshot.
    """

    def __init__(self, ack_timeout: float = 2.0):
        self._socket = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        self._closed = False
        self._pending = []
        self._sequences = {}
        self._token = secrets.randbits(31)
        try:
            try:
                # Linux SO_RCVBUFFORCE bypasses rmem_max with CAP_NET_ADMIN.
                self._socket.setsockopt(socket.SOL_SOCKET, 33, 4 * 1024 * 1024)
            except OSError:
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            self._socket.bind((0, CN_IDX_PROC))
            self._send(1)
            deadline = time.monotonic() + ack_timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('process connector subscription was not acknowledged')
                records = self._receive(remaining)
                if records is None:
                    raise TimeoutError('process connector subscription was not acknowledged')
                acknowledged = False
                for event, _, _, ack in records:
                    if event is not None:
                        if event.kind == 'ack':
                            acknowledged |= ack == self._token + 1
                        else:
                            self._pending.append(event)
                if len(self._pending) > 65536:
                    raise EventLoss('too many events while waiting for subscription ACK')
                if acknowledged:
                    break
        except BaseException:
            self.close()
            raise

    def _send(self, operation):
        payload = struct.pack('=I', operation)
        connector = _CN.pack(CN_IDX_PROC, CN_VAL_PROC, self._token, self._token, len(payload), 0)
        header = _NL.pack(_NL.size + len(connector) + len(payload), 3, 0, self._token,
                          self._socket.getsockname()[0])
        message = header + connector + payload
        if self._socket.sendto(message, (0, 0)) != len(message):
            raise OSError('short process connector subscription write')

    def _receive(self, timeout):
        self._socket.settimeout(max(0.0, timeout))
        try:
            data, _, flags, address = self._socket.recvmsg(1024 * 1024)
        except (socket.timeout, BlockingIOError):
            return None
        except OSError as exc:
            if exc.errno == errno.ENOBUFS:
                raise EventLoss('process connector receive buffer overflow') from exc
            raise
        if not address or address[0] != 0:
            raise EventLoss('process connector message did not originate in the kernel')
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise EventLoss('truncated process connector datagram')
        try:
            records = list(_parse(data))
        except ValueError as exc:
            raise EventLoss(str(exc)) from exc
        for _, cpu, sequence, _ in records:
            if cpu == 0xffffffff:  # Older kernels send ACKs outside CPU sequences.
                continue
            previous = self._sequences.get(cpu)
            self._sequences[cpu] = sequence
            if previous is not None and sequence != (previous + 1) & 0xffffffff:
                raise EventLoss(f'process connector sequence gap on CPU {cpu}: {previous} -> {sequence}')
        return records

    def receive(self, timeout: float) -> list[Event]:
        """Return process events, or [] on timeout; raise EventLoss on loss."""
        if self._pending:
            pending, self._pending = self._pending, []
            return pending
        records = self._receive(timeout)
        return [event for event, _, _, _ in (records or [])
                if event is not None and event.kind != 'ack']

    def close(self):
        """Best-effort unsubscribe; always release the socket, exactly once."""
        if self._closed:
            return
        self._closed = True
        try:
            self._send(2)
        except OSError:
            pass
        finally:
            self._socket.close()


class EventPump:
    """Drain a subscribed stream independently of slow /proc reconciliation.

    Events are refresh hints, not a process history: coalescing also includes
    fork parents so the consumer can reread identities and provenance. Any loss
    permanently poisons the pump and takes precedence over pending hints; close
    it and subscribe anew before rebuilding ancestry. The reader still drains
    the old stream until closed, preventing kernel-buffer growth while callers
    finish handling the error.
    """

    _MAX_PENDING = 65536
    _POLL_SECONDS = 0.1

    def __init__(self, stream=None):
        self._stream = ProcEvents() if stream is None else stream
        self._condition = threading.Condition()
        self._stop = threading.Event()
        self._pending = set()
        self._failure = None
        self._thread = threading.Thread(target=self._run, name='agent-guard-events', daemon=True)
        try:
            self._thread.start()
        except BaseException:
            self._stream.close()
            raise

    @property
    def healthy(self):
        """Thread-safe pre-action check; false once any loss has been observed."""
        with self._condition:
            return self._failure is None and not self._stop.is_set() and self._thread.is_alive()

    def _fail(self, reason):
        with self._condition:
            if self._failure is None:
                self._failure = str(reason)
            self._pending.clear()
            self._condition.notify_all()

    def _run(self):
        try:
            while not self._stop.is_set():
                try:
                    batch = self._stream.receive(self._POLL_SECONDS)
                    with self._condition:
                        if self._stop.is_set() or self._failure is not None:
                            continue
                        for event in batch:
                            if event.kind == 'ack':
                                continue
                            for pid in (event.pid, event.parent_pid):
                                if pid is None or pid <= 0 or pid in self._pending:
                                    continue
                                if len(self._pending) >= self._MAX_PENDING:
                                    self._fail(f'process refresh queue exceeded {self._MAX_PENDING} PIDs')
                                    break
                                self._pending.add(pid)
                            if self._failure is not None:
                                break
                        if self._pending:
                            self._condition.notify_all()
                except Exception as exc:
                    self._fail(exc)
                    # A permanently broken descriptor must not create a busy
                    # loop while the main thread finishes its current sample.
                    self._stop.wait(0.01)
        finally:
            # Sole reader ownership avoids closing/reusing the socket descriptor
            # concurrently with recvmsg. Its bounded receive timeout lets close
            # join promptly without trying to interrupt a syscall from outside.
            try:
                self._stream.close()
            except Exception as exc:
                self._fail(exc)
            with self._condition:
                self._condition.notify_all()

    def receive(self, timeout: float) -> list[Event]:
        """Return deduplicated refresh hints; a latched EventLoss always wins."""
        deadline = time.monotonic() + max(0.0, timeout)
        with self._condition:
            while not self._pending and self._failure is None and not self._stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return []
                self._condition.wait(remaining)
            if self._failure is not None:
                raise EventLoss(self._failure)
            if self._stop.is_set():
                return []
            pending, self._pending = self._pending, set()
        return [Event('refresh', pid, None, 0) for pid in pending]

    def close(self):
        """Stop and join the reader; safe to call repeatedly or concurrently."""
        self._stop.set()
        with self._condition:
            self._pending.clear()
            self._condition.notify_all()
        self._thread.join(timeout=2.0)
        if self._thread.is_alive():
            # An injected stream that violates receive(timeout) must not hang
            # daemon shutdown indefinitely or masquerade as a completed close.
            raise RuntimeError('process event reader did not stop within 2 seconds')
