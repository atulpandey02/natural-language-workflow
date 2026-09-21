"""Total-deadline + streaming response-cap + phase-aware classification for the
shared external-action HTTP path (M11.5 P1C, ADR-013/014).

These exercise ``perform_action_request`` directly with custom streaming
transports and a controllable monotonic clock, so a trickling / oversized /
compressed / failing response is deterministic without real time or network.
"""

import gzip
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress

import httpx
import pytest

from nlw.connectors.http_action import (
    FINALIZE_MARGIN_S,
    TOTAL_ACTION_DEADLINE_S,
    assert_action_deadline_fits_lease,
    perform_action_request,
)
from nlw.engine.actions import LEASE_DURATION_S
from nlw.registry.registry import (
    AmbiguousActionError,
    RetryableActionError,
)


class FakeClock:
    """A monotonic clock advanced explicitly (or by the response stream)."""

    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


class _ListStream(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.closed = False
        self.chunks_yielded = 0

    def __iter__(self):  # type: ignore[no-untyped-def]
        for chunk in self._chunks:
            self.chunks_yielded += 1
            yield chunk

    def close(self) -> None:
        self.closed = True


class _TrickleStream(httpx.SyncByteStream):
    """Yields forever, advancing the fake clock by ``dt`` before EVERY chunk, so a
    per-op read timer would keep resetting but the TOTAL deadline still fires."""

    def __init__(self, clock: FakeClock, *, chunk: bytes = b"x" * 10, dt: float = 1.0) -> None:
        self._clock, self._chunk, self._dt = clock, chunk, dt
        self.yielded = 0
        self.closed = False

    def __iter__(self):  # type: ignore[no-untyped-def]
        while True:
            self._clock.advance(self._dt)
            self.yielded += 1
            yield self._chunk

    def close(self) -> None:
        self.closed = True


class _StreamTransport(httpx.BaseTransport):
    def __init__(
        self,
        stream: httpx.SyncByteStream,
        *,
        headers: dict[str, str] | None = None,
        status: int = 200,
    ) -> None:
        self._stream, self._headers, self._status = stream, headers or {}, status
        self.seen_accept_encoding: str | None = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.seen_accept_encoding = request.headers.get("Accept-Encoding")
        return httpx.Response(self._status, headers=self._headers, stream=self._stream)


class _RaisingTransport(httpx.BaseTransport):
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        raise self._exc


def _perform(transport: httpx.BaseTransport, **over: object) -> object:
    kwargs: dict[str, object] = dict(
        method="POST",
        url="https://sink.example/hook",
        content=b"{}",
        headers={},
        transport=transport,
        timeout_s=15,
        max_response_bytes=1_000_000,
        want_body=True,
    )
    kwargs.update(over)
    return perform_action_request(**kwargs)  # type: ignore[arg-type]


# --- Total deadline (wall-clock, not per-op inactivity) ---


def test_total_deadline_is_less_than_lease_with_finalize_margin() -> None:
    # The core invariant: a completed-or-timed-out send always leaves margin to
    # re-lock and finalize BEFORE the lease could be reclaimed by another worker.
    assert TOTAL_ACTION_DEADLINE_S + FINALIZE_MARGIN_S < LEASE_DURATION_S


def test_trickling_response_is_stopped_at_total_deadline() -> None:
    clock = FakeClock()
    stream = _TrickleStream(clock, dt=1.0)
    transport = _StreamTransport(stream)
    with pytest.raises(AmbiguousActionError):
        _perform(transport, total_deadline_s=5.0, monotonic=clock)
    # A per-op read timer would never fire (each chunk resets it); the TOTAL
    # deadline stopped it after ~5 one-second chunks, and the stream was closed.
    assert stream.yielded <= 6
    assert stream.closed


def test_deadline_exceeded_before_transmission_is_retryable() -> None:
    # Budget already spent (e.g. slow DNS) before any bytes are written -> the
    # send provably never happened -> safe to retry, not UNKNOWN.
    clock = FakeClock()

    class _SpendingTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("must not transmit once the budget is already gone")

    # total_deadline_s=0 => remaining() <= 0 immediately, before the client runs.
    with pytest.raises(RetryableActionError):
        _perform(_SpendingTransport(), total_deadline_s=0.0, monotonic=clock)


# --- Response byte cap (enforced on RAW wire bytes) ---


def test_response_cap_truncates_without_unbounded_buffer() -> None:
    stream = _ListStream([b"y" * 100 for _ in range(100)])  # 10_000 bytes on the wire
    transport = _StreamTransport(stream)
    resp = _perform(transport, max_response_bytes=500, want_body=True)
    assert resp.truncated is True  # type: ignore[attr-defined]
    assert len(resp.body) == 500  # type: ignore[attr-defined]  # never buffered beyond the cap
    assert stream.closed


def test_identity_encoding_requested_and_compressed_body_not_expanded() -> None:
    # A server that ignores identity and returns a gzip bomb: we read RAW bytes
    # via iter_raw and never decompress, so the cap applies to WIRE bytes and the
    # bomb cannot expand in memory.
    raw = gzip.compress(b"A" * 5_000_000)
    chunks = [raw[i : i + 1000] for i in range(0, len(raw), 1000)]
    stream = _ListStream(chunks)
    transport = _StreamTransport(stream, headers={"Content-Encoding": "gzip"})
    resp = _perform(transport, max_response_bytes=1000, want_body=True)
    assert transport.seen_accept_encoding == "identity"
    assert resp.truncated is True  # type: ignore[attr-defined]
    assert len(resp.body) <= 1000  # type: ignore[attr-defined]  # decompressed size (5MB) never materialized


def test_want_body_false_does_not_consume_the_body() -> None:
    # The webhook path decides success from the status alone; it must NOT consume
    # a possibly unbounded/trickling body — it closes right after the head (P1C
    # part D). Proven by the stream being closed with ZERO chunks read.
    stream = _ListStream([b"z" * 100 for _ in range(100)])
    transport = _StreamTransport(stream)
    resp = _perform(transport, max_response_bytes=200, want_body=False)
    assert resp.body == b""  # type: ignore[attr-defined]  # body not retained
    assert resp.truncated is False  # type: ignore[attr-defined]  # never read, so never "truncated"
    assert stream.chunks_yielded == 0  # the body was never consumed
    assert stream.closed  # the stream was closed after the head


def test_small_response_is_not_truncated() -> None:
    stream = _ListStream([b'{"ok":true}'])
    transport = _StreamTransport(stream)
    resp = _perform(transport, max_response_bytes=1000, want_body=True)
    assert resp.truncated is False  # type: ignore[attr-defined]
    assert resp.body == b'{"ok":true}'  # type: ignore[attr-defined]


# --- Phase-aware exception classification ---


def test_connect_error_is_pre_transmission_retryable() -> None:
    transport = _RaisingTransport(httpx.ConnectError("refused"))
    with pytest.raises(RetryableActionError):
        _perform(transport)


def test_connect_timeout_is_pre_transmission_retryable() -> None:
    transport = _RaisingTransport(httpx.ConnectTimeout("connect timed out"))
    with pytest.raises(RetryableActionError):
        _perform(transport)


def test_read_timeout_after_transmission_is_ambiguous() -> None:
    transport = _RaisingTransport(httpx.ReadTimeout("read timed out"))
    with pytest.raises(AmbiguousActionError):
        _perform(transport)


def test_write_error_is_ambiguous() -> None:
    transport = _RaisingTransport(httpx.WriteError("broken pipe"))
    with pytest.raises(AmbiguousActionError):
        _perform(transport)


def test_remote_protocol_error_is_ambiguous() -> None:
    transport = _RaisingTransport(httpx.RemoteProtocolError("server disconnected"))
    with pytest.raises(AmbiguousActionError):
        _perform(transport)


def test_mid_stream_read_error_is_ambiguous() -> None:
    # Transmission definitely happened (headers received), then the body read
    # fails -> outcome unprovable -> AMBIGUOUS, never a silent retry.
    class _MidFailStream(httpx.SyncByteStream):
        def __iter__(self):  # type: ignore[no-untyped-def]
            yield b"partial"
            raise httpx.ReadError("connection reset mid-body")

        def close(self) -> None:
            pass

    transport = _StreamTransport(_MidFailStream())
    with pytest.raises(AmbiguousActionError):
        _perform(transport, max_response_bytes=1_000_000, want_body=True)


# --- One total wall-clock budget across all phases (P1C part C) ---

# These use a fake monotonic clock for the seams the helper controls (post-DNS,
# post-header, per-chunk) and a REAL controlled localhost server (with elapsed-time
# assertions) for the phases httpx enforces. None of them mock an immediate
# TimeoutError.


class _ClockAdvancingTransport(httpx.BaseTransport):
    """Simulates slow pre-response phases (connect/TLS/write/header) by advancing
    the fake clock by ``advance_s`` before the response head is produced."""

    def __init__(self, clock: FakeClock, advance_s: float, stream: httpx.SyncByteStream) -> None:
        self._clock, self._advance, self._stream = clock, advance_s, stream
        self.called = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.called = True
        self._clock.advance(self._advance)
        return httpx.Response(200, stream=self._stream)


def test_dns_consumes_budget_and_connect_gets_only_the_remainder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # DNS eats 20s of a 30s budget; the phase timeouts handed to httpx (connect
    # AND pool) must be the ~10s REMAINDER, not a fresh 30s — proving DNS time is
    # inside the one total budget.
    clock = FakeClock()
    captured: dict[str, httpx.Timeout] = {}

    def _slow_resolver(host: str) -> list[str]:
        clock.advance(20.0)
        return ["93.184.216.34"]  # a public IP (passes the SSRF policy)

    class _SpyClient:
        def __init__(self, *, timeout: httpx.Timeout, **_kw: object) -> None:
            captured["timeout"] = timeout
            raise httpx.ConnectError("stop before real connect")

    monkeypatch.setattr(httpx, "Client", _SpyClient)
    with pytest.raises(RetryableActionError):  # connect failure is pre-transmission
        perform_action_request(
            method="POST",
            url="https://sink.example/hook",
            content=b"{}",
            headers={},
            transport=None,  # exercise the real DNS pre-resolve path
            timeout_s=15,
            max_response_bytes=1000,
            want_body=False,
            total_deadline_s=30.0,
            resolver=_slow_resolver,
            monotonic=clock,
        )
    t = captured["timeout"]
    assert 9.0 <= float(t.connect or 0) <= 10.0  # the remainder, not 15 or 30
    assert 9.0 <= float(t.pool or 0) <= 10.0  # pool wait is inside the same budget


def test_no_connection_started_after_caller_deadline() -> None:
    # If the budget is already spent, the helper must NOT open a connection.
    transport = _RaisingTransport(AssertionError("must not connect after timeout"))
    with pytest.raises(RetryableActionError):
        _perform(transport, total_deadline_s=0.0)


def test_slow_pre_response_phase_cannot_proceed_past_deadline() -> None:
    # Connect/TLS/write/header collectively overrun the budget; the post-header
    # check refuses to proceed -> AMBIGUOUS (transmission may have happened).
    clock = FakeClock()
    stream = _ListStream([b"body"])
    transport = _ClockAdvancingTransport(clock, advance_s=31.0, stream=stream)
    with pytest.raises(AmbiguousActionError):
        _perform(transport, total_deadline_s=30.0, monotonic=clock, want_body=True)
    assert transport.called
    assert stream.chunks_yielded == 0  # never started reading the body past the deadline


def test_streaming_does_not_restart_the_budget() -> None:
    # Headers arrive with only a sliver of budget left; the streamed body cannot
    # get a fresh full deadline — the FIRST chunk that crosses the deadline aborts.
    clock = FakeClock()

    class _AdvancingStream(httpx.SyncByteStream):
        def __init__(self) -> None:
            self.count = 0

        def __iter__(self) -> Iterator[bytes]:
            self.count += 1
            clock.advance(1.0)  # pushes past the deadline on the first chunk
            yield b"x" * 10
            self.count += 1
            yield b"y" * 10  # must never be reached

        def close(self) -> None:
            pass

    stream = _AdvancingStream()
    # handle_request leaves 0.5s of budget; the first chunk advances 1.0s.
    transport = _ClockAdvancingTransport(clock, advance_s=29.5, stream=stream)
    with pytest.raises(AmbiguousActionError):
        _perform(transport, total_deadline_s=30.0, monotonic=clock, want_body=True)
    assert stream.count == 1  # only one chunk pulled; no fresh 30s budget


def test_config_invariant_guard_rejects_deadline_that_can_outlive_lease() -> None:
    # total + margin must be strictly < lease, else a slow send could still be in
    # flight when another worker reclaims the lease.
    assert TOTAL_ACTION_DEADLINE_S + FINALIZE_MARGIN_S < LEASE_DURATION_S
    assert_action_deadline_fits_lease(  # the live config is valid
        total_deadline_s=TOTAL_ACTION_DEADLINE_S,
        finalize_margin_s=FINALIZE_MARGIN_S,
        lease_duration_s=float(LEASE_DURATION_S),
    )
    with pytest.raises(RuntimeError):
        assert_action_deadline_fits_lease(
            total_deadline_s=40.0, finalize_margin_s=10.0, lease_duration_s=45.0
        )
    with pytest.raises(RuntimeError):  # equality is not enough (need strict <)
        assert_action_deadline_fits_lease(
            total_deadline_s=35.0, finalize_margin_s=10.0, lease_duration_s=45.0
        )


# --- Controlled real localhost server (elapsed-time proofs) ---


@contextmanager
def _controlled_server(handler: Callable[[socket.socket], None]) -> Iterator[int]:
    """Run a one-shot raw TCP server on 127.0.0.1 that hands each accepted socket
    to ``handler``. Yields the bound port. The injected real ``httpx.HTTPTransport``
    reaches it directly (the SSRF pre-resolve is only used for the None-transport
    path, so this does not weaken production SSRF controls)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _serve() -> None:
        srv.settimeout(5.0)
        try:
            conn, _addr = srv.accept()
        except OSError:
            return
        with conn, suppress(OSError):
            handler(conn)
        stop.set()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        srv.close()
        thread.join(timeout=5.0)


def _real_perform(port: int, *, total_deadline_s: float) -> object:
    return perform_action_request(
        method="POST",
        url=f"http://127.0.0.1:{port}/hook",
        content=b"{}",
        headers={},
        transport=httpx.HTTPTransport(),  # real network transport to the local server
        timeout_s=10,
        max_response_bytes=1000,
        want_body=True,
        total_deadline_s=total_deadline_s,
    )


def test_controlled_server_delayed_headers_stops_near_total_deadline() -> None:
    # The server accepts + reads the request, then never replies. httpx's read
    # timeout (= the remaining budget) must stop the wait at ~the total deadline,
    # not an inactivity timeout that never fires -> AMBIGUOUS.
    def _handler(conn: socket.socket) -> None:
        conn.recv(65536)  # consume the request
        time.sleep(5.0)  # then stall well beyond the deadline

    with _controlled_server(_handler) as port:
        start = time.monotonic()
        with pytest.raises(AmbiguousActionError):
            _real_perform(port, total_deadline_s=1.0)
        elapsed = time.monotonic() - start
    assert 0.5 <= elapsed <= 4.0  # bounded by the total deadline, not the 5s stall


def test_controlled_server_reset_after_request_is_ambiguous_post_transmission() -> None:
    # The server reads the full request (transmission happened) then closes without
    # responding -> the outcome cannot be proven -> AMBIGUOUS (UNKNOWN), not retry.
    def _handler(conn: socket.socket) -> None:
        conn.recv(65536)
        conn.close()  # abrupt close after we transmitted

    with _controlled_server(_handler) as port, pytest.raises(AmbiguousActionError):
        _real_perform(port, total_deadline_s=5.0)
