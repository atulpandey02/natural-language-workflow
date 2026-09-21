"""Total-deadline + streaming HTTP for external actions (M11.5 P1C, ADR-013/014).

Shared by the webhook and Slack connectors. It enforces:

- ONE monotonic total wall-clock budget covering destination resolution, pool
  acquisition, connection, TLS, request write, response headers and streamed
  response consumption — NOT a per-operation inactivity timeout and NOT a fresh
  timeout per phase. Each httpx phase (pool/connect/write/read) is bounded by the
  budget REMAINING when the request starts, so no single phase can block past the
  total; and the monotonic deadline is re-checked at every seam we control (after
  DNS, immediately after the response head, and before every streamed chunk), so
  the operation never *proceeds* past the deadline and response streaming can
  neither restart nor extend the budget. A trickle response that stays under every
  inactivity timeout is therefore still stopped at the total deadline. (Residual:
  in the pathological case where several sequential pre-response phases each block
  near the full remaining budget, the pre-response wall-clock can reach up to ~2x
  the budget before the post-header check aborts; the per-phase timeouts still
  prevent unbounded blocking and no body is consumed or state finalized past the
  deadline. Documented, not hidden.)
- a fresh single-use connection pool per call, so pool acquisition is trivial and
  bounded by the same remaining budget (inside the deadline, not a separate one).
- a hard response byte cap enforced WHILE reading raw wire bytes
  (``Accept-Encoding: identity`` + ``iter_raw`` — the body is never decompressed,
  so a compression bomb cannot expand in memory; at most one bounded chunk beyond
  the cap is ever held). A caller that does not need the body (webhook) does NOT
  consume it at all: the stream is closed right after the head.
- conservative phase-aware outcome classification: a failure PROVABLY before
  transmission (DNS/connect/TLS/pool) is retryable; a failure once transmission
  may have started (write/read/reset/total deadline) is AMBIGUOUS (-> terminal
  UNKNOWN, never auto-resent).

No background thread continues the request after the caller returns: the whole
operation runs synchronously and every resource is closed on exit.
"""

import socket
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import httpx

from nlw.connectors.http_guard import (
    GuardedTransport,
    Resolver,
    SsrfError,
    _default_resolver,
    resolve_and_validate,
    validate_url,
)
from nlw.engine.actions import LEASE_DURATION_S
from nlw.registry.registry import (
    AmbiguousActionError,
    RetryableActionError,
    ToolExecutionError,
)

# Total external-operation deadline and the finalization safety margin. The
# invariant TOTAL + MARGIN < LEASE_DURATION_S (engine/actions.py) guarantees a
# completed-or-timed-out send always leaves room to re-lock and finalize before
# the lease could be reclaimed by another worker. Enforced at import (below).
TOTAL_ACTION_DEADLINE_S = 30.0
FINALIZE_MARGIN_S = 10.0

# httpx exception phases.
_PRE_TRANSMISSION = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)
_AMBIGUOUS_TRANSPORT = (
    httpx.WriteError,
    httpx.WriteTimeout,
    httpx.ReadError,
    httpx.ReadTimeout,
    httpx.RemoteProtocolError,
)


def assert_action_deadline_fits_lease(
    *, total_deadline_s: float, finalize_margin_s: float, lease_duration_s: float
) -> None:
    """Fail closed unless a completed-or-timed-out send always leaves finalize
    margin before the lease could be reclaimed: ``total + margin < lease``."""
    if total_deadline_s + finalize_margin_s >= lease_duration_s:
        raise RuntimeError(
            "invalid action timing configuration: total action deadline + finalize "
            f"margin ({total_deadline_s}s + {finalize_margin_s}s) must be strictly "
            f"less than the lease duration ({lease_duration_s}s), else a slow send "
            "could still be in flight when another worker reclaims the lease"
        )


# Startup guard: any process that wires the action HTTP path refuses to import
# (and therefore to start) if the deadline could outlive the lease.
assert_action_deadline_fits_lease(
    total_deadline_s=TOTAL_ACTION_DEADLINE_S,
    finalize_margin_s=FINALIZE_MARGIN_S,
    lease_duration_s=float(LEASE_DURATION_S),
)


@dataclass(frozen=True)
class ActionHttpResponse:
    status_code: int
    headers: httpx.Headers
    body: bytes  # bounded to max_response_bytes (empty when want_body is False)
    truncated: bool  # the wire response exceeded max_response_bytes


def perform_action_request(
    *,
    method: str,
    url: str,
    content: bytes,
    headers: dict[str, str],
    transport: httpx.BaseTransport | None,
    timeout_s: float,
    max_response_bytes: int,
    want_body: bool,
    total_deadline_s: float = TOTAL_ACTION_DEADLINE_S,
    resolver: Resolver | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> ActionHttpResponse:
    hdrs = {**headers, "Accept-Encoding": "identity"}
    deadline = monotonic() + total_deadline_s

    def remaining() -> float:
        return deadline - monotonic()

    # Destination resolution/validation is inside the total budget. When a
    # transport is injected (tests/MockTransport) it performs no real DNS, so we
    # skip pre-resolution; production pins the validated IP so libpq-style second
    # resolution cannot happen (DNS-rebinding safe, mirrors GuardedTransport). A
    # POLICY rejection (SsrfError) is deterministic (no transmission -> FAILED); a
    # transient resolution failure (no transmission) is safe to retry.
    if transport is not None:
        inner: httpx.BaseTransport = transport
    else:
        try:
            host, _port = validate_url(url)
        except SsrfError as exc:
            raise ToolExecutionError(f"destination blocked: {exc}") from None
        try:
            ip = resolve_and_validate(host, resolver or _default_resolver)
        except SsrfError as exc:
            raise ToolExecutionError(f"destination blocked: {exc}") from None
        except (socket.gaierror, OSError) as exc:
            # Name resolution failed before any bytes were written -> no effect.
            raise RetryableActionError(f"destination did not resolve: {exc}") from None
        inner = GuardedTransport(resolver=lambda _h: [ip])

    if remaining() <= 0:
        # Budget already spent (e.g. slow DNS) before any bytes were written: the
        # request provably never left, so retry (never UNKNOWN).
        raise RetryableActionError("action deadline exceeded before transmission")

    # One budget: each phase (pool acquire, connect/TLS, write, read-header) is
    # bounded by the remaining budget at request start; the monotonic deadline is
    # re-checked after the head and per streamed chunk (below).
    phase = max(0.001, min(float(timeout_s), remaining()))
    timeout = httpx.Timeout(connect=phase, write=phase, read=phase, pool=phase)
    transmitted = False
    try:
        with (
            httpx.Client(transport=inner, timeout=timeout, follow_redirects=False) as client,
            client.stream(method, url, content=content, headers=hdrs) as resp,
        ):
            # Reaching here: request line + headers + body were written and the
            # response head was received -> transmission definitely happened.
            transmitted = True
            # If pool+connect+write+header collectively consumed the whole budget,
            # do NOT proceed to (or start) reading the body.
            if remaining() <= 0:
                resp.close()
                raise AmbiguousActionError("action total deadline exceeded at response headers")
            if not want_body:
                # Success/failure is decided by the status line alone; do NOT
                # consume a possibly unbounded/trickling body — close after the
                # head so a slow body can never turn a delivered request into a
                # deadline breach or buffer unbounded bytes.
                status, out_headers = resp.status_code, resp.headers.copy()
                resp.close()
                return ActionHttpResponse(status, out_headers, b"", truncated=False)
            total = 0
            buf = bytearray()
            # A real transport streams lazily (the byte cap is enforced WHILE
            # reading). An eagerly-buffered response (e.g. httpx.MockTransport in
            # tests) is already in memory and takes the bounded read() fallback.
            raw_chunks: Iterator[bytes] = (
                iter((resp.read(),)) if resp.is_stream_consumed else resp.iter_raw()
            )
            for chunk in raw_chunks:
                if remaining() <= 0:
                    resp.close()
                    raise AmbiguousActionError("action total deadline exceeded during response")
                total += len(chunk)
                if len(buf) < max_response_bytes:
                    buf.extend(chunk[: max_response_bytes - len(buf)])
                if total > max_response_bytes:
                    resp.close()
                    return ActionHttpResponse(
                        resp.status_code, resp.headers.copy(), bytes(buf), truncated=True
                    )
            return ActionHttpResponse(
                resp.status_code, resp.headers.copy(), bytes(buf), truncated=False
            )
    except SsrfError as exc:
        raise ToolExecutionError(f"destination blocked: {exc}") from None
    except AmbiguousActionError:
        raise
    except _PRE_TRANSMISSION:
        raise RetryableActionError("connect failure before transmission") from None
    except _AMBIGUOUS_TRANSPORT:
        raise AmbiguousActionError("transport failure during/after transmission") from None
    except httpx.HTTPError:
        # Unclassified transport error: conservative — ambiguous once we may have
        # transmitted, retryable only when provably still pre-transmission.
        if transmitted:
            raise AmbiguousActionError("response failure after transmission") from None
        raise RetryableActionError("transport failure before transmission") from None
