"""Live API recovery-state gate (M11.5 P2 addendum).

The worker/scheduler evaluate the authoritative DR recovery lock once, at boot, and
refuse to start if locked. The API is different: it may need to stay alive for
DB-independent liveness while PostgreSQL is unreachable. So it must NOT decide
"allowed" from a boot-time connection failure and then serve forever — it must keep
re-evaluating the authoritative ``dr_restore_events`` state and fail closed until a
successful check says the newest generation is enabled.

This gate holds a three-valued state — ALLOWED / LOCKED / UNKNOWN — refreshed from
the database on a short, bounded cache:

  - initial state is UNKNOWN (never ALLOWED) until a successful authoritative read;
  - a business request refreshes at most once per ``ttl_s`` (a fresh cached decision
    is reused; liveness never triggers a query);
  - each refresh runs under ``query_timeout_s``; any failure/timeout/malformed row
    -> UNKNOWN (fail closed);
  - a cached ALLOWED decision is only reused within ``ttl_s``; after that the next
    business request re-reads, so losing the DB after being allowed fails closed
    within the TTL, and a later restore generation re-locks a running API without a
    process restart.

The gate never exposes restore ids, project names, database details, or exception
text — callers translate its state to a sanitized HTTP status.
"""

import asyncio
import time
from typing import Literal

from nlw.backup.recovery_lock import read_recovery_state

State = Literal["ALLOWED", "LOCKED", "UNKNOWN"]


class RecoveryGate:
    def __init__(self, engine: object, *, ttl_s: float, query_timeout_s: float) -> None:
        self._engine = engine
        self._ttl = ttl_s
        self._timeout = query_timeout_s
        self._state: State = "UNKNOWN"  # never ALLOWED until proven
        self._last_attempt = float("-inf")
        self._lock = asyncio.Lock()

    @property
    def state(self) -> State:
        return self._state

    async def _refresh(self) -> None:
        self._last_attempt = time.monotonic()
        try:
            async with asyncio.timeout(self._timeout):
                async with self._engine.connect() as conn:  # type: ignore[attr-defined]
                    state = await conn.run_sync(read_recovery_state)
            self._state = state  # "ALLOWED" | "LOCKED"
        except Exception:
            # Connection failure, timeout, permission/malformed -> fail closed. We do
            # NOT keep a stale ALLOWED: an unreadable state is UNKNOWN.
            self._state = "UNKNOWN"

    async def check(self) -> State:
        """Return the current authoritative state, refreshing at most once per TTL.

        Bounded: within the TTL window this is an in-memory read (no query); after it,
        exactly one timed refresh (single-flighted across concurrent callers)."""
        if time.monotonic() - self._last_attempt < self._ttl:
            return self._state
        async with self._lock:
            if time.monotonic() - self._last_attempt < self._ttl:
                return self._state
            await self._refresh()
            return self._state
