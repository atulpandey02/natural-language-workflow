"""Authoritative, database-enforced recovery lock (M11.5 P2 addendum).

The file-based restore-ready gate (``nlw.backup.gate``) and the compose runtime
guard are useful, but neither can be the sole authority: the file gate was only
consulted when ``NLW_RESTORE_MODE=1`` — an OPTIONAL flag whose omission let
api/worker/scheduler start against a freshly restored (un-enabled) database.

The AUTHORITATIVE lock is ``dr_restore_events`` itself, which runtime roles cannot
write. Every api/worker/scheduler process runs :func:`assert_startup_allowed_*` at
boot and consults the newest restore generation's DB state — regardless of any env
flag, compose profile, mounted file, or entrypoint:

  - no restore event                      -> ALLOW (ordinary, never-restored DB)
  - newest quiesced but not validated     -> BLOCK (RecoveryLocked)
  - newest validated but not enabled      -> BLOCK (RecoveryLocked)
  - newest validated AND enabled          -> ALLOW
  - malformed / unreadable state          -> BLOCK (RecoveryStateUnknown, fail closed)

A later restore inserts a newer, un-enabled generation, so an older enablement can
never authorize it (the preflight always reads the NEWEST row).
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine, Row
from sqlalchemy.exc import SQLAlchemyError

# Runtime roles have column-scoped SELECT on exactly these (migration 0014).
_NEWEST_STATE = text(
    "SELECT id, validation_completed_at, runtime_enabled_at "
    "FROM dr_restore_events ORDER BY restored_at DESC LIMIT 1"
)


class RecoveryLocked(RuntimeError):
    """The newest restore generation is not operator-enabled — startup refused."""


class RecoveryStateUnknown(RuntimeError):
    """Recovery-lock state could not be read reliably — fail closed."""


class EnableRejected(RuntimeError):
    """An enable-runtime request was stale/mismatched/unvalidated/incomplete."""


def _evaluate(row: "Row[Any] | None") -> None:
    if row is None:
        return  # never restored -> ordinary startup allowed
    event_id, validated, enabled = row[0], row[1], row[2]
    if event_id is None:
        raise RecoveryStateUnknown("malformed restore event (missing id)")
    if validated is None:
        raise RecoveryLocked("newest restore generation is quiesced but not validated")
    if enabled is None:
        raise RecoveryLocked("newest restore generation is validated but not operator-enabled")


def check_recovery_lock(conn: Connection) -> None:
    """Evaluate the newest generation on an already-open sync connection.

    Raises RecoveryLocked (blocked) or RecoveryStateUnknown (indeterminate). A query
    failure — permission denied, missing table/columns — is treated as indeterminate
    and fails closed."""
    try:
        row = conn.execute(_NEWEST_STATE).first()
    except SQLAlchemyError as exc:
        raise RecoveryStateUnknown("cannot read authoritative recovery-lock state") from exc
    _evaluate(row)


def assert_startup_allowed_sync(engine: Engine) -> None:
    """Startup preflight for the worker/scheduler (sync engines). Fails closed on any
    inability to determine the recovery state (including connection failure)."""
    try:
        with engine.connect() as conn:
            check_recovery_lock(conn)
    except RecoveryLocked:
        raise
    except RecoveryStateUnknown:
        raise
    except SQLAlchemyError as exc:
        raise RecoveryStateUnknown("cannot connect to check recovery-lock state") from exc


async def assert_startup_allowed_async(engine: object) -> None:
    """Startup preflight for the API (async engine).

    Fails closed when the DB is REACHABLE but the newest generation is locked
    (RecoveryLocked) or its state is indeterminate — e.g. permission denied / missing
    columns (RecoveryStateUnknown). This closes the reported bypass: a RESTORED
    database is reachable, so it is always evaluated here.

    A pure CONNECTION failure (DB unreachable at boot) is tolerated so the API keeps
    its DB-free liveness/readiness contract (it boots and reports not-ready until the
    DB returns). That is NOT the restore-lock scenario — a restored DB is reachable —
    and the worker/scheduler (which must have the DB to do anything) fail closed on it
    via the sync preflight."""
    try:
        async with engine.connect() as conn:  # type: ignore[attr-defined]
            await conn.run_sync(check_recovery_lock)
    except (RecoveryLocked, RecoveryStateUnknown):
        raise  # reachable + locked / indeterminate -> fail closed
    except SQLAlchemyError:
        return  # DB unreachable at boot -> preserve DB-free liveness/readiness


# --- operator-side transitions (owner/restore credential only) ---


def mark_validated(
    engine: Engine, event_id: str, *, target_project: str, when: datetime | None = None
) -> None:
    """Record that validation succeeded for this generation (owner connection). This
    is what moves a generation from 'quiesced' to 'validated' (still locked)."""
    ts = when or datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE dr_restore_events SET validation_completed_at=:ts, target_project=:proj "
                "WHERE id=:id"
            ),
            {"ts": ts, "proj": target_project, "id": event_id},
        )


@dataclass(frozen=True)
class EnableResult:
    event_id: str
    enabled_at: datetime
    already_enabled: bool


def enable_runtime(
    engine: Engine, *, event_id: str, confirm_project: str, operator: str
) -> EnableResult:
    """Explicitly enable the exact newest, validated restore generation (operator
    credential). Conditional + idempotent for the same already-enabled generation;
    rejects stale/mismatched/unvalidated/incomplete generations. Never starts
    services. Prints/returns no secret or customer data."""
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT id, validation_completed_at, runtime_enabled_at, target_project "
                "FROM dr_restore_events ORDER BY restored_at DESC LIMIT 1 FOR UPDATE"
            )
        ).first()
        if row is None:
            raise EnableRejected("no restore event exists to enable")
        newest_id, validated, enabled_at, proj = row
        if str(newest_id) != event_id:
            raise EnableRejected(
                "supplied generation is not the newest restore event (stale/mismatched)"
            )
        if validated is None:
            raise EnableRejected("generation is not validated yet — cannot enable")
        if proj is None or proj != confirm_project:
            raise EnableRejected("target project/database confirmation does not match")
        if enabled_at is not None:
            # Idempotent for the SAME already-enabled newest generation.
            return EnableResult(str(newest_id), enabled_at, already_enabled=True)
        now = datetime.now(UTC)
        res = conn.execute(
            text(
                "UPDATE dr_restore_events SET runtime_enabled_at=:now, runtime_enabled_by=:op "
                "WHERE id=:id AND validation_completed_at IS NOT NULL "
                "AND runtime_enabled_at IS NULL"
            ),
            {"now": now, "op": operator, "id": event_id},
        )
        if res.rowcount != 1:  # lost a race / state changed under us -> fail closed
            raise EnableRejected("enable transition did not apply (state changed)")
    return EnableResult(event_id, now, already_enabled=False)
