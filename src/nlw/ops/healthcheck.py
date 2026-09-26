"""Container healthcheck for the worker/scheduler roles (M9, req 7).

Beyond "is the process alive", this proves the process can actually do its job:
PostgreSQL is reachable, Redis is reachable, and the process's own metrics port
is accepting connections (which only happens after the role has booted). Exit 0
when all checks pass, 1 otherwise. Reasons print to stderr (never a secret).

Usage: ``python -m nlw.ops.healthcheck``
"""

import socket
import sys
import uuid

import psycopg
import redis

from nlw.core.config import Settings, get_settings
from nlw.tenancy.keys import build_signer
from nlw.tenancy.signing import Purpose


def _libpq_url(database_url: str) -> str:
    """SQLAlchemy URL -> libpq URL (drop the +driver suffix)."""
    return database_url.replace("+psycopg", "", 1)


def _check_postgres(settings: Settings) -> None:
    with psycopg.connect(_libpq_url(settings.database_url), connect_timeout=3) as conn:
        conn.execute("SELECT 1")


def _check_recovery_lock(settings: Settings) -> None:
    """The authoritative DR recovery lock (``dr_restore_events``) must permit this
    role to run. A worker/scheduler whose boot was refused by the lock — or that is
    restart-looping against a locked database — must never be reported healthy."""
    from nlw.backup.recovery_lock import assert_startup_allowed_sync
    from nlw.db.session import create_sync_engine

    engine = create_sync_engine(settings)
    try:
        assert_startup_allowed_sync(engine)
    finally:
        engine.dispose()


def _check_redis(settings: Settings) -> None:
    client = redis.from_url(settings.redis_url, socket_connect_timeout=3, socket_timeout=3)
    try:
        client.ping()
    finally:
        client.close()


def _check_metrics_port(settings: Settings) -> None:
    if not settings.metrics_enabled:
        return
    with socket.create_connection(("127.0.0.1", settings.metrics_port), timeout=3):
        pass


_ROLE_PURPOSE = {
    "nlw_worker": Purpose.WORKER_EXECUTION,
    "nlw_scheduler": Purpose.SCHEDULER_RECONCILE,
    "nlw_app": Purpose.API_REQUEST,
}


def _check_signed_context(settings: Settings) -> None:
    """Prove this container's key file signs contexts the database verifies (P3B).

    The purpose is bound to the DB LOGIN ROLE the container connects as (never to
    configuration), a throwaway sentinel context is signed, applied
    transaction-locally, verified via ``app_ctx_claims()``, and rolled back.
    """
    with psycopg.connect(_libpq_url(settings.database_url), connect_timeout=3) as conn:
        role = str(conn.execute("SELECT session_user").fetchone()[0])  # type: ignore[index]
        purpose = _ROLE_PURPOSE[role]
        signer = build_signer(settings, purpose)
        nil = uuid.UUID(int=0)
        ids: dict[str, uuid.UUID] = (
            {"tenant_id": nil, "run_id": nil}
            if purpose is Purpose.WORKER_EXECUTION
            else {"user_id": nil, "tenant_id": nil}
            if purpose is Purpose.API_REQUEST
            else {}
        )
        gucs = signer.sign(**ids).as_gucs()
        try:
            with conn.transaction():
                for name, value in gucs.items():
                    conn.execute("SELECT set_config(%s, %s, true)", (name, value))
                row = conn.execute("SELECT (public.app_ctx_claims()).purpose").fetchone()
                verified = row is not None and row[0] == str(purpose)
                raise _Rollback  # never persist the probe (transaction-local anyway)
        except _Rollback:
            pass
        if not verified:
            raise RuntimeError("signed context not verified by the database")


class _Rollback(Exception):
    pass


def main() -> int:
    settings = get_settings()
    checks = (
        ("postgres", _check_postgres),
        ("recovery_lock", _check_recovery_lock),
        ("redis", _check_redis),
        ("metrics", _check_metrics_port),
        ("signed_context", _check_signed_context),
    )
    for name, check in checks:
        try:
            check(settings)
        except Exception as exc:  # noqa: BLE001 - report class only, never secrets
            print(f"healthcheck {name} failed: {type(exc).__name__}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
