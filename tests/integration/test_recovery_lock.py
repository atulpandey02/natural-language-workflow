"""Authoritative DB recovery lock: state machine, grants, enable command (addendum).

Proves api/worker/scheduler startup is blocked against a restored-but-not-enabled
database regardless of NLW_RESTORE_MODE, that only the operator credential can
enable, and that runtime roles cannot forge or mutate the lock.
"""

import uuid
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy import create_engine, text

from nlw.backup.quiescence import quiesce
from nlw.backup.recovery_lock import (
    EnableRejected,
    RecoveryLocked,
    assert_startup_allowed_async,
    assert_startup_allowed_sync,
    enable_runtime,
    mark_validated,
)
from nlw.db.session import create_engine as create_async_engine

pytestmark = pytest.mark.integration

_PROJECT = "nlw-dr-project"


def _runtime_engines(pg_stack: SimpleNamespace) -> dict[str, object]:
    return {
        "api": create_engine(pg_stack.settings.database_url),
        "worker": create_engine(pg_stack.worker_settings.database_url),
        "scheduler": create_engine(pg_stack.scheduler_settings.database_url),
    }


def test_never_restored_db_allows_all_runtime_startup(pg_stack: SimpleNamespace) -> None:
    for engine in _runtime_engines(pg_stack).values():
        assert_startup_allowed_sync(engine)  # type: ignore[arg-type]  # no raise


async def test_api_async_preflight_blocks_reachable_locked_db(pg_stack: SimpleNamespace) -> None:
    # The API's async preflight (as nlw_app) blocks a REACHABLE but locked DB — the
    # exact bypass being fixed — and permits a never-restored / enabled one.
    owner = create_engine(pg_stack.owner_sa)
    engine = create_async_engine(pg_stack.settings)
    try:
        await assert_startup_allowed_async(engine)  # no restore event -> allowed
        qr = quiesce(owner)
        assert qr.event_id is not None
        mark_validated(owner, qr.event_id, target_project=_PROJECT)
        with pytest.raises(RecoveryLocked):
            await assert_startup_allowed_async(engine)  # validated, not enabled -> blocked
        enable_runtime(owner, event_id=qr.event_id, confirm_project=_PROJECT, operator="op")
        await assert_startup_allowed_async(engine)  # enabled -> allowed
    finally:
        await engine.dispose()


def test_full_lock_state_machine_for_all_three_roles(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = create_engine(pg_stack.owner_sa)
    engines = _runtime_engines(pg_stack)

    # (2-4) A new restore generation, quiesced but NOT validated -> all roles blocked.
    qr = quiesce(owner)
    assert qr.event_id is not None
    for engine in engines.values():
        with pytest.raises(RecoveryLocked, match="not validated"):
            assert_startup_allowed_sync(engine)  # type: ignore[arg-type]

    # (5-6) Omitting / zeroing NLW_RESTORE_MODE does NOT bypass the DB lock.
    monkeypatch.delenv("NLW_RESTORE_MODE", raising=False)
    with pytest.raises(RecoveryLocked):
        assert_startup_allowed_sync(engines["api"])  # type: ignore[arg-type]
    monkeypatch.setenv("NLW_RESTORE_MODE", "0")
    with pytest.raises(RecoveryLocked):
        assert_startup_allowed_sync(engines["worker"])  # type: ignore[arg-type]

    # (7-8) Validated but NOT operator-enabled -> still blocked (a file gate alone,
    # which is not consulted here, cannot unlock the DB authority).
    mark_validated(owner, qr.event_id, target_project=_PROJECT)
    for engine in engines.values():
        with pytest.raises(RecoveryLocked, match="not operator-enabled"):
            assert_startup_allowed_sync(engine)  # type: ignore[arg-type]

    # (9) Correct explicit enable of the newest generation -> all roles allowed.
    res = enable_runtime(
        owner, event_id=qr.event_id, confirm_project=_PROJECT, operator="op@example"
    )
    assert res.already_enabled is False
    for engine in engines.values():
        assert_startup_allowed_sync(engine)  # type: ignore[arg-type]  # no raise

    # (15) Repeated enable of the SAME generation is idempotent + audited.
    again = enable_runtime(
        owner, event_id=qr.event_id, confirm_project=_PROJECT, operator="someone-else"
    )
    assert again.already_enabled is True and again.event_id == qr.event_id
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT runtime_enabled_by FROM dr_restore_events WHERE id=%s", (qr.event_id,)
        ).fetchone()
    assert row is not None and row[0] == "op@example"  # first enabler recorded; not overwritten


def test_wrong_project_and_stale_generation_enable_rejected(pg_stack: SimpleNamespace) -> None:
    owner = create_engine(pg_stack.owner_sa)
    qr = quiesce(owner)
    assert qr.event_id is not None
    mark_validated(owner, qr.event_id, target_project=_PROJECT)

    # (11) wrong project confirmation.
    with pytest.raises(EnableRejected, match="project/database confirmation"):
        enable_runtime(owner, event_id=qr.event_id, confirm_project="other", operator="op")
    # (10) stale/nonexistent generation id.
    with pytest.raises(EnableRejected, match="newest"):
        enable_runtime(owner, event_id=str(uuid.uuid4()), confirm_project=_PROJECT, operator="op")


def test_unvalidated_generation_cannot_be_enabled(pg_stack: SimpleNamespace) -> None:
    owner = create_engine(pg_stack.owner_sa)
    qr = quiesce(owner)  # NOT validated
    assert qr.event_id is not None
    with pytest.raises(EnableRejected, match="not validated"):
        enable_runtime(owner, event_id=qr.event_id, confirm_project=_PROJECT, operator="op")


def test_later_restore_generation_invalidates_prior_enablement(
    pg_stack: SimpleNamespace,
) -> None:
    owner = create_engine(pg_stack.owner_sa)
    api = create_engine(pg_stack.settings.database_url)

    qr1 = quiesce(owner)
    assert qr1.event_id is not None
    mark_validated(owner, qr1.event_id, target_project=_PROJECT)
    enable_runtime(owner, event_id=qr1.event_id, confirm_project=_PROJECT, operator="op")
    assert_startup_allowed_sync(api)  # enabled -> allowed

    # (12) A later restore generation (changed state -> new event) re-locks startup.
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        m = pg_stack.seed_member()
        wf, ver, run = (uuid.uuid4() for _ in range(3))
        c.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, m.tenant_id)
        )
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,'{\"steps\":[]}'::jsonb)",
            (ver, m.tenant_id, wf),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) "
            "VALUES (%s,%s,%s,%s,'RUNNING')",
            (run, m.tenant_id, wf, ver),
        )
    qr2 = quiesce(owner)
    assert qr2.event_id is not None and qr2.event_id != qr1.event_id
    with pytest.raises(RecoveryLocked):
        assert_startup_allowed_sync(api)

    # (12) The OLD enablement cannot authorize the newer generation.
    with pytest.raises(EnableRejected, match="newest"):
        enable_runtime(owner, event_id=qr1.event_id, confirm_project=_PROJECT, operator="op")


def test_runtime_roles_cannot_forge_or_mutate_the_lock(pg_stack: SimpleNamespace) -> None:
    owner = create_engine(pg_stack.owner_sa)
    qr = quiesce(owner)
    assert qr.event_id is not None

    deny = psycopg.errors.InsufficientPrivilege
    for role_libpq in (pg_stack.app_libpq, pg_stack.worker_libpq, pg_stack.scheduler_libpq):
        # (13) cannot INSERT a restore event.
        with psycopg.connect(role_libpq, autocommit=True) as c, pytest.raises(deny):
            c.execute(
                "INSERT INTO dr_restore_events (id, cutoff_at) VALUES (%s, now())", (uuid.uuid4(),)
            )
        # cannot set runtime_enabled_at / modify validation state.
        with psycopg.connect(role_libpq, autocommit=True) as c, pytest.raises(deny):
            c.execute("UPDATE dr_restore_events SET runtime_enabled_at = now()")
        # cannot delete the newest restore event.
        with psycopg.connect(role_libpq, autocommit=True) as c, pytest.raises(deny):
            c.execute("DELETE FROM dr_restore_events WHERE id=%s", (qr.event_id,))
        # MAY read only the minimal lock-state columns (for its own preflight)...
        with psycopg.connect(role_libpq, autocommit=True) as c:
            c.execute(
                "SELECT id, validation_completed_at, runtime_enabled_at FROM dr_restore_events"
            )
        # ...but NOT the provenance/note columns (column-scoped SELECT).
        with psycopg.connect(role_libpq, autocommit=True) as c, pytest.raises(deny):
            c.execute("SELECT note FROM dr_restore_events")


def test_startup_preflight_reads_only_allowed_columns(pg_stack: SimpleNamespace) -> None:
    # The preflight query itself must succeed as each runtime role (grant is correct).
    owner = create_engine(pg_stack.owner_sa)
    qr = quiesce(owner)
    assert qr.event_id is not None
    mark_validated(owner, qr.event_id, target_project=_PROJECT)
    enable_runtime(owner, event_id=qr.event_id, confirm_project=_PROJECT, operator="op")
    for engine in _runtime_engines(pg_stack).values():
        with engine.connect() as conn:  # type: ignore[attr-defined]
            conn.execute(
                text(
                    "SELECT id, validation_completed_at, runtime_enabled_at "
                    "FROM dr_restore_events ORDER BY restored_at DESC LIMIT 1"
                )
            ).first()
