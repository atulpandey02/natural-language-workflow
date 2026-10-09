"""The unattended dataset dispatcher (ADR-032, owner decision O-7).

``nlw_ingest_dispatch`` can do exactly one thing with dataset data: call
``dataset_dispatch_pending()``. The dispatcher re-sends the envelopes of
committed, still-waiting processing requests, bounded and oldest first; the
real ingest runtime (``ingest_runtime``) then processes them as ``nlw_ingest``.
"""

import json
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.db.session import create_sync_engine
from nlw.ingest_dispatch import dispatcher
from nlw.ops import datasets as ops
from nlw.ops.roles import DISPATCH_GRANTS_SQL, dispatch_grant_problems

pytestmark = pytest.mark.integration

_SECRET = "dev-secret-for-tests-32bytes-min-length"
CSV = b"region,amount\n" + b"".join(f"r{i % 3},{i}\n".encode() for i in range(30))
DATASET_TABLES = (
    "datasets",
    "dataset_versions",
    "dataset_processing_requests",
    "dataset_profiles",
    "dataset_events",
    "dataset_semantic_revisions",
)


def _hdr(user_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, str]:
    token = jwt.encode(
        {
            "iss": "https://proj.supabase.co/auth/v1",
            "aud": "authenticated",
            "exp": int(time.time()) + 300,
            "sub": f"sub-{user_id}",
            "email": f"{user_id}@example.com",
        },
        _SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}", "X-Workspace-Id": str(tenant_id)}


class Broker:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[Any] = []
        self.fail = fail

    def enqueue(self, message: Any, *, delay: int | None = None) -> Any:
        if self.fail:
            raise ConnectionError("redis unavailable")
        self.sent.append(message)
        return message

    def version_ids(self) -> list[str]:
        return [json.loads(m.args[0])["version_id"] for m in self.sent]


@pytest.fixture
def st(
    pg_stack: SimpleNamespace, tmp_path: Path, ingest_runtime: Any, monkeypatch: pytest.MonkeyPatch
) -> Iterator[SimpleNamespace]:
    settings = pg_stack.settings.model_copy(
        update={
            "datasets_api_enabled": True,
            "dataset_storage_backend": "local",
            "dataset_storage_root": str(tmp_path / "datasets"),
        }
    )
    dsettings = pg_stack.settings.model_copy(
        update={"database_url": pg_stack.dispatch_sa, "dataset_dispatch_min_age_s": 0}
    )
    engine = create_sync_engine(dsettings)
    m = pg_stack.seed_member("owner")
    app = create_app(settings)
    with TestClient(app) as c:
        rt = ingest_runtime.attach(app, monkeypatch)
        yield SimpleNamespace(
            c=c, rt=rt, h=_hdr(m.user_id, m.tenant_id), pg=pg_stack, engine=engine,
            settings=dsettings, tenant=m.tenant_id,
        )  # fmt: skip
    engine.dispose()


def _owner(pg: SimpleNamespace, sql: str, *args: Any) -> list[tuple[Any, ...]]:
    with psycopg.connect(pg.owner_libpq, autocommit=True) as c:
        cur = c.execute(sql, args)
        return cur.fetchall() if cur.description else []


def _dataset(st: SimpleNamespace) -> str:
    r = st.c.post("/datasets", headers=st.h, json={"name": f"d-{uuid.uuid4().hex[:6]}"})
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _lost(st: SimpleNamespace, did: str, data: bytes = CSV) -> str:
    """A version whose content and request committed but whose enqueue failed."""
    r = st.c.post(
        f"/datasets/{did}/versions",
        headers={**st.h, "Idempotency-Key": uuid.uuid4().hex},
        json={"original_filename": "a.csv", "declared_size_bytes": len(data)},
    )
    vid = str(r.json()["id"])
    st.rt.fail = True
    put = st.c.put(f"/datasets/{did}/versions/{vid}/content", headers=st.h, content=data)
    st.rt.fail = False
    assert put.status_code == 503 and put.json()["error"]["code"] == "PROCESSING_NOT_QUEUED"
    return vid


def _age(pg: SimpleNamespace, vid: str, seconds: int) -> None:
    """Pretend the version's requests were made ``seconds`` ago. The table is
    immutable to every runtime role; the test owner disables the guard briefly.
    (This breaks the envelope digest: aged requests are never processed.)"""
    with psycopg.connect(pg.owner_libpq, autocommit=True) as c, c.transaction():
        c.execute(
            "ALTER TABLE dataset_processing_requests "
            "DISABLE TRIGGER dataset_processing_requests_guard"
        )
        c.execute(
            "UPDATE dataset_processing_requests SET requested_at = requested_at - "
            "make_interval(secs => %s) WHERE version_id = %s",
            (seconds, vid),
        )
        c.execute(
            "ALTER TABLE dataset_processing_requests "
            "ENABLE TRIGGER dataset_processing_requests_guard"
        )


def _status(pg: SimpleNamespace, vid: str) -> tuple[Any, ...]:
    return _owner(
        pg,
        "SELECT status, (SELECT count(*) FROM dataset_profiles p WHERE p.version_id = v.id), "
        "(SELECT count(*) FROM dataset_processing_requests r WHERE r.version_id = v.id) "
        "FROM dataset_versions v WHERE id = %s",
        vid,
    )[0]


def _pending(pg: SimpleNamespace, limit: int = 100, min_age: int = 0, fresh: int = 82800) -> Any:
    with psycopg.connect(pg.dispatch_libpq) as c:
        return c.execute(
            "SELECT * FROM dataset_dispatch_pending(%s, %s, %s)", (limit, min_age, fresh)
        ).fetchall()


# --- the role boundary ----------------------------------------------------------------------


def test_the_dispatcher_role_holds_exactly_one_function_and_the_lock_columns(
    pg_stack: SimpleNamespace,
) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as c:
        actual = {r[0] for r in c.execute(DISPATCH_GRANTS_SQL).fetchall()}
        attrs = c.execute(
            "SELECT rolcanlogin, rolsuper, rolbypassrls, rolinherit, rolcreatedb, rolcreaterole "
            "FROM pg_roles WHERE rolname = 'nlw_ingest_dispatch'"
        ).fetchone()
        members = c.execute(
            "SELECT count(*) FROM pg_auth_members am JOIN pg_roles r ON r.oid IN "
            "(am.roleid, am.member) WHERE r.rolname = 'nlw_ingest_dispatch'"
        ).fetchone()
        owner, definer, path = c.execute(
            "SELECT pg_get_userbyid(proowner), prosecdef, proconfig FROM pg_proc "
            "WHERE proname = 'dataset_dispatch_pending'"
        ).fetchone()  # type: ignore[misc]
    assert dispatch_grant_problems(actual) == []
    assert attrs == (True, False, False, False, False, False)  # LOGIN in tests only
    assert members == (0,)
    assert (owner, definer, path) == ("nlw_rls_bypass", True, ["search_path=pg_catalog"])


@pytest.mark.parametrize("table", DATASET_TABLES)
def test_the_dispatcher_can_neither_read_nor_write_any_dataset_table(
    pg_stack: SimpleNamespace, table: str
) -> None:
    for sql in (
        f"SELECT 1 FROM {table} LIMIT 1",
        f"DELETE FROM {table}",
        f"UPDATE {table} SET tenant_id = tenant_id",
    ):
        with (
            psycopg.connect(pg_stack.dispatch_libpq) as c,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            c.execute(sql)


def test_no_other_runtime_role_can_call_the_dispatch_function(pg_stack: SimpleNamespace) -> None:
    for url in (
        pg_stack.app_libpq,
        pg_stack.worker_libpq,
        pg_stack.scheduler_libpq,
        pg_stack.ingest_libpq,
    ):
        with psycopg.connect(url) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM dataset_dispatch_pending(1, 0, 60)")
    # ... and the worker and scheduler gained nothing on dataset tables.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        for role in ("nlw_worker", "nlw_scheduler"):
            for table in DATASET_TABLES:
                for priv in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                    row = c.execute(
                        "SELECT has_table_privilege(%s, %s, %s)", (role, table, priv)
                    ).fetchone()
                    assert row == (False,), (role, table, priv)


def test_the_dispatcher_cannot_set_or_use_a_signed_context(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.dispatch_libpq) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT public.app_ctx_claims()")
        c.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM ctx_keys")


# --- the function ---------------------------------------------------------------------------


def test_only_waiting_fresh_requests_are_returned_oldest_first_with_aggregate_stats(
    st: SimpleNamespace,
) -> None:
    did = _dataset(st)
    old, mid, new = _lost(st, did), _lost(st, did), _lost(st, did)
    _age(st.pg, old, 600)
    _age(st.pg, mid, 300)
    # Settled or otherwise ineligible versions never appear.
    done = _lost(st, did)
    st.rt.process(_pending_envelope(st, done))
    assert _status(st.pg, done)[0] == "PROFILED"
    deleting = _lost(st, did)
    assert st.c.delete(f"/datasets/{did}/versions/{deleting}", headers=st.h).status_code == 202

    rows = _pending(st.pg)
    assert [str(r[3]) for r in rows] == [old, mid, new]
    assert {(r[7], r[9]) for r in rows} == {(3, 0)}  # pending_total, stale_total
    assert 600 <= rows[0][8] < 700  # oldest age
    # min_age keeps very recent requests (likely still in flight) out of the batch,
    # while the stats still count every waiting version.
    rows = _pending(st.pg, min_age=200)
    assert [str(r[3]) for r in rows] == [old, mid] and rows[0][7] == 3
    # Bounded: the limit is clamped to 1..1000.
    assert len(_pending(st.pg, limit=1)) == 1 and len(_pending(st.pg, limit=0)) == 1
    assert len(_pending(st.pg, limit=100_000)) == 3
    # Too old for the consumer: counted, never returned.
    rows = _pending(st.pg, fresh=450)
    assert [str(r[3]) for r in rows] == [mid, new] and rows[0][9] == 1


def test_the_function_returns_ids_digests_and_counts_only(st: SimpleNamespace) -> None:
    did = _dataset(st)
    _lost(st, did)
    with psycopg.connect(st.pg.dispatch_libpq) as c:
        cur = c.execute("SELECT * FROM dataset_dispatch_pending(10, 0, 82800)")
        names = [d.name for d in cur.description or []]
        rows = cur.fetchall()
    assert names == [
        "request_id", "tenant_id", "dataset_id", "version_id", "content_sha256",
        "envelope_sha256", "requested_at_us", "pending_total", "oldest_age_s", "stale_total",
    ]  # fmt: skip
    text = json.dumps([[str(v) for v in r] for r in rows])
    assert "a.csv" not in text and "quarantine" not in text and "region" not in text


def test_with_nothing_waiting_the_stats_row_is_still_returned(st: SimpleNamespace) -> None:
    rows = _pending(st.pg)
    assert len(rows) == 1 and rows[0][0] is None and (rows[0][7], rows[0][8]) == (0, 0.0)


def test_a_live_lease_hides_a_version_and_an_expired_one_does_not(st: SimpleNamespace) -> None:
    did = _dataset(st)
    vid = _lost(st, did)
    _owner(
        st.pg,
        "UPDATE dataset_versions SET status = 'PROFILING', processing_lease_token = %s, "
        "processing_lease_expires_at = now() + interval '5 minutes' WHERE id = %s",
        uuid.uuid4(),
        vid,
    )
    assert _pending(st.pg)[0][0] is None
    _owner(
        st.pg,
        "UPDATE dataset_versions SET processing_lease_expires_at = now() - interval '1 second' "
        "WHERE id = %s",
        vid,
    )
    assert [str(r[3]) for r in _pending(st.pg)] == [vid]


def _pending_envelope(st: SimpleNamespace, vid: str) -> str:
    (row,) = [r for r in _pending(st.pg) if str(r[3]) == vid]
    return dispatcher._envelope(_Row(row)).to_json()


class _Row:
    _COLS = (
        "request_id", "tenant_id", "dataset_id", "version_id", "content_sha256",
        "envelope_sha256", "requested_at_us", "pending_total", "oldest_age_s", "stale_total",
    )  # fmt: skip

    def __init__(self, values: tuple[Any, ...]) -> None:
        for k, v in zip(self._COLS, values, strict=True):
            setattr(self, k, v)


# --- the dispatcher -------------------------------------------------------------------------


def test_a_cycle_resends_lost_work_once_and_the_ingest_runtime_settles_it(
    st: SimpleNamespace,
) -> None:
    did = _dataset(st)
    a, b = _lost(st, did), _lost(st, did)
    broker, state, clock = Broker(), dispatcher.DispatchState(), [1000.0]
    res = dispatcher.run_cycle(st.engine, broker, st.settings, state, clock=lambda: clock[0])
    assert (res.result, res.pending, res.enqueued, res.stale) == ("ok", 2, 2, 0)
    assert broker.version_ids() == [a, b]  # oldest first
    # Within the resend window nothing is sent again.
    clock[0] += 60
    assert (
        dispatcher.run_cycle(st.engine, broker, st.settings, state, clock=lambda: clock[0]).enqueued
        == 0
    )
    # Delivered twice (the first send and a duplicate): one profile, one request.
    for m in [*broker.sent, broker.sent[0]]:
        st.rt.process(m.args[0])
    assert _status(st.pg, a) == ("PROFILED", 1, 1) and _status(st.pg, b) == ("PROFILED", 1, 1)
    res = dispatcher.run_cycle(st.engine, broker, st.settings, state, clock=lambda: clock[0])
    assert (res.pending, res.enqueued, state.last_sent) == (0, 0, {})  # memory pruned


def test_a_still_waiting_request_is_resent_after_the_resend_window(st: SimpleNamespace) -> None:
    did = _dataset(st)
    vid = _lost(st, did)
    broker, state, clock = Broker(), dispatcher.DispatchState(), [0.0]
    dispatcher.run_cycle(st.engine, broker, st.settings, state, clock=lambda: clock[0])
    clock[0] += st.settings.dataset_dispatch_resend_s
    dispatcher.run_cycle(st.engine, broker, st.settings, state, clock=lambda: clock[0])
    assert broker.version_ids() == [vid, vid]
    assert _status(st.pg, vid) == ("QUARANTINED", 0, 1)  # the dispatcher never processes


def test_the_batch_is_bounded(st: SimpleNamespace) -> None:
    did = _dataset(st)
    vids = [_lost(st, did) for _ in range(3)]
    settings = st.settings.model_copy(update={"dataset_dispatch_batch": 2})
    broker = Broker()
    res = dispatcher.run_cycle(st.engine, broker, settings, dispatcher.DispatchState())
    assert (res.pending, res.enqueued) == (3, 2) and broker.version_ids() == vids[:2]


def test_the_recovery_lock_stops_dispatch(st: SimpleNamespace) -> None:
    did = _dataset(st)
    vid = _lost(st, did)
    restore = uuid.uuid4()
    _owner(st.pg, "INSERT INTO dr_restore_events (id, cutoff_at) VALUES (%s, now())", restore)
    broker = Broker()
    res = dispatcher.run_cycle(st.engine, broker, st.settings, dispatcher.DispatchState())
    assert res.result == "locked" and broker.sent == []
    with pytest.raises(dispatcher.DispatchBootRefused, match="recovery lock"):
        dispatcher.boot_checks(st.engine)
    _owner(
        st.pg,
        "UPDATE dr_restore_events SET validation_completed_at = now(), runtime_enabled_at = now() "
        "WHERE id = %s",
        restore,
    )
    res = dispatcher.run_cycle(st.engine, broker, st.settings, dispatcher.DispatchState())
    assert res.result == "ok" and broker.version_ids() == [vid]


def test_one_sweep_at_a_time_with_the_operator_cli(st: SimpleNamespace) -> None:
    _lost(st, _dataset(st))
    with psycopg.connect(st.pg.owner_libpq, autocommit=True) as other:
        other.execute(ops._SQL_SWEEP_LOCK)  # an operator sweep is running
        broker = Broker()
        res = dispatcher.run_cycle(st.engine, broker, st.settings, dispatcher.DispatchState())
        assert res.result == "busy" and broker.sent == []
        other.execute(ops._SQL_SWEEP_UNLOCK)
    res = dispatcher.run_cycle(st.engine, Broker(), st.settings, dispatcher.DispatchState())
    assert res.result == "ok"
    # The dispatcher released the lock: the operator CLI can run now.
    with psycopg.connect(st.pg.owner_libpq, autocommit=True) as c:
        assert ops.dispatch_pending(c, Broker(), dry_run=True)["busy"] == 0


def test_a_broker_failure_changes_nothing_and_releases_the_lock(st: SimpleNamespace) -> None:
    did = _dataset(st)
    vid = _lost(st, did)
    before = _status(st.pg, vid)
    state = dispatcher.DispatchState()
    with pytest.raises(ConnectionError):
        dispatcher.run_cycle(st.engine, Broker(fail=True), st.settings, state)
    assert _status(st.pg, vid) == before and state.last_sent == {}
    res = dispatcher.run_cycle(st.engine, Broker(), st.settings, state)
    assert (res.result, res.enqueued) == ("ok", 1)


def test_boot_is_refused_for_any_other_identity(pg_stack: SimpleNamespace) -> None:
    for url in (pg_stack.settings.database_url, pg_stack.owner_sa, pg_stack.ingest_sa):
        engine = create_sync_engine(pg_stack.settings.model_copy(update={"database_url": url}))
        try:
            with pytest.raises(dispatcher.DispatchBootRefused, match="must connect as"):
                dispatcher.boot_checks(engine)
        finally:
            engine.dispose()
    engine = create_sync_engine(
        pg_stack.settings.model_copy(update={"database_url": pg_stack.dispatch_sa})
    )
    try:
        dispatcher.boot_checks(engine)  # the dispatcher itself boots
    finally:
        engine.dispose()


def test_0027_goes_down_and_up_and_removes_exactly_its_objects(pg_stack: SimpleNamespace) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", pg_stack.owner_sa)

    def shape() -> tuple[Any, ...]:
        with psycopg.connect(pg_stack.owner_libpq) as c:
            fn = c.execute(
                "SELECT count(*) FROM pg_proc WHERE proname = 'dataset_dispatch_pending'"
            ).fetchone()
            grants = {r[0] for r in c.execute(DISPATCH_GRANTS_SQL).fetchall()}
            bypass_cols = c.execute(
                "SELECT count(*) FROM information_schema.column_privileges WHERE grantee = "
                "'nlw_rls_bypass' AND table_name IN ('dataset_processing_requests', "
                "'dataset_versions')"
            ).fetchone()
            policies = c.execute("SELECT count(*) FROM pg_policies").fetchone()
        return fn, frozenset(grants), bypass_cols, policies

    head = shape()
    assert head[0] == (1,) and dispatch_grant_problems(set(head[1])) == []
    command.downgrade(cfg, "0026_dataset_ingest_role")
    down = shape()
    assert down[0] == (0,) and down[1] == frozenset() and down[2] == (0,)
    assert down[3] == head[3] == (74,)
    command.upgrade(cfg, "head")
    assert shape() == head


def test_the_batch_limit_is_clamped_to_1000(st: SimpleNamespace) -> None:
    """More than 1000 waiting versions: the function never returns more than
    1000 rows, whatever limit is asked for. (Bulk-seeded as the owner through
    the real triggers; the same shape the upload API writes.)"""
    did = _dataset(st)
    n = 1001
    with psycopg.connect(st.pg.owner_libpq) as c, c.transaction():
        user = c.execute("SELECT created_by FROM datasets WHERE id = %s", (did,)).fetchone()[0]  # type: ignore[index]
        for _ in range(n):  # numbers are allocated one at a time (dataset_guard)
            (num,) = c.execute(
                "UPDATE datasets SET last_version_number = last_version_number + 1 "
                "WHERE id = %s RETURNING last_version_number",
                (did,),
            ).fetchone()  # type: ignore[misc]
            c.execute(
                "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, "
                "status, original_filename, media_type, declared_size_bytes, created_by) "
                "VALUES (gen_random_uuid(), %s, %s, %s, 'QUARANTINED', 'b.csv', 'text/csv', "
                "10, %s)",
                (st.tenant, did, num, user),
            )
        c.execute(
            "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
            "from_status, to_status, actor_kind, actor_user_id) "
            "SELECT gen_random_uuid(), tenant_id, dataset_id, id, 'VERSION_CREATED', NULL, "
            "'QUARANTINED', 'user', created_by FROM dataset_versions WHERE dataset_id = %s",
            (did,),
        )
        c.execute(
            "UPDATE dataset_versions SET content_sha256 = repeat('a', 64), "
            "storage_object_key = 'quarantine/' || tenant_id || '/' || dataset_id || '/' || id "
            "WHERE dataset_id = %s",
            (did,),
        )
        c.execute(
            "INSERT INTO dataset_processing_requests (id, tenant_id, dataset_id, version_id, "
            "content_sha256, requested_by, envelope_sha256) "
            "SELECT gen_random_uuid(), tenant_id, dataset_id, id, content_sha256, created_by, "
            "repeat('0', 64) FROM dataset_versions WHERE dataset_id = %s",
            (did,),
        )
    rows = _pending(st.pg, limit=5000)
    assert len(rows) == 1000 and rows[0][7] == n
