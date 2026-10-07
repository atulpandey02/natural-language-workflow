"""Lifecycle-event authenticity (review finding F, migration 0025).

Before 0025 an ``nlw_app`` session holding a valid SIGNED admin context could
insert arbitrary non-operator lifecycle events: any type, any from/to, any
user as the actor, with no transition behind them. These tests use exactly
that session (direct SQL, no service code) and show every forgery is refused,
while genuine transitions with their single event still commit.
"""

import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

REFUSED = (psycopg.errors.CheckViolation, psycopg.errors.InsufficientPrivilege)
_EV = (
    "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
    "from_status, to_status, actor_kind, actor_user_id, reason_code) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)


def _owner(pg: SimpleNamespace) -> psycopg.Connection[Any]:
    return psycopg.connect(pg.owner_libpq, autocommit=True)


def _admin(pg: SimpleNamespace, user: uuid.UUID, tenant: uuid.UUID) -> psycopg.Connection[Any]:
    conn = psycopg.connect(pg.app_libpq)
    pg.apply_ctx(conn, pg.sign(Purpose.API_REQUEST, user_id=user, tenant_id=tenant))
    return conn


def _resign(pg: SimpleNamespace, conn: psycopg.Connection[Any], user: uuid.UUID,
            tenant: uuid.UUID) -> None:  # fmt: skip
    conn.rollback()
    pg.apply_ctx(conn, pg.sign(Purpose.API_REQUEST, user_id=user, tenant_id=tenant))


def _setup(pg: SimpleNamespace) -> SimpleNamespace:
    """A workspace with one dataset (created WITH its event) and one version."""
    m = pg.seed_member("owner")
    did, vid = uuid.uuid4(), uuid.uuid4()
    with _owner(pg) as c, c.transaction():
        c.execute(
            "INSERT INTO datasets (id, tenant_id, name, normalized_name, status, created_by) "
            "VALUES (%s, %s, 'Evt', 'evt', 'ACTIVE', %s)",
            (did, m.tenant_id, m.user_id),
        )
        c.execute(_EV, (uuid.uuid4(), m.tenant_id, did, None, "DATASET_CREATED", None,
                        "ACTIVE", "user", m.user_id, None))  # fmt: skip
        c.execute("UPDATE datasets SET last_version_number = 1 WHERE id = %s", (did,))
        c.execute(
            "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, status, "
            "original_filename, media_type, declared_size_bytes, created_by) VALUES "
            "(%s, %s, %s, 1, 'QUARANTINED', 'a.csv', 'text/csv', 10, %s)",
            (vid, m.tenant_id, did, m.user_id),
        )
        c.execute(_EV, (uuid.uuid4(), m.tenant_id, did, vid, "VERSION_CREATED", None,
                        "QUARANTINED", "user", m.user_id, None))  # fmt: skip
    return SimpleNamespace(user=m.user_id, tenant=m.tenant_id, did=did, vid=vid)


def _events(pg: SimpleNamespace, did: uuid.UUID) -> int:
    with _owner(pg) as c:
        row = c.execute(
            "SELECT count(*) FROM dataset_events WHERE dataset_id = %s", (did,)
        ).fetchone()
    assert row is not None
    return int(row[0])


def test_an_event_without_a_transition_is_refused(pg_stack: SimpleNamespace) -> None:
    w = _setup(pg_stack)
    before = _events(pg_stack, w.did)
    forged = [
        ("VERSION_ACTIVATED", "PROFILED", "ACTIVE"),
        ("VERSION_PROFILED", "PROFILING", "PROFILED"),
        ("VERSION_DELETION_REQUESTED", "QUARANTINED", "DELETING"),
        ("VERSION_CREATED", None, "QUARANTINED"),  # already recorded, long ago
    ]
    with _admin(pg_stack, w.user, w.tenant) as conn:
        for et, src, dst in forged:
            with pytest.raises(REFUSED):
                conn.execute(_EV, (uuid.uuid4(), w.tenant, w.did, w.vid, et, src, dst, "user",
                                   w.user, None))  # fmt: skip
            _resign(pg_stack, conn, w.user, w.tenant)
        with pytest.raises(REFUSED):  # a dataset-level event with no transition
            conn.execute(_EV, (uuid.uuid4(), w.tenant, w.did, None, "DATASET_DELETION_REQUESTED",
                               "ACTIVE", "DELETING", "user", w.user, "USER_REQUEST"))  # fmt: skip
    assert _events(pg_stack, w.did) == before


def test_a_real_transition_accepts_exactly_its_own_single_event(
    pg_stack: SimpleNamespace,
) -> None:
    w = _setup(pg_stack)
    row = (uuid.uuid4(), w.tenant, w.did, w.vid, "VERSION_DELETION_REQUESTED", "QUARANTINED",
           "DELETING", "user", w.user, "USER_REQUEST")  # fmt: skip
    with _admin(pg_stack, w.user, w.tenant) as conn:
        conn.execute("UPDATE dataset_versions SET status = 'DELETING' WHERE id = %s", (w.vid,))
        for wrong in (
            {4: "VERSION_REJECTED"},  # the wrong event type for the state
            {5: "PROFILED"},  # the wrong previous state
            {6: "REJECTED"},  # the wrong target state
        ):
            bad = list(row)
            bad[0] = uuid.uuid4()
            for i, value in wrong.items():
                bad[i] = value
            with pytest.raises(REFUSED), conn.transaction():  # savepoint keeps the update
                conn.execute(_EV, tuple(bad))
        conn.execute(_EV, row)
        with pytest.raises(REFUSED), conn.transaction():  # a second event for it
            conn.execute(_EV, (uuid.uuid4(), *row[1:]))
        conn.commit()
    with _owner(pg_stack) as c:
        assert c.execute(
            "SELECT count(*) FROM dataset_events WHERE version_id = %s AND to_status = 'DELETING'",
            (w.vid,),
        ).fetchone() == (1,)


def test_a_runtime_transition_without_its_event_cannot_commit(pg_stack: SimpleNamespace) -> None:
    w = _setup(pg_stack)
    with _admin(pg_stack, w.user, w.tenant) as conn:
        conn.execute("UPDATE dataset_versions SET status = 'DELETING' WHERE id = %s", (w.vid,))
        with pytest.raises(psycopg.errors.CheckViolation, match="exactly one event"):
            conn.commit()
    with _owner(pg_stack) as c:
        assert c.execute(
            "SELECT status FROM dataset_versions WHERE id = %s", (w.vid,)
        ).fetchone() == ("QUARANTINED",)


def test_the_actor_is_the_signed_user(pg_stack: SimpleNamespace) -> None:
    w = _setup(pg_stack)
    other = pg_stack.add_membership(w.tenant, "admin")
    with _admin(pg_stack, w.user, w.tenant) as conn:
        conn.execute("UPDATE dataset_versions SET status = 'DELETING' WHERE id = %s", (w.vid,))
        for kind, actor in (("user", other), ("service", other), ("user", None),
                            ("operator", None)):  # fmt: skip
            with pytest.raises(REFUSED), conn.transaction():
                conn.execute(_EV, (uuid.uuid4(), w.tenant, w.did, w.vid,
                                   "VERSION_DELETION_REQUESTED", "QUARANTINED", "DELETING", kind,
                                   actor, "USER_REQUEST"))  # fmt: skip
        # The guard is satisfied here, so RLS alone refuses the false attribution.
        with pytest.raises(psycopg.errors.InsufficientPrivilege), conn.transaction():
            conn.execute(_EV, (uuid.uuid4(), w.tenant, w.did, w.vid,
                               "VERSION_DELETION_REQUESTED", "QUARANTINED", "DELETING", "user",
                               other, "USER_REQUEST"))  # fmt: skip
        conn.execute(
            _EV,
            (uuid.uuid4(), w.tenant, w.did, w.vid, "VERSION_DELETION_REQUESTED", "QUARANTINED",
             "DELETING", "service", w.user, "USER_REQUEST"),
        )  # fmt: skip
        conn.commit()


def test_events_cannot_be_backdated(pg_stack: SimpleNamespace) -> None:
    w = _setup(pg_stack)
    with _admin(pg_stack, w.user, w.tenant) as conn:
        conn.execute("UPDATE dataset_versions SET status = 'DELETING' WHERE id = %s", (w.vid,))
        conn.execute(
            "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
            "from_status, to_status, actor_kind, actor_user_id, reason_code, created_at) VALUES "
            "(%s, %s, %s, %s, 'VERSION_DELETION_REQUESTED', 'QUARANTINED', 'DELETING', 'user', "
            "%s, 'USER_REQUEST', now() - interval '1 year')",
            (uuid.uuid4(), w.tenant, w.did, w.vid, w.user),
        )
        txn_now = conn.execute("SELECT now()").fetchone()
        conn.commit()
    with _owner(pg_stack) as c:
        stored = c.execute(
            "SELECT created_at FROM dataset_events WHERE version_id = %s "
            "AND event_type = 'VERSION_DELETION_REQUESTED'",
            (w.vid,),
        ).fetchone()
    assert txn_now is not None and stored == (txn_now[0],)


def test_another_workspace_cannot_record_events_for_this_one(pg_stack: SimpleNamespace) -> None:
    w = _setup(pg_stack)
    b = pg_stack.seed_member("owner")
    with _owner(pg_stack) as c:  # the attacker is also an owner of A, but signed into B
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,'owner')",
            (uuid.uuid4(), b.user_id, w.tenant),
        )
    with _admin(pg_stack, b.user_id, b.tenant_id) as conn, pytest.raises(REFUSED):
        conn.execute(
            _EV,
            (uuid.uuid4(), w.tenant, w.did, w.vid, "VERSION_DELETION_REQUESTED", "QUARANTINED",
             "DELETING", "user", b.user_id, "USER_REQUEST"),
        )  # fmt: skip


def test_purge_evidence_only_for_a_deleting_version(pg_stack: SimpleNamespace) -> None:
    w = _setup(pg_stack)
    with _owner(pg_stack) as c, pytest.raises(psycopg.errors.CheckViolation, match="DELETING"):
        c.execute(
            "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
            "from_status, to_status, actor_kind, reason_code, receipt_sink, receipt_id, "
            "receipt_digest) VALUES (%s,%s,%s,%s,'VERSION_OBJECT_PURGED','DELETING','DELETING',"
            "'operator','OPERATOR_PURGE','local-fake','r1',%s)",
            (uuid.uuid4(), w.tenant, w.did, w.vid, "a" * 64),
        )


# --- no API input reaches the event fields -----------------------------------------------

_SECRET = "dev-secret-for-tests-32bytes-min-length"


def _hdr(user_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, str]:
    token = jwt.encode(
        {"iss": "https://proj.supabase.co/auth/v1", "aud": "authenticated",
         "exp": int(time.time()) + 300, "sub": f"sub-{user_id}", "email": f"{user_id}@example.com"},
        _SECRET, algorithm="HS256",
    )  # fmt: skip
    return {"Authorization": f"Bearer {token}", "X-Workspace-Id": str(tenant_id)}


@pytest.fixture
def api(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    settings = pg_stack.settings.model_copy(update={"datasets_api_enabled": True})
    with TestClient(create_app(settings)) as c:
        yield c


def test_no_api_input_can_carry_event_fields(api: TestClient, pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member("owner")
    h = _hdr(m.user_id, m.tenant_id)
    for extra in ({"event_type": "VERSION_ACTIVATED"}, {"actor_user_id": str(uuid.uuid4())},
                  {"status": "ACTIVE"}, {"from_status": "PROFILED"}):  # fmt: skip
        r = api.post("/datasets", headers=h, json={"name": f"x-{uuid.uuid4().hex[:6]}", **extra})
        assert r.status_code == 422, (extra, r.status_code)
    d = api.post("/datasets", headers=h, json={"name": "Clean"}).json()
    with _owner(pg_stack) as c:
        rows = c.execute(
            "SELECT event_type, actor_kind, actor_user_id FROM dataset_events "
            "WHERE dataset_id = %s",
            (d["id"],),
        ).fetchall()
    assert [r[:2] for r in rows] == [("DATASET_CREATED", "user")]
