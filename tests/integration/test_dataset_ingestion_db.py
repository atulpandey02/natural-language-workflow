"""Migration 0025 (ADR-030): database-enforced ingestion invariants.

Constraints and triggers are exercised as the table OWNER (superuser in the test
harness, so only triggers/constraints stand in the way); RLS and grants as the
real runtime roles with signed contexts. Also: a populated 0024 database
upgrades without rewriting anything, and 0025 goes down and up again.
"""

import json
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.config import Config

from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

SHA = "b" * 64
PROFILE = json.dumps({"contract_version": "profile-2", "columns": []})
MAPPING = json.dumps({"contract_version": "semantics-1", "columns": []})
CHECK = (psycopg.errors.CheckViolation, psycopg.errors.RaiseException)


def _owner(pg: SimpleNamespace) -> psycopg.Connection[Any]:
    return psycopg.connect(pg.owner_libpq, autocommit=True)


def _app(pg: SimpleNamespace, user: uuid.UUID, tenant: uuid.UUID) -> psycopg.Connection[Any]:
    conn = psycopg.connect(pg.app_libpq)
    pg.apply_ctx(conn, pg.sign(Purpose.API_REQUEST, user_id=user, tenant_id=tenant))
    return conn


def _dataset(c: psycopg.Connection[Any], tenant: uuid.UUID, by: uuid.UUID) -> uuid.UUID:
    did = uuid.uuid4()
    name = f"d-{did.hex[:8]}"
    c.execute(
        "INSERT INTO datasets (id, tenant_id, name, normalized_name, status, created_by) "
        "VALUES (%s, %s, %s, %s, 'ACTIVE', %s)",
        (did, tenant, name, name, by),
    )
    return did


def _version(
    c: psycopg.Connection[Any],
    tenant: uuid.UUID,
    did: uuid.UUID,
    by: uuid.UUID,
    *,
    key: str | None = None,
) -> uuid.UUID:
    with c.transaction():
        n = c.execute(
            "UPDATE datasets SET last_version_number = last_version_number + 1 "
            "WHERE id = %s RETURNING last_version_number",
            (did,),
        ).fetchone()
        assert n is not None
        vid = uuid.uuid4()
        c.execute(
            "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, status, "
            "original_filename, media_type, declared_size_bytes, created_by, "
            "upload_idempotency_key) VALUES (%s, %s, %s, %s, 'QUARANTINED', 'a.csv', "
            "'text/csv', 10, %s, %s)",
            (vid, tenant, did, n[0], by, key),
        )
    return vid


def _content(c: psycopg.Connection[Any], tenant: uuid.UUID, did: uuid.UUID, vid: uuid.UUID) -> str:
    key = f"quarantine/{tenant}/{did}/{vid}"
    c.execute(
        "UPDATE dataset_versions SET content_sha256 = %s, storage_object_key = %s WHERE id = %s",
        (SHA, key, vid),
    )
    return key


def _profile(c: psycopg.Connection[Any], vid: uuid.UUID, sha: str = SHA) -> None:
    c.execute(
        "INSERT INTO dataset_profiles (version_id, tenant_id, dataset_id, contract_version, "
        "content_sha256, row_count, column_count, profile) SELECT id, tenant_id, dataset_id, "
        "'profile-2', %s, 1, 1, %s::jsonb FROM dataset_versions WHERE id = %s",
        (sha, PROFILE, vid),
    )


def _semantics(c: psycopg.Connection[Any], vid: uuid.UUID, n: int = 1) -> None:
    c.execute(
        "INSERT INTO dataset_semantic_revisions (id, tenant_id, dataset_id, version_id, "
        "revision_number, mapping, confirmed_by) SELECT %s, tenant_id, dataset_id, id, %s, "
        "%s::jsonb, created_by FROM dataset_versions WHERE id = %s",
        (uuid.uuid4(), n, MAPPING, vid),
    )


def _status(c: psycopg.Connection[Any], vid: uuid.UUID, status: str, **cols: str) -> None:
    sets = ", ".join(["status = %s"] + [f"{k} = %s" for k in cols])
    if status == "PROFILING":  # entering PROFILING takes a database-time lease
        sets += (
            ", processing_lease_token = gen_random_uuid(), "
            "processing_lease_expires_at = now() + interval '5 minutes'"
        )
    c.execute(
        f"UPDATE dataset_versions SET {sets} WHERE id = %s",  # noqa: S608 - fixed column names
        (status, *cols.values(), vid),
    )


def _profiled(
    c: psycopg.Connection[Any], tenant: uuid.UUID, did: uuid.UUID, by: uuid.UUID
) -> uuid.UUID:
    vid = _version(c, tenant, did, by)
    key = _content(c, tenant, did, vid)
    _status(c, vid, "PROFILING")
    _profile(c, vid)
    _status(c, vid, "PROFILED", storage_object_key=key.replace("quarantine/", "datasets/", 1))
    return vid


@pytest.fixture
def ws(pg_stack: SimpleNamespace) -> SimpleNamespace:
    m = pg_stack.seed_member("owner")
    return SimpleNamespace(tenant=m.tenant_id, user=m.user_id)


# --- migration: populated 0024 upgrade, up/down/up ---------------------------------


def _alembic(pg: SimpleNamespace) -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", pg.owner_sa)
    return cfg


def _posture(pg: SimpleNamespace) -> dict[str, Any]:
    with _owner(pg) as c:

        def one(sql: str) -> Any:
            row = c.execute(sql).fetchone()
            assert row is not None
            return row[0]

        return {
            "revision": one("SELECT version_num FROM alembic_version"),
            "policies": one("SELECT count(*) FROM pg_policies WHERE schemaname='public'"),
            "tables": one(
                "SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND "
                "relname IN ('dataset_profiles','dataset_semantic_revisions')"
            ),
            "column": one(
                "SELECT count(*) FROM information_schema.columns WHERE table_name="
                "'dataset_versions' AND column_name='upload_idempotency_key'"
            ),
            "guard_has_ingest_rules": one(
                "SELECT prosrc LIKE '%dataset_profiles%' FROM pg_proc "
                "WHERE proname='dataset_version_guard'"
            ),
        }


@pytest.fixture
def at_0024(pg_stack: SimpleNamespace) -> Iterator[Config]:
    cfg = _alembic(pg_stack)
    command.downgrade(cfg, "0024_dataset_lifecycle")
    try:
        yield cfg
    finally:
        command.upgrade(cfg, "head")


def test_populated_0024_upgrades_without_rewriting_anything(
    pg_stack: SimpleNamespace, at_0024: Config
) -> None:
    m = pg_stack.seed_member("owner")
    with _owner(pg_stack) as c:
        did = _dataset(c, m.tenant_id, m.user_id)
        with c.transaction():
            c.execute("UPDATE datasets SET last_version_number = 1 WHERE id = %s", (did,))
            vid = uuid.uuid4()
            c.execute(
                "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, status, "
                "original_filename, media_type, declared_size_bytes, created_by) VALUES "
                "(%s, %s, %s, 1, 'QUARANTINED', 'old.csv', 'text/csv', 5, %s)",
                (vid, m.tenant_id, did, m.user_id),
            )
        c.execute(
            "INSERT INTO dataset_events (id, tenant_id, dataset_id, event_type, to_status, "
            "actor_kind, actor_user_id) VALUES (%s, %s, %s, 'DATASET_CREATED', 'ACTIVE', "
            "'user', %s)",
            (uuid.uuid4(), m.tenant_id, did, m.user_id),
        )

    def snapshot() -> tuple[Any, ...]:
        with _owner(pg_stack) as c:
            row = c.execute(
                "SELECT (SELECT md5(string_agg(d::text, ',' ORDER BY d.id)) FROM datasets d), "
                "(SELECT md5(string_agg(concat_ws('|', v.id, v.status, v.original_filename, "
                "v.updated_at), ',' ORDER BY v.id)) FROM dataset_versions v), "
                "(SELECT md5(string_agg(concat_ws('|', e.id, e.tenant_id, e.dataset_id, "
                "e.version_id, e.event_type, e.from_status, e.to_status, e.actor_kind, "
                "e.actor_user_id, e.reason_code, e.created_at), ',' ORDER BY e.id)) "
                "FROM dataset_events e)"
            ).fetchone()
        assert row is not None
        return tuple(row)

    before = snapshot()
    assert _posture(pg_stack)["policies"] == 61
    command.upgrade(at_0024, "head")
    assert snapshot() == before
    after = _posture(pg_stack)
    # Upgraded to head: 0025 and the ingest boundary 0026 (ADR-031), still
    # rewriting nothing.
    assert after == {
        "revision": "0026_dataset_ingest_role",
        "policies": 74,
        "tables": 2,
        "column": 1,
        "guard_has_ingest_rules": True,
    }
    with _owner(pg_stack) as c:
        assert c.execute(
            "SELECT upload_idempotency_key FROM dataset_versions WHERE id = %s", (vid,)
        ).fetchone() == (None,)
        for table in ("dataset_profiles", "dataset_semantic_revisions"):
            assert c.execute(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s::regclass",
                (table,),
            ).fetchone() == (True, True)
            assert c.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)  # noqa: S608


def test_0025_goes_down_and_up_with_the_documented_down_state(
    pg_stack: SimpleNamespace,
) -> None:
    cfg = _alembic(pg_stack)
    head = _posture(pg_stack)
    command.downgrade(cfg, "0024_dataset_lifecycle")
    down = _posture(pg_stack)
    assert down == {
        "revision": "0024_dataset_lifecycle",
        "policies": 61,
        "tables": 0,
        "column": 0,
        "guard_has_ingest_rules": False,
    }
    command.upgrade(cfg, "head")
    assert _posture(pg_stack) == head


# --- grants -----------------------------------------------------------------------------


# Since 0026 (ADR-031) the API reads profiles but only the ingest runtime records
# them; semantic confirmation stays the admin's and the ingest role has none of it.
_EXPECTED_GRANTS = {
    "dataset_profiles": {"nlw_app": {"SELECT"}, "nlw_ingest": {"SELECT", "INSERT"}},
    "dataset_semantic_revisions": {"nlw_app": {"SELECT", "INSERT"}, "nlw_ingest": set()},
}


@pytest.mark.parametrize("table", ["dataset_profiles", "dataset_semantic_revisions"])
def test_grants_are_minimal_for_every_role(pg_stack: SimpleNamespace, table: str) -> None:
    with _owner(pg_stack) as c:

        def can(role: str, priv: str) -> bool:
            row = c.execute(
                "SELECT has_table_privilege(%s, %s, %s)", (role, table, priv)
            ).fetchone()
            assert row is not None
            return bool(row[0])

        privs = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
        for role, want in _EXPECTED_GRANTS[table].items():
            assert {p for p in privs if can(role, p)} == want, role
        for role in ("nlw_worker", "nlw_scheduler"):
            for priv in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                assert not can(role, priv), (role, priv)
        public = c.execute(
            "SELECT count(*) FROM information_schema.role_table_grants "
            "WHERE table_name = %s AND grantee = 'PUBLIC'",
            (table,),
        ).fetchone()
        assert public == (0,)
        assert c.execute(
            "SELECT count(*) FROM pg_policies "
            "WHERE tablename = %s AND NOT (roles <@ ARRAY['nlw_app', 'nlw_ingest']::name[])",
            (table,),
        ).fetchone() == (0,)


def test_the_worker_role_cannot_read_profiles_or_semantics(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.worker_libpq) as conn:
        for table in ("dataset_profiles", "dataset_semantic_revisions"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(f"SELECT count(*) FROM {table}")  # noqa: S608
            conn.rollback()


# --- profile and semantic-revision guards --------------------------------------------------


def test_a_profile_is_recorded_only_while_profiling_with_the_version_digest(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _dataset(c, ws.tenant, ws.user)
        vid = _version(c, ws.tenant, did, ws.user)
        _content(c, ws.tenant, did, vid)
        with pytest.raises(CHECK, match="PROFILING"):  # still QUARANTINED
            _profile(c, vid)
        _status(c, vid, "PROFILING")
        with pytest.raises(CHECK, match="digest"):
            _profile(c, vid, sha="c" * 64)
        _profile(c, vid)
        with pytest.raises(psycopg.errors.UniqueViolation):  # one profile per version
            _profile(c, vid)
        for assignment in ("row_count = 2", "content_sha256 = repeat('d', 64)",
                           "profile = '{\"x\": 1}'::jsonb"):  # fmt: skip
            with pytest.raises(CHECK, match="immutable"):
                c.execute(
                    f"UPDATE dataset_profiles SET {assignment} WHERE version_id = %s",  # noqa: S608
                    (vid,),
                )
        with pytest.raises(CHECK, match="never deleted"):
            c.execute("DELETE FROM dataset_profiles WHERE version_id = %s", (vid,))
        # The tombstone's scrub is the only change, and only once.
        c.execute("UPDATE dataset_profiles SET profile = NULL WHERE version_id = %s", (vid,))
        with pytest.raises(CHECK, match="immutable"):
            c.execute(
                "UPDATE dataset_profiles SET profile = %s::jsonb WHERE version_id = %s",
                (PROFILE, vid),
            )


def test_profiled_requires_the_profile_and_active_requires_semantics(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _dataset(c, ws.tenant, ws.user)
        vid = _version(c, ws.tenant, did, ws.user)
        key = _content(c, ws.tenant, did, vid)
        _status(c, vid, "PROFILING")
        with pytest.raises(CHECK, match="recorded profile"):
            _status(c, vid, "PROFILED")
        _profile(c, vid)
        _status(c, vid, "PROFILED", storage_object_key=key.replace("quarantine/", "datasets/", 1))
        with pytest.raises(CHECK, match="confirmed semantics"), c.transaction():
            _status(c, vid, "ACTIVE")
            c.execute("UPDATE datasets SET active_version_id = %s WHERE id = %s", (vid, did))
        _semantics(c, vid)
        with c.transaction():
            _status(c, vid, "ACTIVE")
            c.execute("UPDATE datasets SET active_version_id = %s WHERE id = %s", (vid, did))
        with pytest.raises(CHECK, match="PROFILED"):  # no revision after activation
            _semantics(c, vid, n=2)


def test_semantic_revisions_are_append_only_and_consecutive(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _dataset(c, ws.tenant, ws.user)
        vid = _version(c, ws.tenant, did, ws.user)
        with pytest.raises(CHECK, match="PROFILED"):
            _semantics(c, vid)
        vid = _profiled(c, ws.tenant, did, ws.user)
        _semantics(c, vid, 1)
        with pytest.raises(CHECK, match="consecutively"):
            _semantics(c, vid, 3)
        _semantics(c, vid, 2)
        with pytest.raises(CHECK, match="immutable"):
            c.execute(
                "UPDATE dataset_semantic_revisions SET confirmed_by = %s WHERE version_id = %s",
                (uuid.uuid4(), vid),
            )
        with pytest.raises(CHECK, match="never deleted"):
            c.execute("DELETE FROM dataset_semantic_revisions WHERE version_id = %s", (vid,))


# --- storage key, idempotency key ---------------------------------------------------------


def test_the_storage_key_moves_to_datasets_only_when_profiled(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _dataset(c, ws.tenant, ws.user)
        vid = _version(c, ws.tenant, did, ws.user)
        key = _content(c, ws.tenant, did, vid)
        published = key.replace("quarantine/", "datasets/", 1)
        with pytest.raises(CHECK, match="storage key"):  # not while QUARANTINED
            c.execute(
                "UPDATE dataset_versions SET storage_object_key = %s WHERE id = %s",
                (published, vid),
            )
        _status(c, vid, "PROFILING")
        _profile(c, vid)
        other = f"datasets/{ws.tenant}/{did}/{uuid.uuid4()}"
        with pytest.raises(CHECK, match="storage key"):  # a different object name
            _status(c, vid, "PROFILED", storage_object_key=other)
        with pytest.raises(CHECK, match="storage key"):  # a move without the transition
            c.execute(
                "UPDATE dataset_versions SET storage_object_key = %s WHERE id = %s",
                (published, vid),
            )
        _status(c, vid, "PROFILED", storage_object_key=published)
        with pytest.raises(CHECK, match="storage key"):  # never moved again
            c.execute(
                "UPDATE dataset_versions SET storage_object_key = %s WHERE id = %s", (key, vid)
            )


def test_upload_idempotency_keys_are_unique_per_dataset_and_immutable(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    k = "retry-key-0123456789"
    with _owner(pg_stack) as c:
        d1, d2 = _dataset(c, ws.tenant, ws.user), _dataset(c, ws.tenant, ws.user)
        v1 = _version(c, ws.tenant, d1, ws.user, key=k)
        _version(c, ws.tenant, d2, ws.user, key=k)  # another dataset may reuse it
        with pytest.raises(psycopg.errors.UniqueViolation):
            _version(c, ws.tenant, d1, ws.user, key=k)
        with pytest.raises(CHECK, match="idempotency"):
            c.execute(
                "UPDATE dataset_versions SET upload_idempotency_key = 'another-key-0123456' "
                "WHERE id = %s",
                (v1,),
            )
        with pytest.raises(psycopg.errors.CheckViolation):
            _version(c, ws.tenant, d1, ws.user, key="short")


# --- RLS: roles, tenants, signed identity -------------------------------------------------


def test_profiles_and_semantics_are_admin_only_and_tenant_bound(
    pg_stack: SimpleNamespace,
) -> None:
    a = pg_stack.seed_member("owner")
    member = pg_stack.add_membership(a.tenant_id, "member")
    b = pg_stack.seed_member("owner")
    with _owner(pg_stack) as c:  # the B owner is also an owner of A (dual membership)
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,'owner')",
            (uuid.uuid4(), b.user_id, a.tenant_id),
        )
        did = _dataset(c, a.tenant_id, a.user_id)
        vid = _profiled(c, a.tenant_id, did, a.user_id)
        _semantics(c, vid)

    def visible(conn: psycopg.Connection[Any]) -> tuple[Any, ...]:
        row = conn.execute(
            "SELECT (SELECT count(*) FROM dataset_profiles), "
            "(SELECT count(*) FROM dataset_semantic_revisions)"
        ).fetchone()
        assert row is not None
        return tuple(row)

    with _app(pg_stack, a.user_id, a.tenant_id) as conn:
        assert visible(conn) == (1, 1)
    # Revision number 1 is what the trigger expects from a caller who sees no
    # revisions, so these attempts get past it and RLS is what refuses them.
    with _app(pg_stack, member, a.tenant_id) as conn:
        assert visible(conn) == (0, 0)  # members never see profiles or semantics
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "INSERT INTO dataset_semantic_revisions (id, tenant_id, dataset_id, version_id, "
                "revision_number, mapping, confirmed_by) VALUES (%s,%s,%s,%s,1,%s::jsonb,%s)",
                (uuid.uuid4(), a.tenant_id, did, vid, MAPPING, member),
            )
    with _app(pg_stack, b.user_id, b.tenant_id) as conn:
        assert visible(conn) == (0, 0)  # signed into B: A's rows are invisible
        # A's version is invisible from B, so the guard (which reads it under RLS)
        # or RLS itself refuses the write; either way nothing reaches A.
        with pytest.raises((psycopg.errors.InsufficientPrivilege, psycopg.errors.CheckViolation)):
            conn.execute(
                "INSERT INTO dataset_semantic_revisions (id, tenant_id, dataset_id, version_id, "
                "revision_number, mapping, confirmed_by) VALUES (%s,%s,%s,%s,1,%s::jsonb,%s)",
                (uuid.uuid4(), a.tenant_id, did, vid, MAPPING, b.user_id),
            )
    with _app(pg_stack, a.user_id, a.tenant_id) as conn:
        # The confirmer is bound to the SIGNED user: naming someone else is refused.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "INSERT INTO dataset_semantic_revisions (id, tenant_id, dataset_id, version_id, "
                "revision_number, mapping, confirmed_by) VALUES (%s,%s,%s,%s,2,%s::jsonb,%s)",
                (uuid.uuid4(), a.tenant_id, did, vid, MAPPING, b.user_id),
            )
        conn.rollback()
        pg_stack.apply_ctx(
            conn, pg_stack.sign(Purpose.API_REQUEST, user_id=a.user_id, tenant_id=a.tenant_id)
        )
        conn.execute(
            "INSERT INTO dataset_semantic_revisions (id, tenant_id, dataset_id, version_id, "
            "revision_number, mapping, confirmed_by) VALUES (%s,%s,%s,%s,2,%s::jsonb,%s)",
            (uuid.uuid4(), a.tenant_id, did, vid, MAPPING, a.user_id),
        )
        for sql in (
            "UPDATE dataset_profiles SET profile = NULL",
            "DELETE FROM dataset_semantic_revisions",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(sql)
            conn.rollback()
            pg_stack.apply_ctx(
                conn,
                pg_stack.sign(Purpose.API_REQUEST, user_id=a.user_id, tenant_id=a.tenant_id),
            )


def test_runtime_roles_can_never_write_purge_evidence(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _dataset(c, ws.tenant, ws.user)
        vid = _version(c, ws.tenant, did, ws.user)
        _status(c, vid, "DELETING")
        # Even the owner cannot record a purge with the wrong shape.
        for actor, frm, reason in (("user", "DELETING", "OPERATOR_PURGE"),
                                   ("operator", "QUARANTINED", "OPERATOR_PURGE"),
                                   ("operator", "DELETING", "USER_REQUEST")):  # fmt: skip
            with pytest.raises(psycopg.errors.CheckViolation):
                c.execute(
                    "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, "
                    "event_type, from_status, to_status, actor_kind, actor_user_id, reason_code) "
                    "VALUES (%s,%s,%s,%s,'VERSION_OBJECT_PURGED',%s,'DELETING',%s,%s,%s)",
                    (uuid.uuid4(), ws.tenant, did, vid, frm, actor,
                     ws.user if actor == "user" else None, reason),
                )  # fmt: skip
    with _app(pg_stack, ws.user, ws.tenant) as conn:
        for actor in ("service", "user"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(
                    "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, "
                    "event_type, from_status, to_status, actor_kind, actor_user_id, reason_code) "
                    "VALUES (%s,%s,%s,%s,'VERSION_OBJECT_PURGED','DELETING','DELETING',%s,%s,"
                    "'OPERATOR_PURGE')",
                    (uuid.uuid4(), ws.tenant, did, vid, actor, ws.user),
                )
            conn.rollback()
            pg_stack.apply_ctx(
                conn, pg_stack.sign(Purpose.API_REQUEST, user_id=ws.user, tenant_id=ws.tenant)
            )


def test_storage_keys_are_bound_to_the_version_id(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    """Neither a quarantine nor a published key may name another version's
    object, through any session (the owner bypasses RLS but not CHECKs)."""
    with _owner(pg_stack) as c:
        did = _dataset(c, ws.tenant, ws.user)
        v1 = _version(c, ws.tenant, did, ws.user)
        v2 = _version(c, ws.tenant, did, ws.user)
        for area in ("quarantine", "datasets"):
            with pytest.raises(psycopg.errors.CheckViolation, match="key_names_version"):
                c.execute(
                    "UPDATE dataset_versions SET content_sha256 = %s, storage_object_key = %s "
                    "WHERE id = %s",
                    (SHA, f"{area}/{ws.tenant}/{did}/{v2}", v1),
                )
            with pytest.raises(psycopg.errors.CheckViolation, match="key_names_version"):
                c.execute(
                    "UPDATE dataset_versions SET storage_object_key = %s WHERE id = %s",
                    (f"{area}/{ws.tenant}/{did}/not-the-version", v1),
                )
        # The real quarantine key is accepted; publishing it as another
        # version's object is refused, publishing its own is accepted.
        key = _content(c, ws.tenant, did, v1)
        _status(c, v1, "PROFILING")
        _profile(c, v1)
        with pytest.raises(psycopg.errors.CheckViolation):
            _status(c, v1, "PROFILED", storage_object_key=f"datasets/{ws.tenant}/{did}/{v2}")
        _status(c, v1, "PROFILED", storage_object_key=key.replace("quarantine/", "datasets/", 1))


def test_a_runtime_session_cannot_substitute_another_versions_key(
    pg_stack: SimpleNamespace,
) -> None:
    m = pg_stack.seed_member("owner")
    with _owner(pg_stack) as c:
        did = _dataset(c, m.tenant_id, m.user_id)
        v1 = _version(c, m.tenant_id, did, m.user_id)
        v2 = _version(c, m.tenant_id, did, m.user_id)
    with (
        _app(pg_stack, m.user_id, m.tenant_id) as conn,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        conn.execute(
            "UPDATE dataset_versions SET content_sha256 = %s, storage_object_key = %s "
            "WHERE id = %s",
            (SHA, f"quarantine/{m.tenant_id}/{did}/{v2}", v1),
        )


@pytest.mark.parametrize("ch", ["\u0085", "\u009f", "\x07"])
def test_the_database_refuses_c0_c1_in_filenames_and_names(
    pg_stack: SimpleNamespace, ws: SimpleNamespace, ch: str
) -> None:
    with _owner(pg_stack) as c:
        did = _dataset(c, ws.tenant, ws.user)
        with pytest.raises(psycopg.errors.CheckViolation), c.transaction():
            n = c.execute(
                "UPDATE datasets SET last_version_number = last_version_number + 1 "
                "WHERE id = %s RETURNING last_version_number",
                (did,),
            ).fetchone()
            assert n is not None
            c.execute(
                "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, status, "
                "original_filename, media_type, declared_size_bytes, created_by) VALUES "
                "(%s, %s, %s, %s, 'QUARANTINED', %s, 'text/csv', 10, %s)",
                (uuid.uuid4(), ws.tenant, did, n[0], f"a{ch}b.csv", ws.user),
            )
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute(
                "INSERT INTO datasets (id, tenant_id, name, normalized_name, status, created_by) "
                "VALUES (%s, %s, %s, %s, 'ACTIVE', %s)",
                (uuid.uuid4(), ws.tenant, f"x{ch}y", f"x{ch}y", ws.user),
            )


def test_leaving_profiling_requires_a_live_database_time_lease(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _dataset(c, ws.tenant, ws.user)
        vid = _version(c, ws.tenant, did, ws.user)
        key = _content(c, ws.tenant, did, vid)
        _status(c, vid, "PROFILING")  # takes a lease (helper)
        _profile(c, vid)
        c.execute(
            "UPDATE dataset_versions "
            "SET processing_lease_expires_at = now() - interval '1 second' WHERE id = %s",
            (vid,),
        )
        with pytest.raises(CHECK, match="live processing lease"):
            c.execute(
                "UPDATE dataset_versions SET status = 'PROFILED', storage_object_key = %s "
                "WHERE id = %s",
                (key.replace("quarantine/", "datasets/", 1), vid),
            )
        with pytest.raises(CHECK, match="live processing lease"):
            c.execute(
                "UPDATE dataset_versions SET status = 'REJECTED', rejection_code = 'PARSE_ERROR' "
                "WHERE id = %s",
                (vid,),
            )
        with pytest.raises(CHECK, match="15 minutes"):
            c.execute(
                "UPDATE dataset_versions "
                "SET processing_lease_expires_at = now() + interval '1 day' WHERE id = %s",
                (vid,),
            )
        c.execute(  # renewed by the database clock: now it may leave PROFILING
            "UPDATE dataset_versions "
            "SET processing_lease_expires_at = now() + interval '1 minute' WHERE id = %s",
            (vid,),
        )
        _status(c, vid, "PROFILED", storage_object_key=key.replace("quarantine/", "datasets/", 1))
        row = c.execute(
            "SELECT processing_lease_token, processing_lease_expires_at FROM dataset_versions "
            "WHERE id = %s",
            (vid,),
        ).fetchone()
    assert row == (None, None)  # cleared on leaving PROFILING


def test_a_lease_cannot_exist_outside_profiling(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _dataset(c, ws.tenant, ws.user)
        vid = _version(c, ws.tenant, did, ws.user)
        c.execute(
            "UPDATE dataset_versions SET processing_lease_token = gen_random_uuid(), "
            "processing_lease_expires_at = now() + interval '1 minute' WHERE id = %s",
            (vid,),
        )
        row = c.execute(
            "SELECT status, processing_lease_token FROM dataset_versions WHERE id = %s", (vid,)
        ).fetchone()
        with (
            pytest.raises(psycopg.errors.CheckViolation, match="lease_only_profiling"),
            c.transaction(),
        ):
            n = c.execute(
                "UPDATE datasets SET last_version_number = last_version_number + 1 "
                "WHERE id = %s RETURNING last_version_number",
                (did,),
            ).fetchone()
            assert n is not None
            c.execute(
                "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, "
                "status, original_filename, media_type, declared_size_bytes, created_by, "
                "processing_lease_token, processing_lease_expires_at) VALUES "
                "(%s, %s, %s, %s, 'QUARANTINED', 'x.csv', 'text/csv', 1, %s, "
                "gen_random_uuid(), now())",
                (uuid.uuid4(), ws.tenant, did, n[0], ws.user),
            )
        profiling = _version(c, ws.tenant, did, ws.user)
        _content(c, ws.tenant, did, profiling)
        _status(c, profiling, "PROFILING")
        with pytest.raises(psycopg.errors.CheckViolation, match="lease_pair"):  # half a lease
            c.execute(
                "UPDATE dataset_versions SET processing_lease_expires_at = NULL WHERE id = %s",
                (profiling,),
            )
    assert row == ("QUARANTINED", None)
