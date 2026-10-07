"""Dataset lifecycle (migration 0024, ADR-029): database-enforced invariants.

Constraints and triggers are exercised as the table OWNER (superuser in the test
harness, so RLS is bypassed and only the triggers/constraints stand in the way);
RLS and grants are exercised as the real runtime roles with signed contexts.
"""

import uuid
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest

from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

SHA = "a" * 64


# --- helpers (owner connection) ------------------------------------------------


def _owner(pg: SimpleNamespace) -> psycopg.Connection[Any]:
    return psycopg.connect(pg.owner_libpq, autocommit=True)


def _mk_dataset(
    conn: psycopg.Connection[Any], tenant: uuid.UUID, by: uuid.UUID, name: str = "Sales"
) -> uuid.UUID:
    did = uuid.uuid4()
    conn.execute(
        "INSERT INTO datasets (id, tenant_id, name, normalized_name, status, created_by) "
        "VALUES (%s, %s, %s, %s, 'ACTIVE', %s)",
        (did, tenant, name, name.casefold(), by),
    )
    return did


def _mk_version(
    conn: psycopg.Connection[Any], tenant: uuid.UUID, did: uuid.UUID, by: uuid.UUID
) -> uuid.UUID:
    with conn.transaction():
        n = conn.execute(
            "UPDATE datasets SET last_version_number = last_version_number + 1 "
            "WHERE id = %s RETURNING last_version_number",
            (did,),
        ).fetchone()
        assert n is not None
        vid = uuid.uuid4()
        conn.execute(
            "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, status, "
            "original_filename, media_type, declared_size_bytes, created_by) "
            "VALUES (%s, %s, %s, %s, 'QUARANTINED', 'sales.csv', 'text/csv', 100, %s)",
            (vid, tenant, did, n[0], by),
        )
    return vid


def _move(conn: psycopg.Connection[Any], vid: uuid.UUID, *states: str) -> None:
    """Move a version through ``states``. Since 0025 the database requires a
    content digest before profiling, a recorded profile for PROFILED and a
    confirmed semantic revision for ACTIVE, so those real rows are written on the
    way (synthetic values; no bytes exist at this layer)."""
    for s in states:
        if s == "PROFILING":
            conn.execute(
                "UPDATE dataset_versions SET content_sha256 = %s "
                "WHERE id = %s AND content_sha256 IS NULL",
                (SHA, vid),
            )
        if s == "PROFILED":
            conn.execute(
                "INSERT INTO dataset_profiles (version_id, tenant_id, dataset_id, "
                "contract_version, content_sha256, row_count, column_count, profile) "
                "SELECT id, tenant_id, dataset_id, 'profile-2', content_sha256, 1, 1, "
                "'{\"columns\": []}'::jsonb FROM dataset_versions WHERE id = %s",
                (vid,),
            )
        code = "'REVIEW_REJECTED'" if s == "REJECTED" else "rejection_code"
        # Entering PROFILING takes a (database-time) processing lease; leaving it
        # for PROFILED/REJECTED requires that lease to be live (0025).
        lease = (
            ", processing_lease_token = gen_random_uuid(), "
            "processing_lease_expires_at = now() + interval '5 minutes'"
            if s == "PROFILING"
            else ""
        )
        conn.execute(
            f"UPDATE dataset_versions SET status = %s, rejection_code = {code}{lease} "  # noqa: S608
            "WHERE id = %s",
            (s, vid),
        )
        if s == "PROFILED":
            _confirm(conn, vid)


def _confirm(conn: psycopg.Connection[Any], vid: uuid.UUID) -> None:
    conn.execute(
        "INSERT INTO dataset_semantic_revisions (id, tenant_id, dataset_id, version_id, "
        "revision_number, mapping, confirmed_by) SELECT %s, tenant_id, dataset_id, id, "
        "(SELECT coalesce(max(revision_number), 0) + 1 FROM dataset_semantic_revisions "
        "WHERE version_id = %s), '{\"columns\": []}'::jsonb, created_by "
        "FROM dataset_versions WHERE id = %s",
        (uuid.uuid4(), vid, vid),
    )


def _activate(conn: psycopg.Connection[Any], did: uuid.UUID, vid: uuid.UUID) -> None:
    with conn.transaction():
        conn.execute("UPDATE dataset_versions SET status = 'ACTIVE' WHERE id = %s", (vid,))
        conn.execute("UPDATE datasets SET active_version_id = %s WHERE id = %s", (vid, did))


@pytest.fixture
def ws(pg_stack: SimpleNamespace) -> SimpleNamespace:
    m = pg_stack.seed_member("owner")
    return SimpleNamespace(tenant=m.tenant_id, user=m.user_id)


def _raises_check(fn: Callable[[], object]) -> None:
    with pytest.raises((psycopg.errors.CheckViolation, psycopg.errors.CheckViolation)):
        fn()


# --- schema and constraints ------------------------------------------------------


def test_name_is_unique_per_tenant_case_insensitively_not_globally(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    other = pg_stack.seed_member("owner")
    with _owner(pg_stack) as c:
        _mk_dataset(c, ws.tenant, ws.user, "Sales")
        with pytest.raises(psycopg.errors.UniqueViolation):
            _mk_dataset(c, ws.tenant, ws.user, "SALES")
        _mk_dataset(c, other.tenant_id, other.user_id, "Sales")  # same name, other tenant


def test_version_numbers_are_unique_allocated_and_never_reused(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        v1 = _mk_version(c, ws.tenant, did, ws.user)
        _mk_version(c, ws.tenant, did, ws.user)
        # An arbitrary or reused number is refused: it must equal the allocated one.
        with pytest.raises(psycopg.errors.CheckViolation, match="allocated"):
            c.execute(
                "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, status, "
                "original_filename, media_type, declared_size_bytes, created_by) VALUES "
                "(%s, %s, %s, 1, 'QUARANTINED', 'x.csv', 'text/csv', 1, %s)",
                (uuid.uuid4(), ws.tenant, did, ws.user),
            )
        # Deleting v1 never frees its number for reuse.
        _move(c, v1, "DELETING")
        n = _mk_version(c, ws.tenant, did, ws.user)
        row = c.execute("SELECT version_number FROM dataset_versions WHERE id=%s", (n,)).fetchone()
        assert row == (3,)


def test_counter_only_moves_up_by_one_on_an_active_dataset(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        for bad in ("last_version_number + 2", "0 - 1", "5"):
            with pytest.raises(psycopg.errors.CheckViolation):
                c.execute(
                    f"UPDATE datasets SET last_version_number = {bad} WHERE id = %s",  # noqa: S608
                    (did,),
                )


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("status", "'ARCHIVED'"),
        ("media_type", "'application/vnd.ms-excel'"),
        ("declared_size_bytes", "0"),
        ("declared_size_bytes", "25000001"),
        ("declared_size_bytes", "-5"),
        ("content_sha256", "'XYZ'"),
        ("content_sha256", f"'{'A' * 64}'"),
        ("original_filename", "'../../etc/passwd'"),
        ("original_filename", "'dir\\\\x.csv'"),
        ("original_filename", "'..'"),
        ("original_filename", "E'a\\nb.csv'"),
        ("storage_object_key", "'https://bucket.example/x.csv'"),
        ("storage_object_key", "'quarantine/../../etc/passwd'"),
    ],
)
def test_out_of_contract_version_values_are_refused(
    pg_stack: SimpleNamespace, ws: SimpleNamespace, column: str, value: str
) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        with c.transaction():
            n = c.execute(
                "UPDATE datasets SET last_version_number = 1 WHERE id = %s "
                "RETURNING last_version_number",
                (did,),
            ).fetchone()
            assert n is not None
            cols = {
                "status": "'QUARANTINED'",
                "original_filename": "'sales.csv'",
                "media_type": "'text/csv'",
                "declared_size_bytes": "100",
                "content_sha256": "NULL",
                "storage_object_key": "NULL",
            }
            cols[column] = value
            with pytest.raises((psycopg.errors.CheckViolation, psycopg.errors.CheckViolation)):
                c.execute(
                    "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, "  # noqa: S608
                    f"created_by, {', '.join(cols)}) VALUES (%s, %s, %s, 1, %s, "
                    f"{', '.join(cols.values())})",
                    (uuid.uuid4(), ws.tenant, did, ws.user),
                )
            raise psycopg.Rollback


def test_storage_key_must_name_this_tenant_and_dataset(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    other = pg_stack.seed_member("owner")
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        vid = _mk_version(c, ws.tenant, did, ws.user)
        foreign = f"quarantine/{other.tenant_id}/{did}/{vid}"
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute(
                "UPDATE dataset_versions SET storage_object_key = %s WHERE id = %s", (foreign, vid)
            )
        mine = f"quarantine/{ws.tenant}/{did}/{vid}"
        c.execute("UPDATE dataset_versions SET storage_object_key = %s WHERE id = %s", (mine, vid))
        # ...and is then immutable (set once, only while QUARANTINED).
        _raises_check(
            lambda: c.execute(
                "UPDATE dataset_versions SET storage_object_key = %s WHERE id = %s",
                (f"datasets/{ws.tenant}/{did}/{vid}", vid),
            )
        )


def test_digest_is_set_once_while_quarantined(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        vid = _mk_version(c, ws.tenant, did, ws.user)
        c.execute("UPDATE dataset_versions SET content_sha256 = %s WHERE id = %s", (SHA, vid))
        _raises_check(
            lambda: c.execute(
                "UPDATE dataset_versions SET content_sha256 = %s WHERE id = %s", ("b" * 64, vid)
            )
        )
        v2 = _mk_version(c, ws.tenant, did, ws.user)
        # Straight to PROFILING with NO digest (not via _move, which records one).
        c.execute("UPDATE dataset_versions SET status = 'PROFILING' WHERE id = %s", (v2,))
        _raises_check(
            lambda: c.execute(
                "UPDATE dataset_versions SET content_sha256 = %s WHERE id = %s", (SHA, v2)
            )
        )


@pytest.mark.parametrize(
    "assignment",
    [
        "version_number = 99",
        "media_type = 'text/csv '",
        "declared_size_bytes = 7",
        "original_filename = 'renamed.csv'",
        "created_by = gen_random_uuid()",
        "created_at = now() - interval '1 day'",
        "dataset_id = gen_random_uuid()",
    ],
)
def test_version_identity_and_file_metadata_are_immutable(
    pg_stack: SimpleNamespace, ws: SimpleNamespace, assignment: str
) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        vid = _mk_version(c, ws.tenant, did, ws.user)
        with pytest.raises(psycopg.Error):
            c.execute(f"UPDATE dataset_versions SET {assignment} WHERE id = %s", (vid,))  # noqa: S608


@pytest.mark.parametrize(
    "assignment",
    [
        "name = 'Renamed', normalized_name = 'renamed'",
        "description = 'changed'",
        "created_by = gen_random_uuid()",
        "tenant_id = gen_random_uuid()",
    ],
)
def test_dataset_identity_and_metadata_are_immutable(
    pg_stack: SimpleNamespace, ws: SimpleNamespace, assignment: str
) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        with pytest.raises(psycopg.Error):
            c.execute(f"UPDATE datasets SET {assignment} WHERE id = %s", (did,))  # noqa: S608


def test_every_invalid_version_transition_is_refused_by_the_database(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    from nlw.datasets.lifecycle import VERSION_TRANSITIONS, VersionStatus

    paths = {
        "QUARANTINED": (),
        "PROFILING": ("PROFILING",),
        "PROFILED": ("PROFILING", "PROFILED"),
        "ACTIVE": None,  # via _activate
        "SUPERSEDED": None,
        "REJECTED": ("REJECTED",),
        "DELETING": ("DELETING",),
    }
    refused = 0
    with _owner(pg_stack) as c:
        for src, path in paths.items():
            for dst in VersionStatus:
                if dst.value == src or dst in VERSION_TRANSITIONS[VersionStatus(src)]:
                    continue
                did = _mk_dataset(c, ws.tenant, ws.user, f"t-{uuid.uuid4().hex[:8]}")
                vid = _mk_version(c, ws.tenant, did, ws.user)
                if src in ("ACTIVE", "SUPERSEDED"):
                    _move(c, vid, "PROFILING", "PROFILED")
                    _activate(c, did, vid)
                    if src == "SUPERSEDED":
                        v2 = _mk_version(c, ws.tenant, did, ws.user)
                        _move(c, v2, "PROFILING", "PROFILED")
                        with c.transaction():
                            _move(c, vid, "SUPERSEDED")
                            c.execute(
                                "UPDATE dataset_versions SET status = 'ACTIVE' WHERE id = %s",
                                (v2,),
                            )
                            c.execute(
                                "UPDATE datasets SET active_version_id = %s WHERE id = %s",
                                (v2, did),
                            )
                else:
                    _move(c, vid, *path)  # type: ignore[misc]
                with pytest.raises(psycopg.Error), c.transaction():
                    code = "'REVIEW_REJECTED'" if dst is VersionStatus.REJECTED else "NULL"
                    c.execute(
                        "UPDATE dataset_versions SET status = %s, "  # noqa: S608
                        f"rejection_code = COALESCE({code}, rejection_code) WHERE id = %s",
                        (dst.value, vid),
                    )
                    if dst is VersionStatus.ACTIVE:
                        c.execute(
                            "UPDATE datasets SET active_version_id = %s WHERE id = %s",
                            (vid, did),
                        )
                refused += 1
    assert refused >= 30


def test_deleted_is_terminal_even_for_the_table_owner(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        vid = _mk_version(c, ws.tenant, did, ws.user)
        with c.transaction():
            _move(c, vid, "DELETING")
            c.execute("UPDATE datasets SET status = 'DELETING' WHERE id = %s", (did,))
        with c.transaction():
            c.execute(
                "UPDATE dataset_versions SET status = 'DELETED', original_filename = NULL "
                "WHERE id = %s",
                (vid,),
            )
            c.execute(
                "UPDATE datasets SET status = 'DELETED', name = NULL, normalized_name = NULL "
                "WHERE id = %s",
                (did,),
            )
        for stmt in (
            "UPDATE datasets SET status = 'ACTIVE' WHERE id = %s",
            "UPDATE datasets SET status = 'DELETING' WHERE id = %s",
            "UPDATE datasets SET description = NULL WHERE id = %s",
        ):
            # The dedicated terminal-state guard refuses first (not merely a
            # row-shape CHECK), so removing it is detected on its own.
            with pytest.raises(psycopg.errors.CheckViolation, match="deleted dataset cannot"):
                c.execute(stmt, (did,))
        for stmt in (
            "UPDATE dataset_versions SET status = 'DELETING' WHERE id = %s",
            "UPDATE dataset_versions SET status = 'QUARANTINED' WHERE id = %s",
            "UPDATE dataset_versions SET original_filename = 'back.csv' WHERE id = %s",
            "UPDATE dataset_versions SET declared_size_bytes = 1234 WHERE id = %s",
        ):
            with pytest.raises(
                psycopg.errors.CheckViolation, match="deleted dataset version cannot"
            ):
                c.execute(stmt, (vid,))
        row = c.execute(
            "SELECT status, name, description FROM datasets WHERE id = %s", (did,)
        ).fetchone()
        assert row == ("DELETED", None, None)


def test_a_tombstone_must_be_scrubbed(pg_stack: SimpleNamespace, ws: SimpleNamespace) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        c.execute("UPDATE datasets SET status = 'DELETING' WHERE id = %s", (did,))
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute("UPDATE datasets SET status = 'DELETED' WHERE id = %s", (did,))


def test_versions_only_join_an_active_dataset_of_the_same_tenant(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    other = pg_stack.seed_member("owner")
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        # Tenant linkage cannot disagree: (dataset_id, tenant_id) is a composite FK.
        with (
            pytest.raises((psycopg.errors.ForeignKeyViolation, psycopg.errors.CheckViolation)),
            c.transaction(),
        ):
            c.execute("UPDATE datasets SET last_version_number = 1 WHERE id = %s", (did,))
            c.execute(
                "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, "
                "status, original_filename, media_type, declared_size_bytes, created_by) "
                "VALUES (%s, %s, %s, 1, 'QUARANTINED', 'x.csv', 'text/csv', 1, %s)",
                (uuid.uuid4(), other.tenant_id, did, ws.user),
            )
        # No version can be added once deletion has begun.
        c.execute("UPDATE datasets SET status = 'DELETING' WHERE id = %s", (did,))
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute(
                "UPDATE datasets SET last_version_number = last_version_number + 1 WHERE id = %s",
                (did,),
            )


def test_a_version_is_always_born_quarantined(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        with pytest.raises(psycopg.errors.CheckViolation, match="QUARANTINED"), c.transaction():
            c.execute("UPDATE datasets SET last_version_number = 1 WHERE id = %s", (did,))
            c.execute(
                "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, "
                "status, original_filename, media_type, declared_size_bytes, created_by) "
                "VALUES (%s, %s, %s, 1, 'ACTIVE', 'x.csv', 'text/csv', 1, %s)",
                (uuid.uuid4(), ws.tenant, did, ws.user),
            )


def test_at_most_one_active_version_and_the_pointer_must_agree(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        v1, v2 = (_mk_version(c, ws.tenant, did, ws.user) for _ in range(2))
        for v in (v1, v2):
            _move(c, v, "PROFILING", "PROFILED")
        _activate(c, did, v1)
        # A second ACTIVE version is refused immediately (partial unique index).
        with pytest.raises(psycopg.errors.UniqueViolation):
            c.execute("UPDATE dataset_versions SET status = 'ACTIVE' WHERE id = %s", (v2,))
        # An ACTIVE version without the pointer (or vice versa) fails at COMMIT.
        with (
            pytest.raises(psycopg.errors.CheckViolation, match="active_version_id"),
            c.transaction(),
        ):
            c.execute("UPDATE datasets SET active_version_id = NULL WHERE id = %s", (did,))
        with (
            pytest.raises(psycopg.errors.CheckViolation, match="active_version_id"),
            c.transaction(),
        ):
            _move(c, v1, "SUPERSEDED")  # pointer still names v1, now SUPERSEDED
        # A DELETING dataset cannot keep a live version.
        with (
            pytest.raises((psycopg.errors.CheckViolation, psycopg.errors.CheckViolation)),
            c.transaction(),
        ):
            c.execute(
                "UPDATE datasets SET status = 'DELETING', active_version_id = NULL WHERE id = %s",
                (did,),
            )


def test_events_reject_free_text_and_mismatched_scope(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        base = (
            "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
            "from_status, to_status, actor_kind, actor_user_id, reason_code) VALUES "
        )
        bad_rows = [
            ("DATASET_CREATED", None, "ACTIVE", "user", ws.user, "because I said so"),
            ("SOMETHING_ELSE", None, "ACTIVE", "user", ws.user, None),
            ("DATASET_CREATED", None, "ACTIVE", "user", None, None),  # user without id
            ("DATASET_CREATED", None, "ACTIVE", "operator", ws.user, None),
            ("VERSION_CREATED", None, "QUARANTINED", "user", ws.user, None),  # no version id
            ("DATASET_CREATED", None, "SHIPPED", "user", ws.user, None),
        ]
        for et, fs, ts, kind, actor, reason in bad_rows:
            with pytest.raises(psycopg.errors.CheckViolation):
                c.execute(
                    base + "(%s, %s, %s, NULL, %s, %s, %s, %s, %s, %s)",
                    (uuid.uuid4(), ws.tenant, did, et, fs, ts, kind, actor, reason),
                )
        # A well-formed event is accepted when it records a transition made in
        # its own transaction (0025 event authenticity).
        with c.transaction():
            fresh = _mk_dataset(c, ws.tenant, ws.user, "Fresh")
            c.execute(
                base + "(%s, %s, %s, NULL, 'DATASET_CREATED', NULL, 'ACTIVE', 'user', %s, NULL)",
                (uuid.uuid4(), ws.tenant, fresh, ws.user),
            )


def test_no_free_form_json_or_text_blob_columns(pg_stack: SimpleNamespace) -> None:
    with _owner(pg_stack) as c:
        rows = c.execute(
            "SELECT table_name, column_name, data_type FROM information_schema.columns "
            "WHERE table_name IN ('datasets','dataset_versions','dataset_events') "
            "AND data_type IN ('json','jsonb','bytea','ARRAY')"
        ).fetchall()
    assert rows == []


# --- RLS, grants and roles ----------------------------------------------------------


def _app(pg: SimpleNamespace, user: uuid.UUID, tenant: uuid.UUID) -> psycopg.Connection[Any]:
    conn = psycopg.connect(pg.app_libpq)
    pg.apply_ctx(conn, pg.sign(Purpose.API_REQUEST, user_id=user, tenant_id=tenant))
    return conn


def test_role_matrix_member_reads_admin_writes(pg_stack: SimpleNamespace) -> None:
    owner = pg_stack.seed_member("owner")
    member_id = pg_stack.add_membership(owner.tenant_id, "member")
    admin_id = pg_stack.add_membership(owner.tenant_id, "admin")
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, owner.tenant_id, owner.user_id)
        _mk_version(c, owner.tenant_id, did, owner.user_id)

    with _app(pg_stack, member_id, owner.tenant_id) as m:
        assert m.execute("SELECT count(*) FROM datasets").fetchone() == (1,)
        assert m.execute("SELECT count(*) FROM dataset_versions").fetchone() == (1,)
        assert m.execute("SELECT count(*) FROM dataset_events").fetchone() == (0,)  # admin-only
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            m.execute(
                "INSERT INTO datasets (id, tenant_id, name, normalized_name, status, created_by) "
                "VALUES (%s, %s, 'M', 'm', 'ACTIVE', %s)",
                (uuid.uuid4(), owner.tenant_id, member_id),
            )
    with _app(pg_stack, member_id, owner.tenant_id) as m:
        res = m.execute("UPDATE datasets SET status = 'DELETING' WHERE id = %s", (did,))
        assert res.rowcount == 0  # USING hides the row from a member's UPDATE
    with _app(pg_stack, admin_id, owner.tenant_id) as a:
        new_id = uuid.uuid4()
        a.execute(
            "INSERT INTO datasets (id, tenant_id, name, normalized_name, status, created_by) "
            "VALUES (%s, %s, 'A', 'a', 'ACTIVE', %s)",
            (new_id, owner.tenant_id, admin_id),
        )
        # A runtime-role transition must record its event (deferred check, 0025).
        a.execute(
            "INSERT INTO dataset_events (id, tenant_id, dataset_id, event_type, to_status, "
            "actor_kind, actor_user_id) VALUES (%s, %s, %s, 'DATASET_CREATED', 'ACTIVE', "
            "'user', %s)",
            (uuid.uuid4(), owner.tenant_id, new_id, admin_id),
        )
        a.commit()


def test_tenant_b_cannot_see_or_touch_tenant_a(pg_stack: SimpleNamespace) -> None:
    a = pg_stack.seed_member("owner")
    b = pg_stack.seed_member("owner")
    with _owner(pg_stack) as c:
        with c.transaction():  # an event records a transition made in its transaction
            did = _mk_dataset(c, a.tenant_id, a.user_id)
            c.execute(
                "INSERT INTO dataset_events (id, tenant_id, dataset_id, event_type, to_status, "
                "actor_kind, actor_user_id) VALUES (%s, %s, %s, 'DATASET_CREATED', 'ACTIVE', "
                "'user', %s)",
                (uuid.uuid4(), a.tenant_id, did, a.user_id),
            )
        vid = _mk_version(c, a.tenant_id, did, a.user_id)
    with _app(pg_stack, b.user_id, b.tenant_id) as conn:
        for sql, args in (
            ("SELECT count(*) FROM datasets WHERE id = %s", (did,)),
            ("SELECT count(*) FROM dataset_versions WHERE id = %s", (vid,)),
            ("SELECT count(*) FROM dataset_events WHERE dataset_id = %s", (did,)),
        ):
            assert conn.execute(sql, args).fetchone() == (0,)  # guessed ids fail closed
        assert (
            conn.execute("UPDATE datasets SET status = 'DELETING' WHERE id = %s", (did,)).rowcount
            == 0
        )
        assert (
            conn.execute(
                "UPDATE dataset_versions SET status = 'DELETING' WHERE id = %s", (vid,)
            ).rowcount
            == 0
        )
        # Writing rows that claim tenant A from tenant B's context is refused.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "INSERT INTO datasets (id, tenant_id, name, normalized_name, status, created_by) "
                "VALUES (%s, %s, 'X', 'x', 'ACTIVE', %s)",
                (uuid.uuid4(), a.tenant_id, b.user_id),
            )
    # A's member sees A's row: the absence above is RLS, not a missing row.
    with _app(pg_stack, a.user_id, a.tenant_id) as conn:
        assert conn.execute("SELECT count(*) FROM datasets WHERE id=%s", (did,)).fetchone() == (1,)


def test_policies_bind_to_the_signed_tenant_not_just_membership(
    pg_stack: SimpleNamespace,
) -> None:
    """One user who is owner of BOTH workspaces, signed into B, must not reach
    A's rows. Membership alone would allow it; only the policies' own
    ``tenant_id = ctx_tenant_id()`` binding refuses it (the service's tenant
    filter is a separate layer and is not involved here)."""
    a = pg_stack.seed_member("owner")
    b = pg_stack.seed_member("owner")
    with _owner(pg_stack) as c:
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,'owner')",
            (uuid.uuid4(), a.user_id, b.tenant_id),
        )
        with c.transaction():  # an event records a transition made in its transaction
            did = _mk_dataset(c, a.tenant_id, a.user_id)
            c.execute(
                "INSERT INTO dataset_events (id, tenant_id, dataset_id, event_type, to_status, "
                "actor_kind, actor_user_id) VALUES (%s, %s, %s, 'DATASET_CREATED', 'ACTIVE', "
                "'user', %s)",
                (uuid.uuid4(), a.tenant_id, did, a.user_id),
            )
        _mk_version(c, a.tenant_id, did, a.user_id)
        # Prime the counter so a forged version insert is otherwise well-formed.
        c.execute(
            "UPDATE datasets SET last_version_number = last_version_number + 1 WHERE id = %s",
            (did,),
        )
        next_n = c.execute(
            "SELECT last_version_number FROM datasets WHERE id = %s", (did,)
        ).fetchone()
        assert next_n is not None

    def counts(conn: psycopg.Connection[Any]) -> tuple[Any, ...]:
        row = conn.execute(
            "SELECT (SELECT count(*) FROM datasets WHERE tenant_id = %s), "
            "(SELECT count(*) FROM dataset_versions WHERE tenant_id = %s), "
            "(SELECT count(*) FROM dataset_events WHERE tenant_id = %s)",
            (a.tenant_id, a.tenant_id, a.tenant_id),
        ).fetchone()
        assert row is not None
        return tuple(row)

    with _app(pg_stack, a.user_id, a.tenant_id) as conn:
        assert counts(conn) == (1, 1, 1)  # the same user, signed into A, sees them

    forged = (
        (
            "INSERT INTO datasets (id, tenant_id, name, normalized_name, status, created_by) "
            "VALUES (%s, %s, 'Forged', 'forged', 'ACTIVE', %s)",
            (uuid.uuid4(), a.tenant_id, a.user_id),
        ),
        (
            "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, status, "
            "original_filename, media_type, declared_size_bytes, created_by) "
            "VALUES (%s, %s, %s, %s, 'QUARANTINED', 'f.csv', 'text/csv', 1, %s)",
            (uuid.uuid4(), a.tenant_id, did, next_n[0], a.user_id),
        ),
        (
            "INSERT INTO dataset_events (id, tenant_id, dataset_id, event_type, to_status, "
            "actor_kind, actor_user_id) VALUES (%s, %s, %s, 'DATASET_CREATED', 'ACTIVE', "
            "'user', %s)",
            (uuid.uuid4(), a.tenant_id, did, a.user_id),
        ),
    )
    with _app(pg_stack, a.user_id, b.tenant_id) as conn:
        assert counts(conn) == (0, 0, 0)
        for table in ("datasets", "dataset_versions"):
            res = conn.execute(
                f"UPDATE {table} SET updated_at = now() WHERE tenant_id = %s",  # noqa: S608
                (a.tenant_id,),
            )
            assert res.rowcount == 0, table
        for sql, args in forged:
            with pytest.raises(
                (psycopg.errors.InsufficientPrivilege, psycopg.errors.CheckViolation)
            ):
                conn.execute(sql, args)
            conn.rollback()
            pg_stack.apply_ctx(
                conn, pg_stack.sign(Purpose.API_REQUEST, user_id=a.user_id, tenant_id=b.tenant_id)
            )
    with _owner(pg_stack) as c:
        row = c.execute(
            "SELECT (SELECT count(*) FROM datasets WHERE tenant_id = %s), "
            "(SELECT count(*) FROM dataset_versions WHERE tenant_id = %s), "
            "(SELECT count(*) FROM dataset_events WHERE tenant_id = %s)",
            (a.tenant_id, a.tenant_id, a.tenant_id),
        ).fetchone()
    assert row == (1, 1, 1)  # nothing was forged into A


def test_runtime_app_role_can_never_write_or_touch_a_tombstone(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        c.execute("UPDATE datasets SET status = 'DELETING' WHERE id = %s", (did,))
    with (
        _app(pg_stack, ws.user, ws.tenant) as conn,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        conn.execute(
            "UPDATE datasets SET status = 'DELETED', name = NULL, normalized_name = NULL "
            "WHERE id = %s",
            (did,),
        )
    with _owner(pg_stack) as c:
        c.execute(
            "UPDATE datasets SET status = 'DELETED', name = NULL, normalized_name = NULL "
            "WHERE id = %s",
            (did,),
        )
    with _app(pg_stack, ws.user, ws.tenant) as conn:
        res = conn.execute("UPDATE datasets SET status = 'DELETING' WHERE id = %s", (did,))
        assert res.rowcount == 0  # the tombstone is invisible to UPDATE
        for table in ("datasets", "dataset_versions", "dataset_events"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(f"DELETE FROM {table}")  # noqa: S608
            conn.rollback()
            pg_stack.apply_ctx(
                conn, pg_stack.sign(Purpose.API_REQUEST, user_id=ws.user, tenant_id=ws.tenant)
            )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE dataset_events SET reason_code = NULL")


def test_runtime_app_role_cannot_forge_tombstone_or_operator_events(
    pg_stack: SimpleNamespace, ws: SimpleNamespace
) -> None:
    """The audit trail's tombstone/operator entries can only come from the
    operator path: an owner in the app role is refused."""
    with _owner(pg_stack) as c:
        did = _mk_dataset(c, ws.tenant, ws.user)
        c.execute("UPDATE datasets SET status = 'DELETING' WHERE id = %s", (did,))
    forged = (
        ("DATASET_TOMBSTONED", "DELETING", "DELETED", "operator", None, "OPERATOR_TOMBSTONE"),
        ("DATASET_TOMBSTONED", "DELETING", "DELETED", "user", ws.user, "OPERATOR_TOMBSTONE"),
        ("DATASET_DELETION_REQUESTED", "ACTIVE", "DELETING", "operator", None, "USER_REQUEST"),
    )
    with _app(pg_stack, ws.user, ws.tenant) as conn:
        for event_type, src, dst, kind, actor, reason in forged:
            # Since 0025 the event guard (no such transition in this transaction)
            # or RLS (operator rows, tombstones) refuses them; either way nothing
            # is recorded. RLS alone is proven in test_dataset_ingestion_db.
            with pytest.raises(
                (psycopg.errors.InsufficientPrivilege, psycopg.errors.CheckViolation)
            ):
                conn.execute(
                    "INSERT INTO dataset_events (id, tenant_id, dataset_id, event_type, "
                    "from_status, to_status, actor_kind, actor_user_id, reason_code) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (uuid.uuid4(), ws.tenant, did, event_type, src, dst, kind, actor, reason),
                )
            conn.rollback()
            pg_stack.apply_ctx(
                conn, pg_stack.sign(Purpose.API_REQUEST, user_id=ws.user, tenant_id=ws.tenant)
            )
    with _owner(pg_stack) as c:
        assert c.execute(
            "SELECT count(*) FROM dataset_events WHERE dataset_id = %s", (did,)
        ).fetchone() == (0,)


@pytest.mark.parametrize("role", ["nlw_worker", "nlw_scheduler", "public"])
def test_worker_scheduler_and_public_have_no_dataset_privileges(
    pg_stack: SimpleNamespace, role: str
) -> None:
    with _owner(pg_stack) as c:
        for table in ("datasets", "dataset_versions", "dataset_events"):
            granted = c.execute(
                "SELECT has_table_privilege(%s, %s, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')",
                (role, f"public.{table}"),
            ).fetchone()
            assert granted == (False,), (role, table)


def test_worker_role_is_refused_at_runtime(pg_stack: SimpleNamespace) -> None:
    with (
        psycopg.connect(pg_stack.worker_libpq) as conn,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        conn.execute("SELECT count(*) FROM datasets")


def test_rls_is_forced_and_no_security_definer_function_was_added(
    pg_stack: SimpleNamespace,
) -> None:
    with _owner(pg_stack) as c:
        rows = c.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE relname IN ('datasets','dataset_versions','dataset_events') ORDER BY relname"
        ).fetchall()
        assert rows == [
            ("dataset_events", True, True),
            ("dataset_versions", True, True),
            ("datasets", True, True),
        ]
        funcs = c.execute(
            "SELECT proname, prosecdef, proconfig FROM pg_proc WHERE proname IN "
            "('dataset_guard','dataset_version_guard','dataset_consistency_check') ORDER BY 1"
        ).fetchall()
        assert [(f[0], f[1]) for f in funcs] == [
            ("dataset_consistency_check", False),
            ("dataset_guard", False),
            ("dataset_version_guard", False),
        ]
        assert all(f[2] == ["search_path=pg_catalog"] for f in funcs)
        policies = c.execute(
            "SELECT tablename, policyname, roles::text, cmd FROM pg_policies "
            "WHERE tablename IN ('datasets','dataset_versions','dataset_events')"
        ).fetchall()
        assert len(policies) == 8
        assert {p[2] for p in policies} == {"{nlw_app}"}
        assert not [p for p in policies if p[3] == "DELETE"]
