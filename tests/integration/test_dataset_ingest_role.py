"""The dataset ingest runtime boundary (ADR-031, owner decision O-1).

Real PostgreSQL, real roles, real signed contexts, the real isolated profiler.
``nlw_ingest`` may run exactly the processing path for ONE version (its signed
context) and nothing else; the API role may no longer run it at all.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import subprocess
import sys
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TypeVar

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from nlw.datasets import service as svc
from nlw.datasets.envelope import WorkEnvelope
from nlw.datasets.lifecycle import RejectionCode, VersionStatus
from nlw.datasets.processing_requests import record_processing_request
from nlw.datasets.service import Actor, DatasetConflict
from nlw.ingest.strict import StrictLimits
from nlw.ingest_service import processing
from nlw.storage.blob import LocalBlobStore, TenantScopedBlobStore
from nlw.tenancy.keys import signer_from_material
from nlw.tenancy.session import apply_signed_context
from nlw.tenancy.signing import (
    Purpose,
    SecretBytes,
    SignedContext,
    canonical_message,
    compute_mac,
)

pytestmark = pytest.mark.integration

T = TypeVar("T")
CSV = b"region,amount\n" + b"".join(f"r{i % 3},{i}\n".encode() for i in range(40))
BAD_CSV = b"a,a\n1,2\n"  # duplicate header names: a closed rejection code
CONFIG = processing.IngestionConfig(limits=StrictLimits(timeout_s=30), memory_mb=768)
DENIED = (psycopg.errors.InsufficientPrivilege, psycopg.errors.CheckViolation)
_SHA = "a" * 64


class Stack:
    """Two workspaces, the API role, the ingest role, a local store."""

    def __init__(self, pg: SimpleNamespace, root: Path) -> None:
        pg.enable_ingest()
        self.pg = pg
        a, b = pg.seed_member("owner"), pg.seed_member("owner")
        self.user, self.tenant = a.user_id, a.tenant_id
        self.user_b, self.tenant_b = b.user_id, b.tenant_id
        self.app = create_async_engine(pg.settings.database_url, pool_size=6)
        self.app_maker = async_sessionmaker(self.app, expire_on_commit=False)
        self.ing = create_async_engine(pg.ingest_sa, pool_size=6)
        self.ingest_maker = async_sessionmaker(self.ing, expire_on_commit=False)
        self.signer = pg.signers[Purpose.DATASET_INGEST]
        self.store = LocalBlobStore(root / "store")

    async def close(self) -> None:
        await self.app.dispose()
        await self.ing.dispose()

    async def api(
        self, fn: Callable[[AsyncSession], Awaitable[T]], *, tenant: uuid.UUID | None = None
    ) -> T:
        tenant = tenant or self.tenant
        user = self.user if tenant == self.tenant else self.user_b
        async with self.app_maker() as s, s.begin():
            await apply_signed_context(
                s, self.pg.sign(Purpose.API_REQUEST, user_id=user, tenant_id=tenant)
            )
            return await fn(s)

    async def as_ingest(
        self, tenant: uuid.UUID, version: uuid.UUID, fn: Callable[[AsyncSession], Awaitable[T]]
    ) -> T:
        async with self.ingest_maker() as s, s.begin():
            await apply_signed_context(
                s, self.pg.sign(Purpose.DATASET_INGEST, tenant_id=tenant, run_id=version)
            )
            return await fn(s)

    async def uploaded(
        self, data: bytes = CSV, *, tenant: uuid.UUID | None = None
    ) -> tuple[uuid.UUID, uuid.UUID]:
        """A dataset with one QUARANTINED version whose bytes are stored (what
        the upload route will do; the API role records the content)."""
        tenant = tenant or self.tenant
        user = self.user if tenant == self.tenant else self.user_b
        actor = Actor.user(user)
        d = (
            await self.api(
                lambda s: svc.create_dataset(
                    s, tenant, actor, name=f"d-{uuid.uuid4().hex[:8]}", description=None
                ),
                tenant=tenant,
            )
        ).id
        v = (
            await self.api(
                lambda s: svc.create_version(
                    s, tenant, actor, d, original_filename="a.csv", media_type="text/csv",
                    declared_size_bytes=len(data),
                ),
                tenant=tenant,
            )
        ).id  # fmt: skip
        scoped = TenantScopedBlobStore(self.store, tenant)
        key = scoped.version_key("quarantine", d, v)
        _, sha = scoped.put_stream(key, io.BytesIO(data), max_bytes=10**6)
        await self.api(
            lambda s: svc.record_content(
                s, tenant, d, v, content_sha256=sha, storage_object_key=key
            ),
            tenant=tenant,
        )
        return d, v

    async def request(
        self, d: uuid.UUID, v: uuid.UUID, *, tenant: uuid.UUID | None = None
    ) -> WorkEnvelope:
        tenant = tenant or self.tenant
        user = self.user if tenant == self.tenant else self.user_b
        return await self.api(
            lambda s: record_processing_request(s, tenant, user, d, v), tenant=tenant
        )

    async def process(
        self, message: str, config: processing.IngestionConfig = CONFIG
    ) -> processing.ProcessResult:
        return await processing.process_envelope(
            maker=self.ingest_maker,
            signer=self.signer,
            store=self.store,
            config=config,
            message=message,
        )

    def owner(self) -> psycopg.Connection[Any]:
        return psycopg.connect(self.pg.owner_libpq, autocommit=True)

    def ingest_conn(self, tenant: uuid.UUID, version: uuid.UUID) -> psycopg.Connection[Any]:
        conn: psycopg.Connection[Any] = self.pg.ctx_conn(
            self.pg.ingest_libpq, Purpose.DATASET_INGEST, tenant_id=tenant, run_id=version
        )
        return conn

    def app_conn(self) -> psycopg.Connection[Any]:
        conn: psycopg.Connection[Any] = self.pg.ctx_conn(
            self.pg.app_libpq, Purpose.API_REQUEST, user_id=self.user, tenant_id=self.tenant
        )
        return conn

    def version_row(self, v: uuid.UUID) -> tuple[Any, ...]:
        with self.owner() as c:
            row = c.execute(
                "SELECT status, processing_lease_token IS NOT NULL, storage_object_key, "
                "rejection_code FROM dataset_versions WHERE id = %s",
                (v,),
            ).fetchone()
        assert row is not None
        return tuple(row)

    def events(self, v: uuid.UUID) -> list[tuple[Any, ...]]:
        with self.owner() as c:
            return c.execute(
                "SELECT event_type, from_status, to_status, actor_kind, actor_user_id, "
                "reason_code FROM dataset_events WHERE version_id = %s ORDER BY created_at, "
                "event_type",
                (v,),
            ).fetchall()


@pytest.fixture
async def st(pg_stack: SimpleNamespace, tmp_path: Path) -> AsyncIterator[Stack]:
    stack = Stack(pg_stack, tmp_path)
    yield stack
    await stack.close()


# --- the allowed path ------------------------------------------------------------------


async def test_ingest_profiles_exactly_its_version_end_to_end(st: Stack) -> None:
    d, v = await st.uploaded()
    env = await st.request(d, v)
    assert env.recomputed_digest() == env.envelope_sha256  # DB and Python agree
    assert await st.process(env.to_json()) == "profiled"
    status, leased, key, code = st.version_row(v)
    assert (status, leased, key, code) == ("PROFILED", False, f"datasets/{st.tenant}/{d}/{v}", None)
    assert st.events(v)[1:] == [
        ("VERSION_PROFILING_STARTED", "QUARANTINED", "PROFILING", "service", None, None),
        ("VERSION_PROFILED", "PROFILING", "PROFILED", "service", None, None),
    ]
    scoped = TenantScopedBlobStore(st.store, st.tenant)
    assert scoped.exists(scoped.version_key("datasets", d, v))
    assert not scoped.exists(scoped.version_key("quarantine", d, v))
    profile = await st.api(lambda s: svc.get_profile(s, st.tenant, d, v))
    assert profile is not None


async def test_a_bad_file_is_rejected_with_a_closed_code_and_its_bytes_deleted(st: Stack) -> None:
    d, v = await st.uploaded(BAD_CSV)
    assert await st.process((await st.request(d, v)).to_json()) == "rejected"
    status, leased, _, code = st.version_row(v)
    assert (status, leased) == ("REJECTED", False) and code in RejectionCode.__members__
    assert st.events(v)[-1][:4] == ("VERSION_REJECTED", "PROFILING", "REJECTED", "service")
    assert TenantScopedBlobStore(st.store, st.tenant).list_version(d, v) == []


async def test_a_new_version_of_a_dataset_with_an_active_version_is_processed(st: Stack) -> None:
    """The ingest role sees only its own version; the deferred consistency check
    must still let it publish next to an ACTIVE sibling it cannot see."""
    d, v1 = await st.uploaded()
    assert await st.process((await st.request(d, v1)).to_json()) == "profiled"
    admin = Actor.user(st.user)
    mapping = {
        "contract_version": "semantics-1",
        "columns": [
            {"name": n, "label": n.title(), "semantic_type": t, "role": r,
             "analysis_allowed": True, "description": None}
            for n, t, r in (("region", "category", "dimension"), ("amount", "count", "measure"))
        ],
    }  # fmt: skip
    await st.api(
        lambda s: svc.confirm_semantics(
            s, st.tenant, admin, d, v1, mapping_json=json.dumps(mapping)
        )
    )
    await st.api(lambda s: svc.activate_version(s, st.tenant, admin, d, v1))
    actor = Actor.user(st.user)
    v2 = (
        await st.api(
            lambda s: svc.create_version(
                s, st.tenant, actor, d, original_filename="b.csv", media_type="text/csv",
                declared_size_bytes=len(CSV),
            )
        )
    ).id  # fmt: skip
    scoped = TenantScopedBlobStore(st.store, st.tenant)
    key = scoped.version_key("quarantine", d, v2)
    _, sha = scoped.put_stream(key, io.BytesIO(CSV), max_bytes=10**6)
    await st.api(
        lambda s: svc.record_content(
            s, st.tenant, d, v2, content_sha256=sha, storage_object_key=key
        )
    )
    assert await st.process((await st.request(d, v2)).to_json()) == "profiled"
    assert st.version_row(v1)[0] == "ACTIVE" and st.version_row(v2)[0] == "PROFILED"


async def test_duplicate_delivery_is_idempotent(st: Stack) -> None:
    d, v = await st.uploaded()
    message = (await st.request(d, v)).to_json()
    results = await asyncio.gather(*(st.process(message) for _ in range(3)))
    assert sorted(results) == ["profiled", "skipped", "skipped"]
    assert await st.process(message) == "skipped"  # a late redelivery too
    types = [e[0] for e in st.events(v)]
    assert types.count("VERSION_PROFILING_STARTED") == 1 and types.count("VERSION_PROFILED") == 1
    with st.owner() as c:
        assert c.execute(
            "SELECT count(*) FROM dataset_profiles WHERE version_id = %s", (v,)
        ).fetchone() == (1,)


# --- envelopes ---------------------------------------------------------------------------


async def test_tampered_forged_and_stale_envelopes_are_refused(st: Stack) -> None:
    d, v = await st.uploaded()
    env = await st.request(d, v)
    d2, v2 = await st.uploaded()  # stored, but nobody requested it
    _, vb = await st.uploaded(tenant=st.tenant_b)

    def forged(**changes: Any) -> str:
        e = replace(env, **changes)
        return replace(e, envelope_sha256=e.recomputed_digest()).to_json()

    tampered = json.loads(env.to_json())
    tampered["version_id"] = str(v2)  # digest not recomputed
    for message in (
        "not json",
        json.dumps(tampered),
        forged(version_id=v2, dataset_id=d2),  # a consistent digest, but no request row
        forged(tenant_id=st.tenant_b, version_id=vb),  # another workspace's version
        forged(content_sha256="0" * 64),  # does not match the request
        forged(requested_at_us=env.requested_at_us + 1),
        forged(request_id=uuid.uuid4()),
    ):
        assert await st.process(message) == "refused", message
    fresh_check = replace(CONFIG, max_envelope_age_s=1)
    await asyncio.sleep(2.2)
    assert await st.process(env.to_json(), fresh_check) == "refused"  # stale by DB time
    for version in (v, v2, vb):
        assert st.version_row(version)[:2] == ("QUARANTINED", False)
        assert [e[0] for e in st.events(version)] == ["VERSION_CREATED"]
    assert await st.process(env.to_json()) == "profiled"  # the genuine one still works


async def test_a_processing_request_is_immutable_and_admin_authored(st: Stack) -> None:
    d, v = await st.uploaded()
    env = await st.request(d, v)
    with st.owner() as c:
        for sql in (
            "UPDATE dataset_processing_requests SET content_sha256 = repeat('1', 64)",
            "DELETE FROM dataset_processing_requests",
        ):
            with pytest.raises(psycopg.errors.CheckViolation, match="immutable"):
                c.execute(sql)
    member = st.pg.add_membership(st.tenant, "member")
    other_admin = st.pg.add_membership(st.tenant, "admin")
    for user, by in ((member, member), (st.user, other_admin)):
        with (
            st.pg.ctx_conn(
                st.pg.app_libpq, Purpose.API_REQUEST, user_id=user, tenant_id=st.tenant
            ) as c,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            c.execute(
                "INSERT INTO dataset_processing_requests (id, tenant_id, dataset_id, version_id, "
                "content_sha256, requested_by, envelope_sha256) VALUES "
                "(%s, %s, %s, %s, %s, %s, repeat('0', 64))",
                (uuid.uuid4(), st.tenant, d, v, env.content_sha256, by),
            )
    with st.app_conn() as c, pytest.raises(psycopg.errors.CheckViolation, match="stored"):
        c.execute(  # the digest must be the version's
            "INSERT INTO dataset_processing_requests (id, tenant_id, dataset_id, version_id, "
            "content_sha256, requested_by, envelope_sha256) VALUES "
            "(%s, %s, %s, %s, %s, %s, repeat('0', 64))",
            (uuid.uuid4(), st.tenant, d, v, "f" * 64, st.user),
        )
    d3, v3 = await st.uploaded()
    with st.app_conn() as c:  # a caller-chosen time is replaced by the database's
        sha3 = c.execute("SELECT content_sha256 FROM dataset_versions WHERE id = %s", (v3,))
        c.execute(
            "INSERT INTO dataset_processing_requests (id, tenant_id, dataset_id, version_id, "
            "content_sha256, requested_by, requested_at, envelope_sha256) VALUES "
            "(%s, %s, %s, %s, %s, %s, '2001-01-01', repeat('0', 64))",
            (uuid.uuid4(), st.tenant, d3, v3, sha3.fetchone()[0], st.user),  # type: ignore[index]
        )
    with st.owner() as c:
        assert c.execute(
            "SELECT requested_at > now() - interval '1 minute', envelope_sha256 <> repeat('0', 64) "
            "FROM dataset_processing_requests WHERE version_id = %s",
            (v3,),
        ).fetchone() == (True, True)
    with st.owner() as c:  # the database, not the caller, computes the digest
        stored = c.execute(
            "SELECT envelope_sha256 FROM dataset_processing_requests WHERE id = %s",
            (env.request_id,),
        ).fetchone()
    assert stored == (env.envelope_sha256,) and env.envelope_sha256 != "0" * 64


# --- keys and identity -----------------------------------------------------------------


async def test_another_services_key_cannot_mint_an_ingest_context(st: Stack) -> None:
    d, v = await st.uploaded()
    pg = st.pg
    impostors = [
        signer_from_material(Purpose.DATASET_INGEST, pg.key_ids[c], pg.key_hex[c])
        for c in ("api", "worker", "scheduler")
    ]
    for signer in impostors:
        with psycopg.connect(pg.ingest_libpq, autocommit=False) as c:
            pg.apply_ctx(c, signer.sign(tenant_id=st.tenant, run_id=v))
            assert c.execute("SELECT (public.app_ctx_claims()).purpose").fetchone() == (None,)
            assert c.execute("SELECT count(*) FROM dataset_versions").fetchone() == (0,)
    # ... and the ingest key cannot mint any other runtime's context.
    for purpose, libpq, ids in (
        (Purpose.WORKER_EXECUTION, pg.worker_libpq, {"tenant_id": st.tenant, "run_id": v}),
        (Purpose.API_REQUEST, pg.app_libpq, {"user_id": st.user, "tenant_id": st.tenant}),
        (Purpose.SCHEDULER_RECONCILE, pg.scheduler_libpq, {}),
    ):
        signer = signer_from_material(purpose, pg.key_ids["ingest"], pg.key_hex["ingest"])
        with psycopg.connect(libpq, autocommit=False) as c:
            pg.apply_ctx(c, signer.sign(**ids))
            assert c.execute("SELECT (public.app_ctx_claims()).purpose").fetchone() == (None,)
    # ... nor can any other ROLE present an ingest context, even one correctly
    # MAC'd with the ingest key that names that role (the purpose<->role binding).
    for role, libpq in (
        ("nlw_app", pg.app_libpq),
        ("nlw_worker", pg.worker_libpq),
        ("nlw_scheduler", pg.scheduler_libpq),
    ):
        iat = int(time.time())
        fields: dict[str, Any] = {
            "key_id": pg.key_ids["ingest"], "db_role": role, "purpose": "dataset_ingest",
            "user_id": "", "tenant_id": str(st.tenant), "run_id": str(v),
            "issued_at": iat, "expires_at": iat + 60, "nonce": "ab" * 16,
        }  # fmt: skip
        key = SecretBytes(bytes.fromhex(pg.key_hex["ingest"]))
        forged = SignedContext(
            key_id=pg.key_ids["ingest"], db_role=role, purpose=Purpose.DATASET_INGEST,
            user_id=None, tenant_id=st.tenant, run_id=v, issued_at=iat, expires_at=iat + 60,
            nonce="ab" * 16, mac=compute_mac(key, canonical_message(**fields)),
        )  # fmt: skip
        with psycopg.connect(libpq, autocommit=False) as c:
            pg.apply_ctx(c, forged)
            assert c.execute("SELECT (public.app_ctx_claims()).purpose").fetchone() == (None,)
    # The ingest ROLE cannot present any other purpose, even with a valid key.
    for purpose, ids in (
        (Purpose.API_REQUEST, {"user_id": st.user, "tenant_id": st.tenant}),
        (Purpose.WORKER_EXECUTION, {"tenant_id": st.tenant, "run_id": v}),
    ):
        with psycopg.connect(pg.ingest_libpq, autocommit=False) as c:
            pg.apply_ctx(c, pg.sign(purpose, **ids))
            assert c.execute("SELECT (public.app_ctx_claims()).purpose").fetchone() == (None,)
            assert c.execute("SELECT count(*) FROM dataset_versions").fetchone() == (0,)


async def test_the_ingest_context_is_one_version_in_one_workspace(st: Stack) -> None:
    d, v = await st.uploaded()
    d2, v2 = await st.uploaded()  # same workspace, another version
    db, vb = await st.uploaded(tenant=st.tenant_b)  # another workspace
    with st.ingest_conn(st.tenant, v) as c:
        assert c.execute("SELECT id FROM dataset_versions").fetchall() == [(v,)]
        assert c.execute("SELECT id FROM datasets").fetchall() == [(d,)]
        for other in (v2, vb):  # known ids are not enough
            assert (
                c.execute(
                    "UPDATE dataset_versions SET processing_lease_token = gen_random_uuid() "
                    "WHERE id = %s RETURNING id",
                    (other,),
                ).fetchall()
                == []
            )
        c.rollback()
    # Claiming the other workspace with this version (or vice versa) sees nothing.
    for tenant, version in ((st.tenant_b, v), (st.tenant, vb)):
        with st.ingest_conn(tenant, version) as c:
            assert c.execute("SELECT count(*) FROM dataset_versions").fetchone() == (0,)
            assert c.execute("SELECT count(*) FROM datasets").fetchone() == (0,)
    # An event for another version (even a real one) is refused.
    # (the event guard cannot see that version, so it refuses before RLS does)
    with st.ingest_conn(st.tenant, v) as c, pytest.raises(DENIED):
        c.execute(
            "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
            "from_status, to_status, actor_kind) VALUES (%s, %s, %s, %s, "
            "'VERSION_PROFILING_STARTED', 'QUARANTINED', 'PROFILING', 'service')",
            (uuid.uuid4(), st.tenant, d2, v2),
        )
    for version in (v2, vb):
        assert st.version_row(version)[:2] == ("QUARANTINED", False)


async def test_the_ingest_role_cannot_bypass_rls(st: Stack) -> None:
    d, v = await st.uploaded()
    with st.owner() as c:
        row = c.execute(
            "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolinherit "
            "FROM pg_roles WHERE rolname = 'nlw_ingest'"
        ).fetchone()
        assert row == (False, False, False, False, False)
        assert c.execute(
            "SELECT count(*) FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.member "
            "WHERE r.rolname = 'nlw_ingest'"
        ).fetchone() == (0,)
    with psycopg.connect(st.pg.ingest_libpq, autocommit=False) as c:
        assert c.execute("SELECT count(*) FROM dataset_versions").fetchone() == (0,)  # no ctx
        c.execute("SET row_security = off")
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="row-level security"):
            c.execute("SELECT count(*) FROM dataset_versions")


# --- denied operations -------------------------------------------------------------------


async def test_the_ingest_role_cannot_do_anything_but_process(st: Stack) -> None:
    d, v = await st.uploaded()
    ins_dataset = (
        "INSERT INTO datasets (id, tenant_id, name, normalized_name, status, created_by) "
        "VALUES (gen_random_uuid(), %s, 'x', 'x', 'ACTIVE', %s)"
    )
    attempts: list[tuple[str, tuple[Any, ...]]] = [
        (ins_dataset, (st.tenant, st.user)),
        (
            "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, status, "
            "original_filename, media_type, declared_size_bytes, created_by) VALUES "
            "(gen_random_uuid(), %s, %s, 9, 'QUARANTINED', 'b.csv', 'text/csv', 1, %s)",
            (st.tenant, d, st.user),
        ),
        (
            "INSERT INTO dataset_processing_requests (id, tenant_id, dataset_id, version_id, "
            "content_sha256, requested_by, envelope_sha256) VALUES "
            "(gen_random_uuid(), %s, %s, %s, repeat('a', 64), %s, repeat('0', 64))",
            (st.tenant, d, v, st.user),
        ),
        (
            "INSERT INTO dataset_semantic_revisions (id, tenant_id, dataset_id, version_id, "
            "revision_number, mapping, confirmed_by) VALUES "
            "(gen_random_uuid(), %s, %s, %s, 1, '{}'::jsonb, %s)",
            (st.tenant, d, v, st.user),
        ),
        ("UPDATE datasets SET status = 'DELETING' WHERE id = %s", (d,)),
        ("UPDATE dataset_versions SET original_filename = 'evil.csv' WHERE id = %s", (v,)),
        ("UPDATE dataset_versions SET content_sha256 = repeat('b', 64) WHERE id = %s", (v,)),
        ("DELETE FROM dataset_versions WHERE id = %s", (v,)),
        ("DELETE FROM dataset_events WHERE version_id = %s", (v,)),
        ("DELETE FROM dataset_processing_requests WHERE version_id = %s", (v,)),
        ("TRUNCATE dataset_events", ()),
        ("SELECT count(*) FROM ctx_keys", ()),
        ("SELECT count(*) FROM workflow_runs", ()),
        ("SELECT count(*) FROM connectors", ()),
        ("SELECT count(*) FROM users", ()),
        ("SELECT count(*) FROM dataset_semantic_revisions", ()),
    ]
    for sql, args in attempts:
        with st.ingest_conn(st.tenant, v) as c, pytest.raises(DENIED):
            c.execute(sql, args)
    # Lifecycle moves outside the processing path: refused by policy or guard.
    for target, extra in (
        ("DELETING", ""),
        ("DELETED", ""),
        ("ACTIVE", ""),
        ("REJECTED", ", rejection_code = 'REVIEW_REJECTED'"),  # QUARANTINED -> REJECTED
    ):
        with (
            st.ingest_conn(st.tenant, v) as c,
            pytest.raises((*DENIED, psycopg.errors.RaiseException)),
        ):
            c.execute(
                f"UPDATE dataset_versions SET status = %s{extra} WHERE id = %s",  # noqa: S608
                (target, v),
            )
    # Events it may not write: purge evidence, operator, a user identity, any
    # non-processing type.
    for kind, user, etype, frm, to in (
        ("operator", None, "VERSION_OBJECT_PURGED", "DELETING", "DELETING"),
        ("service", st.user, "VERSION_PROFILING_STARTED", "QUARANTINED", "PROFILING"),
        ("user", st.user, "VERSION_PROFILING_STARTED", "QUARANTINED", "PROFILING"),
        ("service", None, "VERSION_ACTIVATED", "PROFILED", "ACTIVE"),
        ("service", None, "VERSION_DELETION_REQUESTED", "QUARANTINED", "DELETING"),
    ):
        with st.ingest_conn(st.tenant, v) as c, pytest.raises(DENIED):
            c.execute(
                "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
                "from_status, to_status, actor_kind, actor_user_id) VALUES "
                "(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (uuid.uuid4(), st.tenant, d, v, etype, frm, to, kind, user),
            )
    assert st.version_row(v)[:2] == ("QUARANTINED", False)
    assert [e[0] for e in st.events(v)] == ["VERSION_CREATED"]

    # A PROFILED version is out of its reach entirely (no activate, no supersede).
    await st.process((await st.request(d, v)).to_json())
    with st.ingest_conn(st.tenant, v) as c:
        assert (
            c.execute(
                "UPDATE dataset_versions SET status = 'ACTIVE' WHERE id = %s RETURNING id", (v,)
            ).fetchall()
            == []
        )


async def test_the_ingest_role_cannot_choose_a_storage_key(st: Stack) -> None:
    d, v = await st.uploaded()
    d2, v2 = await st.uploaded()
    token = uuid.uuid4()
    await st.as_ingest(
        st.tenant,
        v,
        lambda s: svc.acquire_processing_lease(
            s, st.tenant, processing.ACTOR, d, v, token=token, ttl_s=60
        ),
    )
    for key in (
        f"quarantine/{st.tenant}/{d2}/{v2}",
        f"datasets/{st.tenant}/{d2}/{v2}",
        f"datasets/{st.tenant_b}/{d}/{v}",
        "../../etc/passwd",
    ):
        with (
            st.ingest_conn(st.tenant, v) as c,
            pytest.raises((psycopg.errors.CheckViolation, psycopg.errors.RaiseException)),
        ):
            c.execute("UPDATE dataset_versions SET storage_object_key = %s WHERE id = %s", (key, v))


# --- the API role no longer processes ----------------------------------------------------


async def test_the_api_role_cannot_run_the_processing_path(st: Stack) -> None:
    d, v = await st.uploaded()
    admin = Actor.user(st.user)
    with pytest.raises(Exception) as caught:  # policy (WITH CHECK) or guard (42501)
        await st.api(
            lambda s: svc.acquire_processing_lease(
                s, st.tenant, admin, d, v, token=uuid.uuid4(), ttl_s=60
            )
        )
    assert "row-level security" in str(caught.value) or "reserved for the ingest" in str(
        caught.value
    )
    with st.app_conn() as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute(
            "INSERT INTO dataset_profiles (version_id, tenant_id, dataset_id, contract_version, "
            "content_sha256, row_count, column_count, profile) VALUES "
            "(%s, %s, %s, 'profile-2', repeat('a', 64), 1, 1, '{}'::jsonb)",
            (v, st.tenant, d),
        )
    # A version being processed: the API can neither renew nor settle the lease ...
    token = uuid.uuid4()
    await st.as_ingest(
        st.tenant,
        v,
        lambda s: svc.acquire_processing_lease(
            s, st.tenant, processing.ACTOR, d, v, token=token, ttl_s=60
        ),
    )
    for sql in (
        "UPDATE dataset_versions SET processing_lease_expires_at = now() + interval '1 minute' "
        "WHERE id = %s",
        "UPDATE dataset_versions SET status = 'REJECTED', rejection_code = 'REVIEW_REJECTED' "
        "WHERE id = %s",
        "UPDATE dataset_versions SET status = 'PROFILED', "
        "storage_object_key = 'datasets/' || substr(storage_object_key, 12) WHERE id = %s",
    ):
        with (
            st.app_conn() as c,
            pytest.raises((psycopg.errors.InsufficientPrivilege, psycopg.errors.RaiseException)),
        ):
            c.execute(sql, (v,))
    # ... but deletion still wins over processing, and review rejection of an
    # unprocessed version is still the admin's.
    await st.api(lambda s: svc.request_version_deletion(s, st.tenant, admin, d, v))
    assert st.version_row(v)[:2] == ("DELETING", False)
    d2, v2 = await st.uploaded()
    await st.api(
        lambda s: svc.transition_version(
            s, st.tenant, admin, d2, v2, to=VersionStatus.REJECTED,
            rejection_code=RejectionCode.REVIEW_REJECTED,
        )
    )  # fmt: skip
    assert st.version_row(v2)[0] == "REJECTED"


# --- events, leases ----------------------------------------------------------------------


async def test_every_ingest_transition_needs_exactly_one_authentic_event(st: Stack) -> None:
    d, v = await st.uploaded()
    claim = (
        "UPDATE dataset_versions SET status = 'PROFILING', processing_lease_token = "
        "gen_random_uuid(), processing_lease_expires_at = now() + interval '1 minute' "
        "WHERE id = %s"
    )
    event = (
        "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
        "from_status, to_status, actor_kind) VALUES (gen_random_uuid(), %s, %s, %s, "
        "'VERSION_PROFILING_STARTED', 'QUARANTINED', 'PROFILING', 'service')"
    )
    with st.ingest_conn(st.tenant, v) as c:  # no event: refused at commit
        c.execute(claim, (v,))
        with pytest.raises(psycopg.errors.CheckViolation, match="exactly one event"):
            c.commit()
    with st.ingest_conn(st.tenant, v) as c:  # a second event: refused
        c.execute(claim, (v,))
        c.execute(event, (st.tenant, d, v))
        with pytest.raises(psycopg.errors.CheckViolation, match="exactly one event"):
            c.execute(event, (st.tenant, d, v))
    with (
        st.ingest_conn(st.tenant, v) as c,  # an event without its transition: refused
        pytest.raises(psycopg.errors.CheckViolation, match="transition made in this"),
    ):
        c.execute(event, (st.tenant, d, v))
    assert st.version_row(v)[:2] == ("QUARANTINED", False)


async def test_a_lost_lease_rolls_back_publication(st: Stack) -> None:
    d, v = await st.uploaded()
    mine, theirs = uuid.uuid4(), uuid.uuid4()

    def lease(
        tok: uuid.UUID, ttl: float
    ) -> Callable[[AsyncSession], Awaitable[tuple[svc.LeaseClaim, svc.VersionRecord]]]:
        return lambda s: svc.acquire_processing_lease(
            s, st.tenant, processing.ACTOR, d, v, token=tok, ttl_s=ttl
        )

    assert (await st.as_ingest(st.tenant, v, lease(mine, 1)))[0] == "acquired"
    await asyncio.sleep(2.2)
    assert (await st.as_ingest(st.tenant, v, lease(theirs, 60)))[0] == "reclaimed"
    with pytest.raises(DatasetConflict, match="lease"):
        await st.as_ingest(
            st.tenant,
            v,
            lambda s: svc.publish_profile(
                s, st.tenant, processing.ACTOR, d, v,
                profile_json=json.dumps({"contract_version": "profile-2", "columns": []}),
                contract_version="profile-2",
                content_sha256=hashlib.sha256(CSV).hexdigest(),
                row_count=1, column_count=1,
                published_key=f"datasets/{st.tenant}/{d}/{v}",
                lease_token=mine,
            ),
        )  # fmt: skip
    with st.owner() as c:
        assert c.execute(
            "SELECT count(*) FROM dataset_profiles WHERE version_id = %s", (v,)
        ).fetchone() == (0,)
        assert c.execute(
            "SELECT status, processing_lease_token FROM dataset_versions WHERE id = %s", (v,)
        ).fetchone() == ("PROFILING", theirs)


# --- exact grants -------------------------------------------------------------------------

_INGEST_TABLE_PRIVS = {
    "datasets": {"SELECT"},
    "dataset_versions": {"SELECT"},
    "dataset_profiles": {"SELECT", "INSERT"},
    "dataset_events": {"SELECT", "INSERT"},
    "dataset_processing_requests": {"SELECT"},
}
_INGEST_COLUMN_PRIVS = {
    ("dataset_versions", "UPDATE", c)
    for c in (
        "status",
        "processing_lease_token",
        "processing_lease_expires_at",
        "storage_object_key",
        "rejection_code",
    )
} | {
    ("dr_restore_events", "SELECT", c)
    for c in ("id", "restored_at", "validation_completed_at", "runtime_enabled_at")
}
_DATASET_TABLES = (*_INGEST_TABLE_PRIVS, "dataset_semantic_revisions")


async def test_grants_are_exact_and_distinct_for_every_role(st: Stack) -> None:
    from nlw.ops.roles import EXPECTED_INGEST_GRANTS, INGEST_GRANTS_SQL

    with st.owner() as c:
        # The rollout gate's / restore validator's inventory IS the migration's.
        assert {r[0] for r in c.execute(INGEST_GRANTS_SQL).fetchall()} == EXPECTED_INGEST_GRANTS
        table_privs = c.execute(
            "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = 'nlw_ingest' AND table_schema = 'public'"
        ).fetchall()
        got: dict[str, set[str]] = {}
        for t, p in table_privs:
            got.setdefault(t, set()).add(p)
        assert got == _INGEST_TABLE_PRIVS
        cols = c.execute(
            "SELECT table_name, privilege_type, column_name "
            "FROM information_schema.column_privileges WHERE grantee = 'nlw_ingest' "
            "AND table_schema = 'public'"
        ).fetchall()
        # Column privileges implied by a table grant are listed too; the rest must
        # be exactly the processing columns and the recovery-lock columns.
        explicit = {(t, p, col) for t, p, col in cols if p not in _INGEST_TABLE_PRIVS.get(t, set())}
        assert explicit == _INGEST_COLUMN_PRIVS
        assert c.execute(
            "SELECT count(*) FROM information_schema.role_usage_grants "
            "WHERE grantee = 'nlw_ingest' AND object_type = 'SEQUENCE'"
        ).fetchone() == (0,)
        # Functions: exactly the verifier and the two ingest accessors.
        fns = c.execute(
            "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'public' AND has_function_privilege('nlw_ingest', p.oid, 'EXECUTE') "
            "AND NOT has_function_privilege('public', p.oid, 'EXECUTE')"
        ).fetchall()
        assert {f[0] for f in fns} == {
            "app_ctx_claims",
            "ctx_ingest_tenant_id",
            "ctx_ingest_version_id",
        }
        # The worker, scheduler and PUBLIC still have nothing on any dataset table.
        for role in ("nlw_worker", "nlw_scheduler", "public"):
            for table in _DATASET_TABLES:
                for priv in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                    row = c.execute(
                        "SELECT has_table_privilege(%s, %s, %s)", (role, table, priv)
                    ).fetchone()
                    assert row == (False,), (role, table, priv)
        # The API: requests SELECT/INSERT, profiles read-only, never DELETE.
        for table, want in (
            ("dataset_processing_requests", {"SELECT", "INSERT"}),
            ("dataset_profiles", {"SELECT"}),
        ):
            have = {
                p
                for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
                if c.execute("SELECT has_table_privilege('nlw_app', %s, %s)", (table, p)).fetchone()
                == (True,)
            }
            assert have == want, table
        # No SECURITY DEFINER function was added: the verifier is the only one
        # touched, still owned by the verifier role.
        secdef = c.execute(
            "SELECT p.proname, r.rolname FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'public' AND p.prosecdef AND p.proname LIKE '%ingest%'"
        ).fetchall()
        assert secdef == []
        rls = c.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid = 'dataset_processing_requests'::regclass"
        ).fetchone()
        assert rls == (True, True)
        owned = c.execute(
            "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner "
            "WHERE r.rolname = 'nlw_ingest'"
        ).fetchone()
        assert owned == (0,)


# --- migration -----------------------------------------------------------------------------


def _cfg(pg: SimpleNamespace) -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", pg.owner_sa)
    return cfg


def _shape(pg: SimpleNamespace) -> dict[str, Any]:
    with psycopg.connect(pg.owner_libpq, autocommit=True) as c:

        def one(query: str) -> Any:
            row = c.execute(query).fetchone()
            assert row is not None
            return row[0]

        return {
            "revision": one("SELECT version_num FROM alembic_version"),
            "policies": one("SELECT count(*) FROM pg_policies"),
            "requests": one(
                "SELECT count(*) FROM pg_class WHERE relname = 'dataset_processing_requests'"
            ),
            "verifier": one("SELECT pg_get_functiondef('app_ctx_claims()'::regprocedure)"),
            "guard": one("SELECT pg_get_functiondef('dataset_version_guard()'::regprocedure)"),
            "required": one("SELECT pg_get_functiondef('dataset_event_required()'::regprocedure)"),
            "consistency": one(
                "SELECT pg_get_functiondef('dataset_consistency_check()'::regprocedure)"
            ),
            "ingest_grants": one(
                "SELECT count(*) FROM information_schema.role_table_grants "
                "WHERE grantee = 'nlw_ingest'"
            ),
        }


def test_0026_refuses_a_downgrade_with_an_ingest_key_and_goes_down_and_up_otherwise(
    pg_stack: SimpleNamespace,
) -> None:
    cfg = _cfg(pg_stack)
    command.downgrade(cfg, "0025_dataset_ingestion")
    down_0025 = _shape(pg_stack)
    command.upgrade(cfg, "head")
    head = _shape(pg_stack)
    assert head["revision"] == "0026_dataset_ingest_role" and head["policies"] == 74
    assert down_0025["revision"] == "0025_dataset_ingestion"
    assert (down_0025["policies"], down_0025["requests"], down_0025["ingest_grants"]) == (65, 0, 0)
    for fn in ("verifier", "guard", "required", "consistency"):
        assert down_0025[fn] != head[fn], fn
    assert "dataset_ingest" not in down_0025["verifier"]
    pg_stack.enable_ingest()
    with pytest.raises(Exception, match="ingest keys are registered"):
        command.downgrade(cfg, "0025_dataset_ingestion")
    assert _shape(pg_stack) == head  # the refused downgrade changed nothing
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("DELETE FROM ctx_keys WHERE key_class = 'ingest'")
    command.downgrade(cfg, "0025_dataset_ingestion")
    assert _shape(pg_stack) == down_0025  # exactly the 0025 functions and policies
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:  # no residue
        residue = c.execute(
            "SELECT 'rel' FROM pg_class c, aclexplode(c.relacl) a JOIN pg_roles r "
            "ON r.oid = a.grantee WHERE r.rolname = 'nlw_ingest' "
            "UNION ALL SELECT 'col' FROM pg_attribute t, aclexplode(t.attacl) a JOIN pg_roles r "
            "ON r.oid = a.grantee WHERE r.rolname = 'nlw_ingest' "
            "UNION ALL SELECT 'fn' FROM pg_proc p, aclexplode(p.proacl) a JOIN pg_roles r "
            "ON r.oid = a.grantee WHERE r.rolname = 'nlw_ingest' "
            "UNION ALL SELECT 'nsp' FROM pg_namespace n, aclexplode(n.nspacl) a JOIN pg_roles r "
            "ON r.oid = a.grantee WHERE r.rolname = 'nlw_ingest' "
            "UNION ALL SELECT 'db' FROM pg_database d, aclexplode(d.datacl) a JOIN pg_roles r "
            "ON r.oid = a.grantee WHERE r.rolname = 'nlw_ingest' "
            "AND d.datname = current_database() "
            "UNION ALL SELECT 'pol' FROM pg_policies WHERE 'nlw_ingest' = ANY(roles)"
        ).fetchall()
        assert residue == []
    command.upgrade(cfg, "head")
    assert _shape(pg_stack) == head


async def test_the_ingest_role_cannot_attribute_its_own_transition_to_a_human(st: Stack) -> None:
    """Isolates the event policy: the transition is real (so the event guard
    accepts the event's shape), only the actor is forged."""
    d, v = await st.uploaded()
    claim = (
        "UPDATE dataset_versions SET status = 'PROFILING', processing_lease_token = "
        "gen_random_uuid(), processing_lease_expires_at = now() + interval '1 minute' "
        "WHERE id = %s"
    )
    event = (
        "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
        "from_status, to_status, actor_kind, actor_user_id) VALUES (gen_random_uuid(), "
        "%s, %s, %s, 'VERSION_PROFILING_STARTED', 'QUARANTINED', 'PROFILING', %s, %s)"
    )
    for kind, user in (("user", st.user), ("service", st.user)):
        with st.ingest_conn(st.tenant, v) as c:
            c.execute(claim, (v,))
            with pytest.raises(psycopg.errors.InsufficientPrivilege, match="row-level security"):
                c.execute(event, (st.tenant, d, v, kind, user))
    with st.ingest_conn(st.tenant, v) as c:  # the genuine attribution commits
        c.execute(claim, (v,))
        c.execute(event, (st.tenant, d, v, "service", None))
    assert st.events(v)[-1][:5] == (
        "VERSION_PROFILING_STARTED", "QUARANTINED", "PROFILING", "service", None,
    )  # fmt: skip


async def test_the_ingest_policies_admit_only_the_processing_states(st: Stack) -> None:
    """The policy layer on its own (the version guard is a second layer)."""
    import re

    with st.owner() as c:
        rows = c.execute(
            "SELECT policyname, cmd, coalesce(qual, ''), coalesce(with_check, '') "
            "FROM pg_policies WHERE 'nlw_ingest' = ANY(roles) ORDER BY policyname"
        ).fetchall()
    pol = {r[0]: r for r in rows}
    assert set(pol) == {
        "datasets_ingest_select",
        "dataset_versions_ingest_select",
        "dataset_versions_ingest_update",
        "dataset_profiles_ingest_select",
        "dataset_profiles_ingest_insert",
        "dataset_events_ingest_select",
        "dataset_events_ingest_insert",
        "dataset_processing_requests_ingest_select",
    }

    def states(expr: str) -> set[str]:
        return set(re.findall(r"'([A-Z_]+)'::text", expr))

    _, cmd, using, check = pol["dataset_versions_ingest_update"]
    assert cmd == "UPDATE"
    assert states(using) == {"QUARANTINED", "PROFILING"}
    assert states(check) == {"PROFILING", "PROFILED", "REJECTED"}
    _, _, _, ev = pol["dataset_events_ingest_insert"]
    assert states(ev) == {"VERSION_PROFILING_STARTED", "VERSION_PROFILED", "VERSION_REJECTED"}
    assert "actor_kind = 'service'::text" in ev and "actor_user_id IS NULL" in ev
    with st.owner() as c:  # the API's own version-update policy (the guard is layer 2)
        app_check = c.execute(
            "SELECT with_check FROM pg_policies WHERE policyname = 'dataset_versions_app_update'"
        ).fetchone()
    assert app_check is not None
    assert {"PROFILING", "PROFILED", "DELETED"} <= states(app_check[0])
    assert "NOT" in app_check[0] or "<>" in app_check[0]
    for name, (_, _, using, check) in pol.items():  # every one is bound to the context
        expr = using + check
        assert "ctx_ingest_tenant_id()" in expr and "ctx_ingest_version_id()" in expr, name


# --- independent review (effective privileges, escapes, keys, recovery, restore) -----

_INGEST_FUNCTIONS = {"app_ctx_claims", "ctx_ingest_tenant_id", "ctx_ingest_version_id"}


async def test_effective_privileges_match_the_exact_allowlist(st: Stack) -> None:
    """EFFECTIVE privileges (has_*_privilege, so PUBLIC and inheritance count),
    not only ACL text; missing and extra both fail."""
    with st.owner() as c:

        def rows(sql: str) -> list[tuple[Any, ...]]:
            return c.execute(sql).fetchall()

        tables = rows(
            "SELECT c.relname, string_agg(p, ',' ORDER BY p) FROM pg_class c "
            "CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE',"
            "'REFERENCES','TRIGGER']) p WHERE c.relnamespace = 'public'::regnamespace "
            "AND c.relkind IN ('r','v','m','p','f') "
            "AND has_table_privilege('nlw_ingest', c.oid, p) "
            "GROUP BY 1 ORDER BY 1"
        )
        assert dict(tables) == {
            "dataset_events": "INSERT,SELECT",
            "dataset_processing_requests": "SELECT",
            "dataset_profiles": "INSERT,SELECT",
            "dataset_versions": "SELECT",
            "datasets": "SELECT",
        }
        columns_only = rows(
            "SELECT c.relname, p, a.attname FROM pg_class c JOIN pg_attribute a "
            "ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped "
            "CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) p "
            "WHERE c.relnamespace = 'public'::regnamespace "
            "AND has_column_privilege('nlw_ingest', c.oid, a.attnum, p) "
            "AND NOT has_table_privilege('nlw_ingest', c.oid, p) ORDER BY 1, 2, 3"
        )
        assert {f"{t}:{p}:{a}" for t, p, a in columns_only} == {
            g for g in _EXPECTED_COLUMN_GRANTS()
        }
        # Functions: the documented three, plus pgcrypto's pure functions that
        # PUBLIC can execute (pre-existing, installed by 0016 for the verifier).
        fns = rows(
            "SELECT p.proname, p.prosecdef, EXISTS (SELECT 1 FROM pg_depend d JOIN "
            "pg_extension e ON e.oid = d.refobjid WHERE d.objid = p.oid AND d.deptype = 'e' "
            "AND e.extname = 'pgcrypto') FROM pg_proc p JOIN pg_namespace n "
            "ON n.oid = p.pronamespace WHERE n.nspname NOT IN ('pg_catalog', "
            "'information_schema') AND has_function_privilege('nlw_ingest', p.oid, 'EXECUTE')"
        )
        own = {name for name, _, ext in fns if not ext}
        assert own == _INGEST_FUNCTIONS
        assert [name for name, secdef, _ in fns if secdef] == ["app_ctx_claims"]
        assert (
            rows(
                "SELECT relname FROM pg_class WHERE relkind = 'S' AND ("
                "has_sequence_privilege('nlw_ingest', oid, 'USAGE') OR "
                "has_sequence_privilege('nlw_ingest', oid, 'UPDATE'))"
            )
            == []
        )
        assert (
            rows(
                "SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg\\_%' "
                "AND has_schema_privilege('nlw_ingest', oid, 'CREATE')"
            )
            == []
        )
        assert rows(
            "SELECT has_database_privilege('nlw_ingest', current_database(), 'CREATE')"
        ) == [(False,)]
        assert rows(
            "SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolreplication, "
            "rolbypassrls, rolconfig FROM pg_roles WHERE rolname = 'nlw_ingest'"
        ) == [(False, False, False, False, False, False, None)]
        assert (
            rows(
                "SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid IN (m.member, m.roleid) "
                "WHERE r.rolname = 'nlw_ingest'"
            )
            == []
        )
        owned = rows(
            "SELECT 'rel' FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner "
            "WHERE r.rolname = 'nlw_ingest' UNION ALL SELECT 'fn' FROM pg_proc p JOIN pg_roles r "
            "ON r.oid = p.proowner WHERE r.rolname = 'nlw_ingest' UNION ALL SELECT 'type' FROM "
            "pg_type t JOIN pg_roles r ON r.oid = t.typowner WHERE r.rolname = 'nlw_ingest' "
            "UNION ALL SELECT 'acl' FROM pg_default_acl d JOIN pg_roles r ON r.oid = d.defaclrole "
            "WHERE r.rolname = 'nlw_ingest'"
        )
        assert owned == []


def _EXPECTED_COLUMN_GRANTS() -> set[str]:  # noqa: N802 - mirrors the module constant
    from nlw.ops.roles import EXPECTED_INGEST_GRANTS

    return {g for g in EXPECTED_INGEST_GRANTS if g.count(":") == 2}


async def test_an_ingest_session_cannot_escape_its_boundary(st: Stack) -> None:
    d, v = await st.uploaded()
    d2, v2 = await st.uploaded()
    for sql in (
        "SET ROLE nlw_app",
        "SET ROLE nlw_ctx_verifier",
        "SET SESSION AUTHORIZATION nlw_app",
        "ALTER ROLE nlw_ingest BYPASSRLS",
        "ALTER ROLE nlw_ingest SET session_replication_role = replica",  # skip triggers
        "SET session_replication_role = replica",
    ):
        with st.ingest_conn(st.tenant, v) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(sql)
    # PostgreSQL lets every role change its OWN session defaults (all runtime roles
    # can). For ingest that can only fail closed: with row_security off, a query
    # that RLS would filter errors instead of bypassing.
    with psycopg.connect(st.pg.ingest_libpq, autocommit=True) as c:
        c.execute("ALTER ROLE nlw_ingest SET row_security = off")
    try:
        with (
            st.ingest_conn(st.tenant, v) as c,
            pytest.raises(psycopg.errors.InsufficientPrivilege, match="row-level security"),
        ):
            c.execute("SELECT id FROM dataset_versions")
    finally:
        with psycopg.connect(st.pg.ingest_libpq, autocommit=True) as c:
            c.execute("ALTER ROLE nlw_ingest RESET ALL")
    # A non-owner GRANT is a no-op (PostgreSQL warns, it does not grant).
    with psycopg.connect(st.pg.ingest_libpq, autocommit=True) as c:
        c.execute("GRANT DELETE ON dataset_versions TO nlw_ingest")  # warns, grants nothing
        with pytest.raises(psycopg.errors.InsufficientPrivilege):  # no privilege at all
            c.execute("GRANT SELECT ON dataset_semantic_revisions TO nlw_ingest")
    with st.owner() as c:
        assert c.execute(
            "SELECT has_table_privilege('nlw_ingest', 'dataset_versions', 'DELETE'), "
            "has_table_privilege('nlw_ingest', 'dataset_semantic_revisions', 'SELECT')"
        ).fetchone() == (False, False)
    with st.ingest_conn(st.tenant, v) as c:
        assert c.execute("SELECT id FROM dataset_versions").fetchall() == [(v,)]
        # Swapping the signed version/workspace/purpose mid-transaction voids the tag.
        for guc, value in (
            ("app.ctx_run", str(v2)),
            ("app.ctx_tenant", str(st.tenant_b)),
            ("app.ctx_purpose", "worker_execution"),
        ):
            c.execute("SAVEPOINT s")
            c.execute("SELECT set_config(%s, %s, true)", (guc, value))
            assert c.execute("SELECT (public.app_ctx_claims()).purpose").fetchone() == (None,)
            assert c.execute("SELECT count(*) FROM dataset_versions").fetchone() == (0,)
            c.execute("ROLLBACK TO SAVEPOINT s")
        # A shadowing function in pg_temp and a hostile search_path change nothing:
        # policies and guards call schema-qualified, fixed-search_path functions.
        c.execute(
            f"CREATE FUNCTION pg_temp.ctx_ingest_version_id() RETURNS uuid LANGUAGE sql "
            f"AS $$ SELECT '{v2}'::uuid $$"
        )
        c.execute("SET LOCAL search_path = pg_temp, public")
        assert c.execute("SELECT id FROM public.dataset_versions").fetchall() == [(v,)]
        assert (
            c.execute(
                "UPDATE public.dataset_versions SET processing_lease_token = gen_random_uuid() "
                "WHERE id = %s RETURNING id",
                (v2,),
            ).fetchall()
            == []
        )
        c.rollback()


async def test_ingest_contexts_do_not_leak_through_a_pooled_connection(st: Stack) -> None:
    from sqlalchemy import text

    d, v = await st.uploaded()
    engine = create_async_engine(st.pg.ingest_sa, pool_size=1, max_overflow=0)
    try:
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as s, s.begin():
            await apply_signed_context(
                s, st.pg.sign(Purpose.DATASET_INGEST, tenant_id=st.tenant, run_id=v)
            )
            assert (await s.execute(text("SELECT count(*) FROM dataset_versions"))).scalar() == 1
        async with maker() as s, s.begin():  # the SAME pooled connection, no context
            assert (await s.execute(text("SELECT count(*) FROM dataset_versions"))).scalar() == 0
            got = (await s.execute(text("SELECT current_setting('app.ctx_mac', true)"))).scalar()
            assert got in (None, "")
    finally:
        await engine.dispose()


async def test_revoked_retired_unactivated_and_unknown_ingest_keys_fail(st: Stack) -> None:
    from nlw.ctxkeys import install_key, revoke_key
    from nlw.tenancy.keys import signer_from_material
    from nlw.tenancy.signing import generate_test_key

    d, v = await st.uploaded()
    pg = st.pg

    def verifies(key_id: str, key_hex: str) -> bool:
        signer = signer_from_material(Purpose.DATASET_INGEST, key_id, key_hex)
        with psycopg.connect(pg.ingest_libpq, autocommit=False) as c:
            pg.apply_ctx(c, signer.sign(tenant_id=st.tenant, run_id=v))
            row = c.execute("SELECT (public.app_ctx_claims()).purpose").fetchone()
        return row == ("dataset_ingest",)

    assert verifies(pg.key_ids["ingest"], pg.key_hex["ingest"])
    assert not verifies("test-ingest-unknown", generate_test_key())  # unknown id
    assert not verifies(pg.key_ids["ingest"], generate_test_key())  # wrong material
    with st.owner() as c:
        future, rotated = generate_test_key(), generate_test_key()
        install_key(c, key_class="ingest", key_id="test-ingest-future",
                    secret=SecretBytes(bytes.fromhex(future)),
                    activate_at=datetime.now(UTC) + timedelta(hours=1), actor="review")  # fmt: skip
        install_key(c, key_class="ingest", key_id="test-ingest-rotated",
                    secret=SecretBytes(bytes.fromhex(rotated)), activate_at=None,
                    actor="review")  # fmt: skip
    assert not verifies("test-ingest-future", future)  # not yet active
    assert verifies("test-ingest-rotated", rotated) and verifies(
        pg.key_ids["ingest"], pg.key_hex["ingest"]
    )  # rotation overlap: both verify
    with st.owner() as c:
        revoke_key(c, key_id=pg.key_ids["ingest"], retire_at=None, actor="review")
        revoke_key(c, key_id="test-ingest-rotated",
                   retire_at=datetime.now(UTC) - timedelta(seconds=1), actor="review")  # fmt: skip
    assert not verifies(pg.key_ids["ingest"], pg.key_hex["ingest"])  # revoked
    assert not verifies("test-ingest-rotated", rotated)  # retired


async def test_the_ingest_role_cannot_forge_timestamps_or_retarget_requests(st: Stack) -> None:
    d, v = await st.uploaded()
    env = await st.request(d, v)
    d2, v2 = await st.uploaded()
    for sql, args in (
        ("UPDATE dataset_versions SET profiled_at = now() - interval '1 day' WHERE id = %s", (v,)),
        ("UPDATE dataset_versions SET created_at = now() WHERE id = %s", (v,)),
        ("UPDATE dataset_versions SET deletion_requested_at = now() WHERE id = %s", (v,)),
        ("UPDATE dataset_processing_requests SET version_id = %s", (v2,)),
        ("UPDATE dataset_processing_requests SET requested_at = now()", ()),
    ):
        with st.ingest_conn(st.tenant, v) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(sql, args)
    with st.ingest_conn(st.tenant, v) as c:  # a back-dated event is stamped now()
        c.execute(
            "UPDATE dataset_versions SET status = 'PROFILING', processing_lease_token = "
            "gen_random_uuid(), processing_lease_expires_at = now() + interval '1 minute' "
            "WHERE id = %s",
            (v,),
        )
        c.execute(
            "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
            "from_status, to_status, actor_kind, created_at) VALUES (gen_random_uuid(), %s, %s, "
            "%s, 'VERSION_PROFILING_STARTED', 'QUARANTINED', 'PROFILING', 'service', "
            "'2001-01-01')",
            (st.tenant, d, v),
        )
    with st.owner() as c:
        created = c.execute(
            "SELECT created_at > now() - interval '1 minute' FROM dataset_events "
            "WHERE version_id = %s AND event_type = 'VERSION_PROFILING_STARTED'",
            (v,),
        ).fetchone()
        assert created == (True,)
        assert c.execute(
            "SELECT version_id FROM dataset_processing_requests WHERE id = %s", (env.request_id,)
        ).fetchone() == (v,)


async def test_a_crashed_processor_is_reclaimed_and_completes_exactly_once(st: Stack) -> None:
    d, v = await st.uploaded()
    env = await st.request(d, v)
    crashed = uuid.uuid4()  # a processor that claimed the lease and then died
    await st.as_ingest(
        st.tenant,
        v,
        lambda s: svc.acquire_processing_lease(
            s, st.tenant, processing.ACTOR, d, v, token=crashed, ttl_s=1
        ),
    )
    assert await st.process(env.to_json()) == "skipped"  # its lease is still live
    await asyncio.sleep(2.2)
    assert await st.process(env.to_json()) == "profiled"  # reclaimed after expiry
    assert await st.process(env.to_json()) == "skipped"  # replay: no new transition
    types = [e[0] for e in st.events(v)]
    assert types == ["VERSION_CREATED", "VERSION_PROFILING_STARTED", "VERSION_PROFILED"]


async def test_a_replay_after_rejection_changes_nothing(st: Stack) -> None:
    d, v = await st.uploaded(BAD_CSV)
    message = (await st.request(d, v)).to_json()
    assert await st.process(message) == "rejected"
    before = st.events(v)
    assert await st.process(message) == "skipped"
    assert st.events(v) == before and st.version_row(v)[0] == "REJECTED"


# --- dataset_consistency_check (the ingest adaptation) --------------------------------


async def test_non_ingest_roles_keep_the_full_consistency_check(st: Stack) -> None:
    """The API (and the owner) still get the sibling checks: activating a version
    without moving the dataset pointer is refused at commit."""
    d, v = await st.uploaded()
    await st.process((await st.request(d, v)).to_json())
    admin = Actor.user(st.user)
    mapping = {"contract_version": "semantics-1", "columns": [
        {"name": n, "label": n.title(), "semantic_type": t, "role": r,
         "analysis_allowed": True, "description": None}
        for n, t, r in (("region", "category", "dimension"), ("amount", "count", "measure"))
    ]}  # fmt: skip
    await st.api(
        lambda s: svc.confirm_semantics(s, st.tenant, admin, d, v, mapping_json=json.dumps(mapping))
    )
    sql = (
        "UPDATE dataset_versions SET status = 'ACTIVE' WHERE id = %s",
        "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
        "from_status, to_status, actor_kind, actor_user_id) VALUES (gen_random_uuid(), %s, %s, "
        "%s, 'VERSION_ACTIVATED', 'PROFILED', 'ACTIVE', 'user', %s)",
    )
    with st.app_conn() as c:
        c.execute(sql[0], (v,))
        c.execute(sql[1], (st.tenant, d, v, st.user))
        with pytest.raises(psycopg.errors.CheckViolation, match="active_version_id"):
            c.commit()
    with psycopg.connect(st.pg.owner_libpq) as c:
        c.execute(sql[0], (v,))
        c.execute(sql[1], (st.tenant, d, v, st.user))
        with pytest.raises(psycopg.errors.CheckViolation, match="active_version_id"):
            c.commit()
    assert st.version_row(v)[0] == "PROFILED"


async def test_without_a_valid_ingest_context_the_role_reaches_no_row(st: Stack) -> None:
    """The ingest branch of the consistency check keys on the role; the role can
    only change a row under a valid context for that row (RLS)."""
    d, v = await st.uploaded()
    impostor = signer_from_material(Purpose.DATASET_INGEST, st.pg.key_ids["worker"],
                                    st.pg.key_hex["worker"])  # fmt: skip
    for apply in (
        None,  # no context at all
        impostor.sign(tenant_id=st.tenant, run_id=v),  # a context the database rejects
    ):
        with psycopg.connect(st.pg.ingest_libpq, autocommit=False) as c:
            if apply is not None:
                st.pg.apply_ctx(c, apply)
            assert (
                c.execute(
                    "UPDATE dataset_versions SET status = 'PROFILING' WHERE id = %s RETURNING id",
                    (v,),
                ).fetchall()
                == []
            )


# --- recovery lock ------------------------------------------------------------------------


async def test_processing_refuses_while_a_restore_is_not_enabled(st: Stack) -> None:
    from nlw.backup.recovery_lock import RecoveryLocked

    d, v = await st.uploaded()
    message = (await st.request(d, v)).to_json()
    restore = uuid.uuid4()
    with st.owner() as c:
        c.execute("INSERT INTO dr_restore_events (id, cutoff_at) VALUES (%s, now())", (restore,))
    with pytest.raises(RecoveryLocked):
        await st.process(message)
    assert st.version_row(v)[:2] == ("QUARANTINED", False)  # nothing claimed
    with st.ingest_conn(st.tenant, v) as c:  # the lock columns only, read-only
        assert c.execute(
            "SELECT count(*) FROM dr_restore_events WHERE runtime_enabled_at IS NULL"
        ).fetchone() == (1,)
        c.rollback()
    for sql in (
        "SELECT note FROM dr_restore_events",
        "SELECT cutoff_at FROM dr_restore_events",
        "UPDATE dr_restore_events SET runtime_enabled_at = now()",
        "DELETE FROM dr_restore_events",
        "INSERT INTO dr_restore_events (id, cutoff_at) VALUES (gen_random_uuid(), now())",
    ):
        with st.ingest_conn(st.tenant, v) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(sql)
    with st.owner() as c:
        c.execute(
            "UPDATE dr_restore_events SET validation_completed_at = now(), "
            "runtime_enabled_at = now() WHERE id = %s",
            (restore,),
        )
    assert await st.process(message) == "profiled"


async def test_work_in_flight_cannot_settle_against_an_unenabled_restore(st: Stack) -> None:
    from nlw.backup.recovery_lock import RecoveryLocked

    d, v = await st.uploaded()
    env = await st.request(d, v)
    token = uuid.uuid4()
    state, _ = await processing.in_ingest_context(
        st.ingest_maker,
        st.signer,
        env,
        lambda s: svc.acquire_processing_lease(
            s, st.tenant, processing.ACTOR, d, v, token=token, ttl_s=60
        ),
    )
    assert state == "acquired"
    with st.owner() as c:  # a restore lands while the profile is running
        c.execute(
            "INSERT INTO dr_restore_events (id, cutoff_at) VALUES (%s, now())", (uuid.uuid4(),)
        )
    for attempt in (
        lambda s: svc.renew_processing_lease(s, st.tenant, d, v, token=token, ttl_s=60),
        lambda s: svc.reject_processing(
            s, st.tenant, processing.ACTOR, d, v, token=token,
            rejection_code=RejectionCode.PROCESSING_FAILED,
        ),
    ):  # fmt: skip
        with pytest.raises(RecoveryLocked):
            await processing.in_ingest_context(st.ingest_maker, st.signer, env, attempt)
    assert st.version_row(v)[:2] == ("PROFILING", True)  # nothing settled


# --- restore validation and runtime boot ---------------------------------------------------


async def test_restore_validation_checks_the_exact_ingest_boundary(st: Stack) -> None:
    from sqlalchemy import create_engine

    from nlw.backup.validate import validate_restore

    engine = create_engine(st.pg.owner_sa.replace("+psycopg", "+psycopg"))
    try:
        checks = {c["name"]: c for c in validate_restore(engine)["checks"]}
        assert checks["ingest_grants_exact"]["ok"], checks["ingest_grants_exact"]
        with st.owner() as c:
            c.execute("GRANT DELETE ON dataset_versions TO nlw_ingest")
        checks = {c["name"]: c for c in validate_restore(engine)["checks"]}
        assert not checks["ingest_grants_exact"]["ok"]
        assert "extra dataset_versions:DELETE" in checks["ingest_grants_exact"]["detail"]
        with st.owner() as c:
            c.execute("REVOKE DELETE ON dataset_versions FROM nlw_ingest")
            c.execute("REVOKE INSERT ON dataset_events FROM nlw_ingest")
        checks = {c["name"]: c for c in validate_restore(engine)["checks"]}
        assert "missing dataset_events:INSERT" in checks["ingest_grants_exact"]["detail"]
    finally:
        engine.dispose()


def _boot(pg: SimpleNamespace, root: Path, **env: str) -> subprocess.CompletedProcess[str]:
    base = {
        "PATH": os.environ.get("PATH", ""),
        "APP_ENV": "local",
        "DATABASE_URL": pg.ingest_sa,
        "REDIS_URL": "redis://127.0.0.1:1/0",
        "NLW_CTX_KEY_ID": pg.key_ids["ingest"],
        "NLW_CTX_KEY_FILE": str(pg.key_files["ingest"]),
        "DATASET_STORAGE_BACKEND": "local",
        "DATASET_STORAGE_ROOT": str(root),
    }
    base.update(env)
    code = (
        "import nlw.ingest_service.actors as a\n"
        "from nlw.core.config import get_settings\n"
        "try:\n"
        "    a._boot_checks(get_settings()); print('BOOT_OK')\n"
        "except Exception as exc:\n"
        "    print('REFUSED', type(exc).__name__)\n"
    )
    return subprocess.run(
        [sys.executable, "-c", code], env=base, capture_output=True, text=True, timeout=120
    )


async def test_the_runtime_boots_only_with_its_own_role_key_and_store(
    st: Stack, tmp_path: Path
) -> None:
    pg = st.pg
    assert "BOOT_OK" in _boot(pg, tmp_path).stdout
    for env in (
        {"DATABASE_URL": pg.settings.database_url},  # the API's role
        {"DATABASE_URL": pg.worker_settings.database_url},  # the worker's role
        {"NLW_CTX_KEY_ID": pg.key_ids["worker"],
         "NLW_CTX_KEY_FILE": str(pg.key_files["worker"])},  # another service's key
        {"NLW_CTX_KEY_FILE": str(tmp_path / "missing.key")},  # no key
        {"DATASET_STORAGE_BACKEND": "disabled"},  # no store
    ):  # fmt: skip
        out = _boot(pg, tmp_path, **env)
        assert "REFUSED" in out.stdout and "BOOT_OK" not in out.stdout, (env, out.stdout)
