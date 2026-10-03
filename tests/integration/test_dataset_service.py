"""Dataset lifecycle service (ADR-029) against real PostgreSQL as ``nlw_app``.

Each operation runs in its own transaction carrying a signed ``api_request``
context, exactly as the API does. Concurrency tests use separate connections so
the database (row locks, the partial unique index, the deferred consistency
trigger) is what keeps the invariants, not the test's own ordering.
"""

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from types import SimpleNamespace
from typing import Any, TypeVar

import psycopg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from nlw.datasets import service as svc
from nlw.datasets.lifecycle import RejectionCode, VersionStatus
from nlw.datasets.service import Actor, DatasetConflict, DatasetNotFound, DatasetVersionNotFound
from nlw.ops import datasets as ops_datasets
from nlw.tenancy.session import apply_signed_context
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

T = TypeVar("T")


class Harness:
    def __init__(self, pg: SimpleNamespace, user: uuid.UUID, tenant: uuid.UUID) -> None:
        self.pg, self.user, self.tenant = pg, user, tenant
        self.engine = create_async_engine(pg.settings.database_url, pool_size=10)
        self.maker = async_sessionmaker(self.engine, expire_on_commit=False)
        self.actor = Actor.user(user)

    async def run(
        self, fn: Callable[[AsyncSession], Awaitable[T]], *, user: uuid.UUID | None = None
    ) -> T:
        async with self.maker() as session, session.begin():
            ctx = self.pg.sign(
                Purpose.API_REQUEST, user_id=user or self.user, tenant_id=self.tenant
            )
            await apply_signed_context(session, ctx)
            return await fn(session)

    async def dataset(self, name: str = "Sales") -> svc.DatasetRecord:
        return await self.run(
            lambda s: svc.create_dataset(s, self.tenant, self.actor, name=name, description=None)
        )

    async def version(self, dataset_id: uuid.UUID) -> svc.VersionRecord:
        return await self.run(
            lambda s: svc.create_version(
                s,
                self.tenant,
                self.actor,
                dataset_id,
                original_filename="sales.csv",
                media_type="text/csv",
                declared_size_bytes=1234,
            )
        )

    async def to(
        self, dataset_id: uuid.UUID, version_id: uuid.UUID, *states: VersionStatus
    ) -> svc.VersionRecord:
        v: svc.VersionRecord | None = None
        for st in states:
            code = RejectionCode.REVIEW_REJECTED if st is VersionStatus.REJECTED else None

            async def step(
                s: AsyncSession, st: VersionStatus = st, code: RejectionCode | None = code
            ) -> svc.VersionRecord:
                return await svc.transition_version(
                    s, self.tenant, self.actor, dataset_id, version_id, to=st, rejection_code=code
                )

            v = await self.run(step)
        assert v is not None
        return v

    async def profiled(self, dataset_id: uuid.UUID) -> svc.VersionRecord:
        v = await self.version(dataset_id)
        return await self.to(dataset_id, v.id, VersionStatus.PROFILING, VersionStatus.PROFILED)

    async def activate(self, dataset_id: uuid.UUID, version_id: uuid.UUID) -> svc.VersionRecord:
        return await self.run(
            lambda s: svc.activate_version(s, self.tenant, self.actor, dataset_id, version_id)
        )


@pytest.fixture
async def h(pg_stack: SimpleNamespace) -> AsyncIterator[Harness]:
    m = pg_stack.seed_member("owner")
    harness = Harness(pg_stack, m.user_id, m.tenant_id)
    yield harness
    await harness.engine.dispose()


def _events(pg: SimpleNamespace, dataset_id: uuid.UUID) -> list[tuple[Any, ...]]:
    with psycopg.connect(pg.owner_libpq) as c:
        return c.execute(
            "SELECT event_type, version_id, from_status, to_status, actor_kind, reason_code "
            "FROM dataset_events WHERE dataset_id = %s ORDER BY created_at, event_type",
            (dataset_id,),
        ).fetchall()


def _statuses(pg: SimpleNamespace, dataset_id: uuid.UUID) -> dict[int, str]:
    with psycopg.connect(pg.owner_libpq) as c:
        return dict(
            c.execute(
                "SELECT version_number, status FROM dataset_versions WHERE dataset_id = %s",
                (dataset_id,),
            ).fetchall()
        )


# --- valid lifecycle paths -----------------------------------------------------------


async def test_full_lifecycle_with_one_event_per_transition(h: Harness) -> None:
    d = await h.dataset()
    assert (d.status.value, d.active_version_id, d.last_version_number) == ("ACTIVE", None, 0)
    v = await h.version(d.id)
    assert (v.status, v.version_number, v.original_filename) == (
        VersionStatus.QUARANTINED,
        1,
        "sales.csv",
    )
    await h.to(d.id, v.id, VersionStatus.PROFILING, VersionStatus.PROFILED)
    active = await h.activate(d.id, v.id)
    assert active.status is VersionStatus.ACTIVE and active.activated_at is not None
    ds = await h.run(lambda s: svc.get_dataset(s, h.tenant, d.id))
    assert ds.active_version_id == v.id
    assert [(e[0], e[2], e[3]) for e in _events(h.pg, d.id)] == [
        ("DATASET_CREATED", None, "ACTIVE"),
        ("VERSION_CREATED", None, "QUARANTINED"),
        ("VERSION_PROFILING_STARTED", "QUARANTINED", "PROFILING"),
        ("VERSION_PROFILED", "PROFILING", "PROFILED"),
        ("VERSION_ACTIVATED", "PROFILED", "ACTIVE"),
    ]
    assert {e[4] for e in _events(h.pg, d.id)} == {"user"}


@pytest.mark.parametrize(
    "path",
    [
        (VersionStatus.REJECTED,),
        (VersionStatus.PROFILING, VersionStatus.REJECTED),
        (VersionStatus.PROFILING, VersionStatus.PROFILED, VersionStatus.REJECTED),
    ],
)
async def test_rejection_paths_record_a_constrained_code(
    h: Harness, path: tuple[VersionStatus, ...]
) -> None:
    d = await h.dataset()
    v = await h.version(d.id)
    final = await h.to(d.id, v.id, *path)
    assert final.status is VersionStatus.REJECTED
    assert final.rejection_code is RejectionCode.REVIEW_REJECTED
    assert _events(h.pg, d.id)[-1][0::5] == ("VERSION_REJECTED", "REVIEW_REJECTED")


async def test_activation_supersedes_and_keeps_history_addressable(h: Harness) -> None:
    d = await h.dataset()
    v1 = await h.profiled(d.id)
    await h.activate(d.id, v1.id)
    v2 = await h.profiled(d.id)
    await h.activate(d.id, v2.id)
    old = await h.run(lambda s: svc.get_version(s, h.tenant, d.id, v1.id))
    assert old.status is VersionStatus.SUPERSEDED and old.superseded_at is not None
    assert old.original_filename == "sales.csv"  # immutable, still addressable
    ds = await h.run(lambda s: svc.get_dataset(s, h.tenant, d.id))
    assert ds.active_version_id == v2.id
    assert _statuses(h.pg, d.id) == {1: "SUPERSEDED", 2: "ACTIVE"}


# --- invalid transitions and eligibility -------------------------------------------------


async def test_invalid_transitions_and_ineligible_activation_are_conflicts(h: Harness) -> None:
    d = await h.dataset()
    v = await h.version(d.id)
    with pytest.raises(DatasetConflict) as e1:  # QUARANTINED -> PROFILED skips a step
        await h.to(d.id, v.id, VersionStatus.PROFILED)
    assert e1.value.code == "DATASET_VERSION_INVALID_TRANSITION"
    with pytest.raises(DatasetConflict) as e2:
        await h.activate(d.id, v.id)
    assert e2.value.code == "DATASET_VERSION_NOT_ELIGIBLE"
    for bad in (VersionStatus.ACTIVE, VersionStatus.DELETED, VersionStatus.SUPERSEDED):
        with pytest.raises(DatasetConflict):  # no generic "set status"
            await h.to(d.id, v.id, bad)
    with pytest.raises(DatasetConflict):  # rejection without a code
        await h.run(
            lambda s: svc.transition_version(
                s, h.tenant, h.actor, d.id, v.id, to=VersionStatus.REJECTED
            )
        )
    await h.to(d.id, v.id, VersionStatus.REJECTED)
    with pytest.raises(DatasetConflict):  # REJECTED is final until deletion
        await h.to(d.id, v.id, VersionStatus.PROFILING)
    assert _statuses(h.pg, d.id) == {1: "REJECTED"}


async def test_name_conflicts_are_per_tenant_and_stable(
    h: Harness, pg_stack: SimpleNamespace
) -> None:
    await h.dataset("Sales")
    with pytest.raises(DatasetConflict) as exc:
        await h.dataset("  sales ")
    assert exc.value.code == "DATASET_NAME_TAKEN"
    other = pg_stack.seed_member("owner")
    h2 = Harness(pg_stack, other.user_id, other.tenant_id)
    try:
        await h2.dataset("Sales")
    finally:
        await h2.engine.dispose()


# --- deletion ------------------------------------------------------------------------


async def test_dataset_deletion_is_idempotent_and_blocks_everything_after(h: Harness) -> None:
    d = await h.dataset()
    v1 = await h.profiled(d.id)
    await h.activate(d.id, v1.id)
    v2 = await h.version(d.id)
    deleting, changed = await h.run(
        lambda s: svc.request_dataset_deletion(s, h.tenant, h.actor, d.id)
    )
    assert changed and deleting.status.value == "DELETING"
    assert deleting.active_version_id is None and deleting.deletion_requested_at is not None
    again, changed_again = await h.run(
        lambda s: svc.request_dataset_deletion(s, h.tenant, h.actor, d.id)
    )
    assert not changed_again and again.deletion_requested_at == deleting.deletion_requested_at
    assert _statuses(h.pg, d.id) == {1: "DELETING", 2: "DELETING"}
    with pytest.raises(DatasetConflict) as e1:
        await h.version(d.id)
    assert e1.value.code == "DATASET_NOT_ACTIVE"
    with pytest.raises(DatasetConflict):
        await h.activate(d.id, v2.id)
    with pytest.raises(DatasetConflict):
        await h.to(d.id, v2.id, VersionStatus.PROFILING)
    kinds = [e[0] for e in _events(h.pg, d.id)]
    assert kinds.count("DATASET_DELETION_REQUESTED") == 1  # idempotent: once
    assert kinds.count("VERSION_DELETION_REQUESTED") == 2
    reasons = {e[5] for e in _events(h.pg, d.id) if e[0] == "VERSION_DELETION_REQUESTED"}
    assert reasons == {"DATASET_DELETION"}


async def test_deleting_the_active_version_leaves_no_active_version(h: Harness) -> None:
    d = await h.dataset()
    v = await h.profiled(d.id)
    await h.activate(d.id, v.id)
    deleted, changed = await h.run(
        lambda s: svc.request_version_deletion(s, h.tenant, h.actor, d.id, v.id)
    )
    assert changed and deleted.status is VersionStatus.DELETING
    _, again = await h.run(lambda s: svc.request_version_deletion(s, h.tenant, h.actor, d.id, v.id))
    assert not again
    ds = await h.run(lambda s: svc.get_dataset(s, h.tenant, d.id))
    assert ds.status.value == "ACTIVE" and ds.active_version_id is None
    with pytest.raises(DatasetConflict):
        await h.activate(d.id, v.id)


async def test_operator_tombstone_scrubs_and_never_resurrects(
    h: Harness, pg_stack: SimpleNamespace
) -> None:
    d = await h.dataset("Payroll 2026")
    v = await h.version(d.id)
    with (
        psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c,
        pytest.raises(ops_datasets.TombstoneError, match="not DELETING"),
    ):
        ops_datasets.tombstone(c, dataset_id=d.id)
    await h.run(lambda s: svc.request_dataset_deletion(s, h.tenant, h.actor, d.id))
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        assert [r[1] for r in ops_datasets.pending(c)] == [d.id]
        result = ops_datasets.tombstone(c, dataset_id=d.id)
        assert result == {"dataset_id": str(d.id), "versions_tombstoned": 1, "dataset": "DELETED"}
        row = c.execute(
            "SELECT status, name, normalized_name, description, last_version_number "
            "FROM datasets WHERE id = %s",
            (d.id,),
        ).fetchone()
        assert row == ("DELETED", None, None, None, 1)  # ids and counts kept, names gone
        vrow = c.execute(
            "SELECT status, original_filename, storage_object_key, declared_size_bytes "
            "FROM dataset_versions WHERE id = %s",
            (v.id,),
        ).fetchone()
        assert vrow == ("DELETED", None, None, 1234)
        with pytest.raises(ops_datasets.TombstoneError):
            ops_datasets.tombstone(c, dataset_id=d.id)
        assert ops_datasets.pending(c) == []
    # Gone for the runtime role: not readable, not deletable again, not revivable.
    with pytest.raises(DatasetNotFound):
        await h.run(lambda s: svc.get_dataset(s, h.tenant, d.id))
    with pytest.raises(DatasetNotFound):
        await h.run(lambda s: svc.request_dataset_deletion(s, h.tenant, h.actor, d.id))
    assert await h.run(lambda s: svc.list_datasets(s, h.tenant, limit=10, offset=0)) == []
    # The name is free again for a NEW dataset (a new id); the tombstone stays.
    fresh = await h.dataset("Payroll 2026")
    assert fresh.id != d.id
    kinds = [e[0] for e in _events(h.pg, d.id)]
    assert kinds.count("VERSION_TOMBSTONED") == 1 and kinds.count("DATASET_TOMBSTONED") == 1
    assert {e[4] for e in _events(h.pg, d.id) if e[0].endswith("TOMBSTONED")} == {"operator"}


async def test_tombstone_refuses_a_version_that_references_a_stored_object(
    h: Harness, pg_stack: SimpleNamespace
) -> None:
    d = await h.dataset()
    v = await h.version(d.id)
    key = f"quarantine/{h.tenant}/{d.id}/upload.csv"
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("UPDATE dataset_versions SET storage_object_key = %s WHERE id = %s", (key, v.id))
    await h.run(lambda s: svc.request_dataset_deletion(s, h.tenant, h.actor, d.id))
    with (
        psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c,
        pytest.raises(ops_datasets.TombstoneError, match="physical deletion"),
    ):
        ops_datasets.tombstone(c, dataset_id=d.id)
    assert _statuses(h.pg, d.id) == {1: "DELETING"}


async def test_single_version_tombstone_on_a_live_dataset(
    h: Harness, pg_stack: SimpleNamespace
) -> None:
    d = await h.dataset()
    v = await h.version(d.id)
    keep = await h.version(d.id)
    await h.run(lambda s: svc.request_version_deletion(s, h.tenant, h.actor, d.id, v.id))
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        assert [(r[1], r[2], r[4]) for r in ops_datasets.pending(c)] == [(d.id, "ACTIVE", 1)]
        with pytest.raises(ops_datasets.TombstoneError, match="not DELETING"):
            ops_datasets.tombstone(c, dataset_id=d.id, version_id=keep.id)
        ops_datasets.tombstone(c, dataset_id=d.id, version_id=v.id)
        assert ops_datasets.pending(c) == []
    assert _statuses(h.pg, d.id) == {1: "DELETED", 2: "QUARANTINED"}
    with pytest.raises(DatasetVersionNotFound):
        await h.run(lambda s: svc.get_version(s, h.tenant, d.id, v.id))


# --- authorization through the service -------------------------------------------------


async def test_member_cannot_write_and_other_tenant_cannot_see(
    h: Harness, pg_stack: SimpleNamespace
) -> None:
    d = await h.dataset()
    member = pg_stack.add_membership(h.tenant, "member")
    listed = await h.run(lambda s: svc.list_datasets(s, h.tenant, limit=10, offset=0), user=member)
    assert [x.id for x in listed] == [d.id]
    with pytest.raises(Exception, match="row-level security|permission|InsufficientPrivilege"):
        await h.run(
            lambda s: svc.create_dataset(
                s, h.tenant, Actor.user(member), name="X", description=None
            ),
            user=member,
        )
    with pytest.raises(DatasetNotFound):  # FOR UPDATE needs admin: invisible to a member
        await h.run(
            lambda s: svc.request_dataset_deletion(s, h.tenant, Actor.user(member), d.id),
            user=member,
        )
    other = pg_stack.seed_member("owner")
    h2 = Harness(pg_stack, other.user_id, other.tenant_id)
    try:
        with pytest.raises(DatasetNotFound):
            await h2.run(lambda s: svc.get_dataset(s, other.tenant_id, d.id))
        with pytest.raises(DatasetNotFound):  # even naming the victim's tenant id
            await h2.run(lambda s: svc.get_dataset(s, h.tenant, d.id))
        with pytest.raises(DatasetNotFound):
            await h2.run(
                lambda s: svc.request_dataset_deletion(
                    s, other.tenant_id, Actor.user(other.user_id), d.id
                )
            )
    finally:
        await h2.engine.dispose()


# --- concurrency -------------------------------------------------------------------------


async def test_concurrent_version_creation_allocates_unique_consecutive_numbers(
    h: Harness,
) -> None:
    d = await h.dataset()
    created = await asyncio.gather(*(h.version(d.id) for _ in range(8)))
    assert sorted(v.version_number for v in created) == list(range(1, 9))
    kinds = [e[0] for e in _events(h.pg, d.id)]
    assert kinds.count("VERSION_CREATED") == 8


async def test_concurrent_activation_leaves_exactly_one_active_version(h: Harness) -> None:
    d = await h.dataset()
    candidates = [await h.profiled(d.id) for _ in range(4)]
    results = await asyncio.gather(
        *(h.activate(d.id, v.id) for v in candidates), return_exceptions=True
    )
    assert all(not isinstance(r, Exception) for r in results), results
    statuses = _statuses(h.pg, d.id)
    assert sorted(statuses.values()) == ["ACTIVE", "SUPERSEDED", "SUPERSEDED", "SUPERSEDED"]
    ds = await h.run(lambda s: svc.get_dataset(s, h.tenant, d.id))
    active_number = next(n for n, st in statuses.items() if st == "ACTIVE")
    assert ds.active_version_id == candidates[active_number - 1].id
    kinds = [e[0] for e in _events(h.pg, d.id)]
    assert kinds.count("VERSION_ACTIVATED") == 4 and kinds.count("VERSION_SUPERSEDED") == 3


async def test_concurrent_deletion_and_activation_never_leave_a_live_active_version(
    h: Harness,
) -> None:
    d = await h.dataset()
    v = await h.profiled(d.id)
    results = await asyncio.gather(
        h.activate(d.id, v.id),
        h.run(lambda s: svc.request_dataset_deletion(s, h.tenant, h.actor, d.id)),
        return_exceptions=True,
    )
    assert sum(1 for r in results if isinstance(r, Exception)) <= 1
    for r in results:
        assert not isinstance(r, Exception) or isinstance(r, DatasetConflict)
    with psycopg.connect(h.pg.owner_libpq) as c:
        row = c.execute(
            "SELECT status, active_version_id FROM datasets WHERE id = %s", (d.id,)
        ).fetchone()
    assert row == ("DELETING", None)
    assert _statuses(h.pg, d.id) == {1: "DELETING"}
