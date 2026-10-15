"""The O-5 retention sweep against PostgreSQL (ADR-035). Objects live in a
local store; receipts in the in-memory Object Lock S3 (no network, no AWS).

The sweep's clock is a parameter, so every deadline is tested one second
before, exactly at, and one second after it against database timestamps.
"""

import threading
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from test_deletion_receipt_log import CONFIG, MAPPING, H, fake

from nlw.core import retention as policy
from nlw.datasets import ingestion
from nlw.datasets import service as svc
from nlw.datasets.deletion_log import DeletionLogUnavailable
from nlw.datasets.deletion_log_s3 import S3DeletionLog
from nlw.datasets.lifecycle import ReasonCode
from nlw.ingest_service import processing
from nlw.ops import dataset_retention as dr
from nlw.ops import datasets as ops
from nlw.storage.blob import TenantScopedBlobStore
from nlw.storage.s3_credentials import CredentialError, verify_role_path

pytestmark = pytest.mark.integration

SECOND = timedelta(seconds=1)
BAD = b"region,amount\nNorth,1,unexpected\n"
DAYS = timedelta(days=policy.INACTIVE_RETENTION_DAYS)


@pytest.fixture
async def h(pg_stack: SimpleNamespace, tmp_path: Path) -> AsyncIterator[H]:
    harness = H(pg_stack, tmp_path)
    yield harness
    await harness.engine.dispose()
    await harness.ingest_engine.dispose()


async def _rejected(h: H, d: uuid.UUID) -> uuid.UUID:
    v = (
        await h.run(
            lambda s: svc.create_version(
                s, h.tenant, h.actor, d, original_filename="bad.csv", media_type="text/csv",
                declared_size_bytes=len(BAD), idempotency_key=uuid.uuid4().hex,
            )
        )
    ).id  # fmt: skip

    async def chunks() -> AsyncIterator[bytes]:
        yield BAD

    _, env = await ingestion.store_content(
        maker=h.maker, signer=h.signer, store=h.store, ctx=h.ctx, dataset_id=d,
        version_id=v, chunks=chunks(), max_bytes=10**6,
    )  # fmt: skip
    assert env is not None
    await processing.process_envelope(
        maker=h.ingest_maker, signer=h.ingest_signer, store=h.store, config=CONFIG,
        message=env.to_json(),
    )  # fmt: skip
    assert h.row(v)[0] == "REJECTED"
    return v  # type: ignore[no-any-return]


def _since(h: H, v: uuid.UUID) -> datetime:
    with h.owner() as c:
        row = c.execute(
            "SELECT coalesce(superseded_at, created_at) FROM dataset_versions WHERE id = %s", (v,)
        ).fetchone()
    assert row is not None
    return row[0]  # type: ignore[no-any-return]


def _db_now(h: H) -> datetime:
    with h.owner() as c:
        return c.execute("SELECT now()").fetchone()[0]  # type: ignore[no-any-return]


def _sweep(h: H, now: datetime, **kw: Any) -> dict[str, int]:
    kw.setdefault("limit", 100)
    with h.owner() as c:
        return dr.retention_sweep(
            c, h.store, h.log, operator="op-sweep", environment="local", now=now, **kw
        )


def _events(h: H, v: uuid.UUID) -> list[tuple[str, str]]:
    with h.owner() as c:
        return [
            (str(a), str(b))
            for a, b in c.execute(
                "SELECT event_type, coalesce(reason_code, '') FROM dataset_events "
                "WHERE version_id = %s ORDER BY created_at, event_type",
                (v,),
            ).fetchall()
        ]


# --- inactive versions: the 30-day boundary --------------------------------------------


async def test_an_inactive_version_is_kept_30_days_and_then_purged_with_a_receipt(h: H) -> None:
    d = await h.dataset()
    v = await h.profiled(d)
    since = _since(h, v)
    assert _sweep(h, since + DAYS - SECOND, dry_run=True)["selected"] == 0
    assert _sweep(h, since + DAYS, dry_run=True)["selected"] == 1  # exactly at: it may go
    assert h.row(v)[0] == "PROFILED"  # a dry run changes nothing
    with h.owner() as c:
        assert dr.retention_status(c, since + DAYS - SECOND)["inactive_count"] == 0
        assert dr.retention_status(c, since + DAYS)["inactive_count"] == 1
    result = _sweep(h, since + DAYS + SECOND)
    assert (result["inactive_moved"], result["inactive_purged"]) == (1, 1)
    assert h.row(v)[0] == "DELETING"
    assert ("VERSION_DELETION_REQUESTED", "INACTIVE_RETENTION") in _events(h, v)
    assert ("VERSION_OBJECT_PURGED", "OPERATOR_PURGE") in _events(h, v)
    assert not TenantScopedBlobStore(h.store, h.tenant).list_version(d, v)
    # The receipt verifies and the operator's tombstone still works as before.
    with h.owner() as c:
        assert ops.reconcile_receipts(c, h.log)["unverified"] == []
        ops.tombstone(c, dataset_id=d, version_id=v, store=h.store, log=h.log)
    assert h.row(v)[0] == "DELETED"


async def test_the_active_version_is_never_touched_and_superseded_ages_from_supersession(
    h: H,
) -> None:
    d = await h.dataset()
    old = await h.active(d)
    new = await h.active(d)  # supersedes `old`
    assert h.row(old)[0] == "SUPERSEDED" and h.row(new) == ("ACTIVE", new)
    superseded = _since(h, old)
    created = _since(h, new)
    assert superseded > created - timedelta(days=1)  # aged from supersession
    far = _db_now(h) + timedelta(days=4000)
    assert _sweep(h, superseded + DAYS - SECOND, dry_run=True)["selected"] == 0
    # The selection alone (a dry run never reaches the row-lock re-check)
    # excludes the ACTIVE version.
    assert _sweep(h, far, dry_run=True)["selected"] == 1
    result = _sweep(h, far)
    assert (result["inactive_moved"], result["inactive_purged"]) == (1, 1)
    assert h.row(new) == ("ACTIVE", new)  # 11 years later, still the published source
    assert TenantScopedBlobStore(h.store, h.tenant).list_version(d, new)
    assert h.row(old)[0] == "DELETING"


async def test_a_concurrent_activation_wins_over_the_sweep(h: H) -> None:
    """Re-checked under the row lock: a version activated after selection is kept."""
    d = await h.dataset()
    v = await h.profiled(d)
    later = _since(h, v) + DAYS + SECOND
    t, a = h.tenant, h.actor
    await h.run(lambda s: svc.confirm_semantics(s, t, a, d, v, mapping_json=MAPPING))
    await h.run(lambda s: svc.activate_version(s, t, a, d, v))
    with h.owner() as c:
        assert not dr._move_to_deleting(
            c, h.tenant, d, v, reason=ReasonCode.INACTIVE_RETENTION, now=later
        )
        # Both reasons' re-checks refuse the active version, at any age.
        for reason in (ReasonCode.INACTIVE_RETENTION, ReasonCode.REJECTED_RETENTION):
            assert not dr._move_to_deleting(
                c, h.tenant, d, v, reason=reason, now=later + timedelta(days=4000)
            )
    assert h.row(v) == ("ACTIVE", v)


# --- deleted and rejected: oldest first, bounded, idempotent ----------------------------


async def test_deleted_and_rejected_bytes_are_purged_oldest_first_in_bounded_batches(
    h: H,
) -> None:
    d = await h.dataset()
    vs = [await h.profiled(d) for _ in range(3)]
    for v in vs:  # deletion requests in this order
        await h.run(lambda s, v=v: svc.request_version_deletion(s, h.tenant, h.actor, d, v))
    rejected = await _rejected(h, d)
    now = _db_now(h)
    with h.owner() as c:
        status = dr.retention_status(c, now)
    assert (status["deleting_count"], status["rejected_count"]) == (3, 1)

    one = _sweep(h, now, limit=2)
    assert (one["deleting_purged"], one["rejected_purged"], one["more"]) == (2, 0, 1)
    purged = [v for v in vs if ("VERSION_OBJECT_PURGED", "OPERATOR_PURGE") in _events(h, v)]
    assert purged == vs[:2]  # the two oldest requests
    two = _sweep(h, now, limit=2)
    assert (two["deleting_purged"], two["rejected_moved"], two["rejected_purged"]) == (1, 1, 1)
    assert ("VERSION_DELETION_REQUESTED", "REJECTED_RETENTION") in _events(h, rejected)
    three = _sweep(h, now, limit=2)  # idempotent: nothing left
    assert three["selected"] == 0 and three["more"] == 0
    with h.owner() as c:
        status = dr.retention_status(c, now)
    assert (status["deleting_count"], status["rejected_count"]) == (0, 0)


async def test_a_partial_failure_stops_the_batch_and_a_retry_finishes_it(h: H) -> None:
    d = await h.dataset()
    a, b = await h.profiled(d), await h.profiled(d)
    for v in (a, b):
        await h.run(lambda s, v=v: svc.request_version_deletion(s, h.tenant, h.actor, d, v))

    class FailSecond(S3DeletionLog):
        appends = 0

        def append(self, receipt: Any) -> str:
            FailSecond.appends += 1
            if FailSecond.appends == 2:
                raise DeletionLogUnavailable("the receipt could not be written (SlowDown)")
            return super().append(receipt)

    flaky = FailSecond(h.bucket.client("operator"), fake.BUCKET)
    progress: dict[str, int] = {}
    with h.owner() as c, pytest.raises(ops.TombstoneError, match="SlowDown"):
        dr.retention_sweep(c, h.store, flaky, operator="op", environment="local",
                           now=_db_now(h), progress=progress)  # fmt: skip
    assert progress["deleting_purged"] == 1  # the first committed, the second rolled back
    assert ("VERSION_OBJECT_PURGED", "OPERATOR_PURGE") in _events(h, a)
    assert ("VERSION_OBJECT_PURGED", "OPERATOR_PURGE") not in _events(h, b)
    retry = _sweep(h, _db_now(h))  # the retry finishes the job
    assert retry["deleting_purged"] == 1
    assert ("VERSION_OBJECT_PURGED", "OPERATOR_PURGE") in _events(h, b)


# --- recovery lock and mutual exclusion ------------------------------------------------


async def test_the_recovery_lock_stops_the_sweep_and_the_tombstone(h: H) -> None:
    d = await h.dataset()
    v = await h.profiled(d)
    await h.run(lambda s: svc.request_version_deletion(s, h.tenant, h.actor, d, v))
    h.lock()
    with pytest.raises(ops.TombstoneError, match="recovery lock"):
        _sweep(h, _db_now(h))
    with pytest.raises(ops.TombstoneError, match="recovery lock"):
        _sweep(h, _db_now(h), dry_run=True)
    with h.owner() as c, pytest.raises(ops.TombstoneError, match="recovery lock"):
        ops.tombstone(c, dataset_id=d, version_id=v, store=h.store, log=h.log)
    assert TenantScopedBlobStore(h.store, h.tenant).list_version(d, v)
    assert ("VERSION_OBJECT_PURGED", "OPERATOR_PURGE") not in _events(h, v)


async def test_only_one_sweep_runs_at_a_time(h: H) -> None:
    d = await h.dataset()
    v = await h.profiled(d)
    await h.run(lambda s: svc.request_version_deletion(s, h.tenant, h.actor, d, v))
    with h.owner() as holder:
        assert holder.execute(dr._SQL_LOCK).fetchone() == (True,)
        result = _sweep(h, _db_now(h))
        assert result["busy"] == 1 and result["selected"] == 0
        holder.execute(dr._SQL_UNLOCK)
    assert ("VERSION_OBJECT_PURGED", "OPERATOR_PURGE") not in _events(h, v)
    # Two sweeps racing: exactly one purges, the other is busy or finds nothing.
    results: list[dict[str, int]] = []
    now = _db_now(h)
    threads = [threading.Thread(target=lambda: results.append(_sweep(h, now))) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r["deleting_purged"] for r in results) == 1
    purges = [e for e in _events(h, v) if e[0] == "VERSION_OBJECT_PURGED"]
    assert len(purges) == 1


async def test_a_naive_clock_is_refused(h: H) -> None:
    with pytest.raises(ops.TombstoneError, match="timezone-aware"):
        _sweep(h, datetime(2026, 10, 15, 12, 0))
    with h.owner() as c, pytest.raises(ops.TombstoneError, match="timezone-aware"):
        dr.retention_status(c, datetime(2026, 10, 15, 12, 0))


# --- receipts nearing expiry, metrics ---------------------------------------------------


async def test_a_receipt_nearing_expiry_before_its_tombstone_is_counted(h: H) -> None:
    d = await h.dataset()
    v = await h.profiled(d)
    await h.run(lambda s: svc.request_version_deletion(s, h.tenant, h.actor, d, v))
    _sweep(h, _db_now(h))
    with h.owner() as c:
        purged_at = c.execute(
            "SELECT max(created_at) FROM dataset_events WHERE version_id = %s "
            "AND event_type = 'VERSION_OBJECT_PURGED'",
            (v,),
        ).fetchone()[0]
        warn = timedelta(days=policy.RECEIPT_RETENTION_DAYS - policy.RECEIPT_EXPIRY_WARNING_DAYS)
        assert dr.retention_status(c, purged_at + warn - SECOND)["receipts_count"] == 0
        assert dr.retention_status(c, purged_at + warn)["receipts_count"] == 1
        ops.tombstone(c, dataset_id=d, version_id=v, store=h.store, log=h.log)
        assert dr.retention_status(c, purged_at + warn)["receipts_count"] == 0


def test_textfile_metrics_are_label_free_and_keep_the_last_success(tmp_path: Path) -> None:
    path = str(tmp_path / "retention.prom")
    now = datetime.fromisoformat("2026-10-15T12:00:00+00:00")
    status = dict.fromkeys(dr.STATUS_METRICS, 0)
    dr.write_textfile(path, dr.sweep_metrics(path, now=now, outcome="ok", status=status))
    later = now + timedelta(days=1)
    dr.write_textfile(path, dr.sweep_metrics(path, now=later, outcome="failed", status=None))
    values = dr.read_textfile(path)
    assert values["nlw_dataset_retention_sweep_last_success_timestamp_seconds"] == now.timestamp()
    assert values["nlw_dataset_retention_sweep_last_run_timestamp_seconds"] == later.timestamp()
    assert values["nlw_dataset_retention_sweep_failed"] == 1
    text = Path(path).read_text()
    assert "{" not in text and "tenant" not in text


# --- the CLI ----------------------------------------------------------------------------


@pytest.fixture
def cli(h: H, monkeypatch: pytest.MonkeyPatch) -> H:
    monkeypatch.setenv("DATABASE_MIGRATION_URL", h.pg.owner_sa)
    monkeypatch.setattr(ops, "configured_deletion_log", lambda settings: h.log)
    monkeypatch.setattr(ops, "dataset_store", lambda settings, service="operator": h.store)
    return h


async def test_cli_sweep_records_success_lock_and_failure(
    cli: H, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    metrics = str(tmp_path / "nlw_datasets_retention.prom")
    d = await cli.dataset()
    v = await cli.profiled(d)
    await cli.run(lambda s: svc.request_version_deletion(s, cli.tenant, cli.actor, d, v))
    assert ops.main(["retention-sweep", "--operator", "op", "--metrics-file", metrics]) == 0
    assert "deleting_purged=1" in capsys.readouterr().out
    ok = dr.read_textfile(metrics)
    assert ok["nlw_dataset_retention_sweep_failed"] == 0
    assert ok["nlw_dataset_deleting_unpurged"] == 0
    last_ok = ok["nlw_dataset_retention_sweep_last_success_timestamp_seconds"]

    lock = cli.lock()
    assert ops.main(["retention-sweep", "--operator", "op", "--metrics-file", metrics]) == 2
    locked = dr.read_textfile(metrics)
    assert locked["nlw_dataset_retention_sweep_recovery_locked"] == 1
    assert locked["nlw_dataset_retention_sweep_last_success_timestamp_seconds"] == last_ok
    cli.unlock(lock)

    def boom(*a: Any, **k: Any) -> Any:
        raise psycopg.OperationalError(f"server at db.internal for {fake.BUCKET} gone")

    monkeypatch.setattr(dr, "retention_sweep", boom)
    assert ops.main(["retention-sweep", "--operator", "op", "--metrics-file", metrics]) == 3
    err = capsys.readouterr().err
    assert "OperationalError" in err and "db.internal" not in err and fake.BUCKET not in err
    assert dr.read_textfile(metrics)["nlw_dataset_retention_sweep_failed"] == 1


async def test_cli_status_writes_the_retention_gauges(
    cli: H, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = await cli.dataset()
    await _rejected(cli, d)
    metrics = str(tmp_path / "status.prom")
    assert ops.main(["retention-status", "--metrics-file", metrics]) == 0
    assert "rejected_count=1" in capsys.readouterr().out
    values = dr.read_textfile(metrics)
    assert values["nlw_dataset_rejected_retained"] == 1
    assert set(values) == {name for name, _ in dr.STATUS_METRICS.values()}


async def test_cli_reconcile_writes_receipt_gauges(
    cli: H, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = await cli.dataset()
    v = await cli.profiled(d)
    await cli.run(lambda s: svc.request_version_deletion(s, cli.tenant, cli.actor, d, v))
    _sweep(cli, _db_now(cli))
    [key] = cli.bucket.objects
    cli.bucket.expire_retention(key)
    metrics = str(tmp_path / "receipts.prom")
    assert ops.main(["reconcile-receipts", "--metrics-file", metrics]) == 1
    values = dr.read_textfile(metrics)
    assert values["nlw_dataset_receipts_unverified"] == 1
    assert values["nlw_dataset_receipts_unexpected_objects"] == 0
    capsys.readouterr()


# --- the operator role path, before any deletion ----------------------------------------


async def test_a_role_at_another_path_stops_the_sweep_before_any_byte_is_deleted(h: H) -> None:
    d = await h.dataset()
    v = await h.profiled(d)
    await h.run(lambda s: svc.request_version_deletion(s, h.tenant, h.actor, d, v))
    iam = fake.FakeIAM(env="local", path="/ops/")

    def role_check() -> None:
        try:
            verify_role_path(iam, "nlw-local-dataset-operator")
        except CredentialError as exc:
            raise DeletionLogUnavailable(str(exc)) from None

    log = S3DeletionLog(h.bucket.client("operator"), fake.BUCKET, role_check=role_check)
    with h.owner() as c, pytest.raises(ops.TombstoneError, match="must be at path /"):
        dr.retention_sweep(c, h.store, log, operator="op", environment="local",
                           now=_db_now(h))  # fmt: skip
    assert TenantScopedBlobStore(h.store, h.tenant).list_version(d, v)  # untouched
    assert h.bucket.objects == {}
    with h.owner() as c, pytest.raises(ops.TombstoneError, match="must be at path /"):
        ops.purge(c, h.store, log, dataset_id=d, version_id=v, operator="op",
                  environment="local")  # fmt: skip
    assert TenantScopedBlobStore(h.store, h.tenant).list_version(d, v)


# --- fairness: one candidate set, earliest effective due time first ----------------------

_SHIFTED = (
    "created_at", "updated_at", "profiling_started_at", "profiled_at", "activated_at",
    "superseded_at", "rejected_at", "deletion_requested_at",
)  # fmt: skip


def _backdate(h: H, v: uuid.UUID, days: int) -> None:
    """Move every lifecycle timestamp of ``v`` ``days`` into the past (test
    setup only: the guard keeps these immutable, so it is suspended for one
    owner transaction)."""
    sets = ", ".join(f"{c} = {c} - make_interval(days => %(days)s)" for c in _SHIFTED)
    with h.owner() as c, c.transaction():
        c.execute("ALTER TABLE dataset_versions DISABLE TRIGGER USER")
        c.execute(f"UPDATE dataset_versions SET {sets} WHERE id = %(v)s", {"v": v, "days": days})
        c.execute("ALTER TABLE dataset_versions ENABLE TRIGGER USER")


def _order(h: H, now: datetime, limit: int = 100) -> list[tuple[str, uuid.UUID]]:
    params = {"now": now, "days": policy.INACTIVE_RETENTION_DAYS,
              "purge_days": policy.DELETED_PURGE_DAYS,
              "rejected_days": policy.REJECTED_PURGE_DAYS, "limit": limit}  # fmt: skip
    with h.owner() as c:
        return [(str(r[0]), r[3]) for r in c.execute(dr._SQL_CANDIDATES, params).fetchall()]


async def _deleting(h: H, d: uuid.UUID, n: int) -> list[uuid.UUID]:
    vs = [await h.profiled(d) for _ in range(n)]
    for v in vs:
        await h.run(lambda s, v=v: svc.request_version_deletion(s, h.tenant, h.actor, d, v))
    return vs


async def test_an_older_rejected_item_runs_before_a_newer_deletion(h: H) -> None:
    d = await h.dataset()
    rejected = await _rejected(h, d)
    [deleting] = await _deleting(h, d, 1)  # requested after the rejection
    now = _db_now(h)
    assert [k for k, _ in _order(h, now)] == ["rejected", "deleting"]
    first = _sweep(h, now, limit=1)
    assert (first["rejected_purged"], first["deleting_purged"], first["more"]) == (1, 0, 1)
    assert h.row(rejected)[0] == "DELETING" and h.row(deleting)[0] == "DELETING"
    assert ("VERSION_OBJECT_PURGED", "OPERATOR_PURGE") not in _events(h, deleting)
    second = _sweep(h, now, limit=1)
    assert second["deleting_purged"] == 1 and second["more"] == 0


async def test_an_older_inactive_version_is_not_starved_by_a_deletion_backlog(h: H) -> None:
    d = await h.dataset()
    inactive = await h.profiled(d)
    _backdate(h, inactive, 40)  # retention ended 10 days ago
    backlog = await _deleting(h, d, 3)  # requested now: due in 7 days
    now = _db_now(h)
    assert [k for k, _ in _order(h, now)] == ["inactive", "deleting", "deleting", "deleting"]
    first = _sweep(h, now, limit=1)
    assert (first["inactive_moved"], first["inactive_purged"], first["deleting_purged"]) == (
        1,
        1,
        0,
    )
    assert h.row(inactive)[0] == "DELETING"
    assert all(("VERSION_OBJECT_PURGED", "OPERATOR_PURGE") not in _events(h, v) for v in backlog)


async def test_every_category_progresses_across_bounded_runs_and_active_is_untouched(
    h: H,
) -> None:
    d = await h.dataset()
    active = await h.active(d)
    _backdate(h, active, 400)  # very old, still the published source
    inactive = [await h.profiled(d) for _ in range(2)]
    for v in inactive:
        _backdate(h, v, 31)  # due yesterday
    rejected = [await _rejected(h, d) for _ in range(2)]
    deleting = await _deleting(h, d, 3)
    now = _db_now(h)
    kinds = [k for k, _ in _order(h, now)]
    assert kinds[:2] == ["inactive", "inactive"] and sorted(kinds[2:]) == sorted(
        ["rejected", "rejected", "deleting", "deleting", "deleting"]
    )
    assert active not in {v for _, v in _order(h, now)}
    totals = dict.fromkeys(("inactive_purged", "rejected_purged", "deleting_purged"), 0)
    runs = 0
    while True:
        runs += 1
        assert runs <= 4, "7 candidates in batches of 2 finish in 4 runs"
        result = _sweep(h, now, limit=2)
        for k in totals:
            totals[k] += result[k]
        if not result["more"]:
            break
    assert runs == 4
    assert totals == {"inactive_purged": 2, "rejected_purged": 2, "deleting_purged": 3}
    assert h.row(active) == ("ACTIVE", active)
    assert TenantScopedBlobStore(h.store, h.tenant).list_version(d, active)
    for v in inactive + rejected + deleting:
        assert ("VERSION_OBJECT_PURGED", "OPERATOR_PURGE") in _events(h, v)


async def test_a_partial_failure_across_categories_is_retried_without_loss(h: H) -> None:
    d = await h.dataset()
    inactive = await h.profiled(d)
    _backdate(h, inactive, 40)
    rejected = await _rejected(h, d)

    class FailSecond(S3DeletionLog):
        appends = 0

        def append(self, receipt: Any) -> str:
            FailSecond.appends += 1
            if FailSecond.appends == 2:
                raise DeletionLogUnavailable("the receipt could not be written (SlowDown)")
            return super().append(receipt)

    flaky = FailSecond(h.bucket.client("operator"), fake.BUCKET)
    progress: dict[str, int] = {}
    with h.owner() as c, pytest.raises(ops.TombstoneError, match="SlowDown"):
        dr.retention_sweep(c, h.store, flaky, operator="op", environment="local",
                           now=_db_now(h), progress=progress)  # fmt: skip
    assert progress["inactive_purged"] == 1  # the older item committed first
    assert progress["rejected_moved"] == 1 and progress["rejected_purged"] == 0
    # The rejected version was moved (its own transaction) but not purged: the
    # retry finds it as a deletion and finishes; nothing runs twice.
    retry = _sweep(h, _db_now(h))
    assert retry["deleting_purged"] == 1 and retry["selected"] == 1
    assert ("VERSION_OBJECT_PURGED", "OPERATOR_PURGE") in _events(h, rejected)
    assert [e for e in _events(h, inactive) if e[0] == "VERSION_OBJECT_PURGED"] == [
        ("VERSION_OBJECT_PURGED", "OPERATOR_PURGE")
    ]
