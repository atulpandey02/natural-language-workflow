"""Operator deletion and restore checks for datasets (ADR-029, ADR-030).

The runtime role can request deletion (-> DELETING) but can never write DELETED
(RLS) or the purge evidence event. The operator applies these steps with the
OWNER credential ``DATABASE_MIGRATION_URL``, exactly like ``python -m nlw.ops.grants``::

    python -m nlw.ops.datasets pending
    python -m nlw.ops.datasets purge --dataset <uuid> [--version <uuid>] --operator <name>
    python -m nlw.ops.datasets tombstone --dataset <uuid> [--version <uuid>]
    python -m nlw.ops.datasets verify-objects
    python -m nlw.ops.datasets dispatch-pending [--dry-run]

``dispatch-pending`` is the operator recovery sweep for the ingest queue
(ADR-031): it (re)enqueues the work envelope of every committed, still fresh
processing request whose version is waiting (QUARANTINED, or PROFILING with an
expired or missing lease). The database rows are the work items; re-enqueueing
is harmless (the ingest runtime re-verifies each envelope and its lease makes
processing idempotent). Requests too old for the consumer are counted, not
sent: an admin re-dispatch records a fresh request. It processes nothing.

``purge`` physically deletes every stored object of the DELETING version(s)
(both storage areas, including crash-orphaned partial uploads), VERIFIES their
absence, appends one receipt per version to the configured deletion log, and
records ``VERSION_OBJECT_PURGED`` (operator) in the event trail. Nothing is
recorded unless verification succeeds.

``tombstone`` scrubs names, description, original filename, storage key, the
profile and the semantic mappings to NULL and keeps ids, version numbers,
digests, sizes, actors and timestamps plus the append-only event trail. It is
REFUSED for any version that still references a storage key unless (a) a purge
event was recorded after its deletion request AND (b) the store, checked live,
holds nothing for that version (a whole-dataset tombstone also requires the
dataset's prefixes to be empty).

``verify-objects`` (restore validation) compares version metadata with the
store: a live version whose object is missing or whose bytes no longer match
the recorded digest, and any stored object no version accounts for. A database
restore alone never restores uploaded files; this check makes that visible.

Output carries ids, codes and counts only, never names or content.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from typing import Any

import psycopg

from nlw.core.config import Settings
from nlw.datasets.deletion_log import (
    DeletionLog,
    DeletionLogUnavailable,
    DeletionReceipt,
    ExpectedReceipt,
    ReceiptCheck,
    UnconfiguredDeletionLog,
    deletion_log_from_settings,
)
from nlw.datasets.lifecycle import ActorKind, EventType, ReasonCode
from nlw.storage.blob import AREAS, LocalBlobStore, TenantScopedBlobStore, list_area
from nlw.storage.factory import dataset_store


class TombstoneError(ValueError):
    """An operator input or state error (message is safe to print)."""


def _owner_url() -> str:
    url = os.environ.get("DATABASE_MIGRATION_URL")
    if not url:
        raise SystemExit("DATABASE_MIGRATION_URL (owner credential) is required")
    return url.replace("+psycopg", "", 1)


def _event(
    conn: psycopg.Connection[Any],
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID | None,
    event_type: EventType,
    from_status: str,
    *,
    to_status: str = "DELETED",
    reason: ReasonCode = ReasonCode.OPERATOR_TOMBSTONE,
    receipt: tuple[str, str, str] | None = None,
) -> None:
    sink, receipt_id, digest = receipt if receipt is not None else (None, None, None)
    conn.execute(
        "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
        "from_status, to_status, actor_kind, actor_user_id, reason_code, receipt_sink, "
        "receipt_id, receipt_digest) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NULL, %s, %s, %s, %s)",
        (
            uuid.uuid4(),
            tenant_id,
            dataset_id,
            version_id,
            event_type.value,
            from_status,
            to_status,
            ActorKind.OPERATOR.value,
            reason.value,
            sink,
            receipt_id,
            digest,
        ),
    )


# --- purge ---------------------------------------------------------------------


def purge(
    conn: psycopg.Connection[Any],
    store: LocalBlobStore | None,
    log: DeletionLog,
    *,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID | None = None,
    operator: str,
    environment: str,
) -> dict[str, Any]:
    """Delete and verify the stored objects of DELETING version(s), then record
    a receipt and a ``VERSION_OBJECT_PURGED`` event per version. Idempotent: a
    repeated purge deletes nothing and records fresh evidence."""
    if not operator.strip() or len(operator) > 64:
        raise TombstoneError("--operator must be a short operator label")
    if isinstance(log, UnconfiguredDeletionLog):
        # Checked BEFORE anything is deleted: physical deletion cannot be undone,
        # so it never happens without a place to record its receipt.
        raise TombstoneError(
            "no deletion log is configured (the external deletion log is a launch gate)"
        )
    with conn.transaction():
        ds = conn.execute(
            "SELECT tenant_id, status FROM datasets WHERE id = %s FOR UPDATE", (dataset_id,)
        ).fetchone()
        if ds is None:
            raise TombstoneError("no such dataset")
        tenant_id, ds_status = ds
        if version_id is None and ds_status != "DELETING":
            raise TombstoneError(f"dataset is {ds_status}, not DELETING")
        rows = conn.execute(
            "SELECT id, status, content_sha256, storage_object_key IS NOT NULL "
            "FROM dataset_versions WHERE dataset_id = %s "
            "AND (%s::uuid IS NULL OR id = %s::uuid) ORDER BY version_number FOR UPDATE",
            (dataset_id, version_id, version_id),
        ).fetchall()
        if version_id is not None and not rows:
            raise TombstoneError("no such version for this dataset")
        targets = [r for r in rows if r[1] == "DELETING"]
        if version_id is not None and not targets:
            raise TombstoneError(f"version is {rows[0][1]}, not DELETING")
        if store is None:
            if any(r[3] for r in targets):
                raise TombstoneError("no dataset store is configured: cannot purge objects")
            return {"dataset_id": str(dataset_id), "versions_purged": 0, "objects_deleted": 0}
        scoped = TenantScopedBlobStore(store, tenant_id)
        purged = deleted_total = 0
        for vid, _status, digest, has_key in targets:
            keys, verified = scoped.delete_version_and_verify(dataset_id, vid)
            if not verified:
                raise TombstoneError(f"objects of version {vid} could not be verified absent")
            if not has_key and not keys:
                continue  # nothing was ever stored for this version
            receipt = DeletionReceipt.for_version(
                sink=log.sink_id,
                environment=environment,
                tenant_id=tenant_id,
                dataset_id=dataset_id,
                version_id=vid,
                content_sha256=digest,
                deleted_keys=keys,
                operator=operator,
            )
            try:
                receipt_id = log.append(receipt)
            except DeletionLogUnavailable as exc:
                raise TombstoneError(str(exc)) from None
            # The purge evidence names its receipt: the tombstone verifies it.
            _event(
                conn,
                tenant_id,
                dataset_id,
                vid,
                EventType.VERSION_OBJECT_PURGED,
                "DELETING",
                to_status="DELETING",
                reason=ReasonCode.OPERATOR_PURGE,
                receipt=(log.sink_id, receipt_id, receipt.deletion_set_sha256),
            )
            purged += 1
            deleted_total += len(keys)
        if version_id is None and not scoped.delete_dataset_and_verify(dataset_id):
            raise TombstoneError("dataset objects could not be verified absent")
        return {
            "dataset_id": str(dataset_id),
            "versions_purged": purged,
            "objects_deleted": deleted_total,
        }


# --- tombstone -----------------------------------------------------------------


def _has_purge_evidence(conn: psycopg.Connection[Any], version_id: uuid.UUID) -> bool:
    row = conn.execute(
        "SELECT 1 FROM dataset_events WHERE version_id = %s "
        "AND event_type = 'VERSION_OBJECT_PURGED' LIMIT 1",
        (version_id,),
    ).fetchone()
    return row is not None


def _require_purged(
    conn: psycopg.Connection[Any],
    store: LocalBlobStore | None,
    log: DeletionLog,
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
) -> None:
    """A version whose bytes were ever stored may be tombstoned only after a
    purge recorded after its deletion request, a VERIFIED deletion receipt for
    exactly that purge, and a live check that nothing is stored for it."""
    evidence = conn.execute(
        "SELECT e.receipt_sink, e.receipt_id, e.receipt_digest, v.content_sha256, "
        "v.deletion_requested_at FROM dataset_events e "
        "JOIN dataset_versions v ON v.id = e.version_id "
        "WHERE e.version_id = %s AND e.event_type = 'VERSION_OBJECT_PURGED' "
        "AND e.actor_kind = 'operator' AND e.created_at >= v.deletion_requested_at "
        "ORDER BY e.created_at DESC LIMIT 1",
        (version_id,),
    ).fetchone()
    if evidence is None:
        raise TombstoneError(
            f"version {version_id} references a storage object that was not purged: run purge first"
        )
    if store is None:
        raise TombstoneError("no dataset store is configured: cannot verify object absence")
    if TenantScopedBlobStore(store, tenant_id).list_version(dataset_id, version_id):
        raise TombstoneError(f"objects of version {version_id} are still present: run purge")
    sink, receipt_id, digest, content_sha256, requested_at = evidence
    if sink != log.sink_id:
        raise TombstoneError(
            f"deletion receipt for version {version_id} is held by sink {sink!r}; "
            f"the configured verifier is {log.sink_id!r}"
        )
    check = log.verify(
        ExpectedReceipt(
            sink=sink,
            receipt_id=receipt_id,
            tenant_id=tenant_id,
            dataset_id=dataset_id,
            version_id=version_id,
            content_sha256=content_sha256,
            deletion_set_sha256=digest,
            not_before=requested_at,
        )
    )
    if check is not ReceiptCheck.VERIFIED:
        raise TombstoneError(
            f"deletion receipt for version {version_id} was not verified: {check.value}"
        )


def _scrub_derived(conn: psycopg.Connection[Any], version_id: uuid.UUID) -> None:
    conn.execute(
        "UPDATE dataset_profiles SET profile = NULL WHERE version_id = %s AND profile IS NOT NULL",
        (version_id,),
    )
    conn.execute(
        "UPDATE dataset_semantic_revisions SET mapping = NULL "
        "WHERE version_id = %s AND mapping IS NOT NULL",
        (version_id,),
    )


def _tombstone_versions(
    conn: psycopg.Connection[Any],
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_ids: list[uuid.UUID],
) -> int:
    for vid in version_ids:
        _scrub_derived(conn, vid)
        conn.execute(
            "UPDATE dataset_versions SET status = 'DELETED', original_filename = NULL, "
            "storage_object_key = NULL WHERE id = %s AND status = 'DELETING'",
            (vid,),
        )
        _event(conn, tenant_id, dataset_id, vid, EventType.VERSION_TOMBSTONED, "DELETING")
    return len(version_ids)


def tombstone(
    conn: psycopg.Connection[Any],
    *,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID | None = None,
    store: LocalBlobStore | None = None,
    log: DeletionLog | None = None,
) -> dict[str, Any]:
    """Tombstone one DELETING version, or a DELETING dataset with all its
    versions, in one transaction. Refuses anything not already DELETING and any
    version whose stored objects were not purged, verified absent, and backed
    by a verified deletion receipt."""
    log = log or UnconfiguredDeletionLog()
    with conn.transaction():
        ds = conn.execute(
            "SELECT tenant_id, status FROM datasets WHERE id = %s FOR UPDATE", (dataset_id,)
        ).fetchone()
        if ds is None:
            raise TombstoneError("no such dataset")
        tenant_id, ds_status = ds
        if version_id is not None:
            v = conn.execute(
                "SELECT status, storage_object_key IS NOT NULL FROM dataset_versions "
                "WHERE id = %s AND dataset_id = %s FOR UPDATE",
                (version_id, dataset_id),
            ).fetchone()
            if v is None:
                raise TombstoneError("no such version for this dataset")
            if v[0] != "DELETING":
                raise TombstoneError(f"version is {v[0]}, not DELETING")
            if v[1] or _has_purge_evidence(conn, version_id):
                _require_purged(conn, store, log, tenant_id, dataset_id, version_id)
            elif store is not None and TenantScopedBlobStore(store, tenant_id).list_version(
                dataset_id, version_id
            ):
                # No key was ever recorded, but a crashed upload may still have
                # linked (or partially written) bytes for this version.
                raise TombstoneError(
                    f"objects of version {version_id} are still present: run purge"
                )
            n = _tombstone_versions(conn, tenant_id, dataset_id, [version_id])
            return {"dataset_id": str(dataset_id), "versions_tombstoned": n, "dataset": ds_status}
        if ds_status != "DELETING":
            raise TombstoneError(f"dataset is {ds_status}, not DELETING")
        rows = conn.execute(
            "SELECT id, status, storage_object_key IS NOT NULL FROM dataset_versions "
            "WHERE dataset_id = %s ORDER BY version_number FOR UPDATE",
            (dataset_id,),
        ).fetchall()
        for vid, status, has_key in rows:
            if status == "DELETING" and (has_key or _has_purge_evidence(conn, vid)):
                _require_purged(conn, store, log, tenant_id, dataset_id, vid)
        if store is not None:
            scoped = TenantScopedBlobStore(store, tenant_id)
            if any(scoped.list_dataset(area, dataset_id) for area in AREAS):
                raise TombstoneError("objects of this dataset are still present: run purge")
        pending = [r[0] for r in rows if r[1] == "DELETING"]
        n = _tombstone_versions(conn, tenant_id, dataset_id, pending)
        conn.execute(
            "UPDATE datasets SET status = 'DELETED', name = NULL, normalized_name = NULL, "
            "description = NULL WHERE id = %s AND status = 'DELETING'",
            (dataset_id,),
        )
        _event(conn, tenant_id, dataset_id, None, EventType.DATASET_TOMBSTONED, "DELETING")
        return {"dataset_id": str(dataset_id), "versions_tombstoned": n, "dataset": "DELETED"}


def pending(conn: psycopg.Connection[Any]) -> list[tuple[Any, ...]]:
    """Datasets awaiting a tombstone: DELETING datasets, and live datasets that
    hold DELETING versions. Columns: tenant id, dataset id, dataset status,
    deletion requested at (NULL for a live dataset), DELETING version count.
    Ids, states and counts only."""
    return conn.execute(
        "SELECT d.tenant_id, d.id, d.status, d.deletion_requested_at, "
        "count(v.id) FILTER (WHERE v.status = 'DELETING') "
        "FROM datasets d LEFT JOIN dataset_versions v ON v.dataset_id = d.id "
        "GROUP BY d.tenant_id, d.id, d.status, d.deletion_requested_at "
        "HAVING d.status = 'DELETING' OR count(v.id) FILTER (WHERE v.status = 'DELETING') > 0 "
        "ORDER BY d.deletion_requested_at NULLS LAST, d.id"
    ).fetchall()


# --- ingest queue recovery (ADR-031) -------------------------------------------

_SQL_PENDING_REQUESTS = (
    "SELECT DISTINCT ON (r.version_id) r.id, r.tenant_id, r.dataset_id, r.version_id, "
    "r.content_sha256, r.envelope_sha256, "
    "(extract(epoch FROM r.requested_at) * 1000000)::bigint, "
    "r.requested_at > now() - make_interval(secs => %s) "
    "FROM dataset_processing_requests r JOIN dataset_versions v "
    "ON v.id = r.version_id AND v.tenant_id = r.tenant_id "
    "WHERE r.content_sha256 = v.content_sha256 AND (v.status = 'QUARANTINED' "
    "OR (v.status = 'PROFILING' AND (v.processing_lease_expires_at IS NULL "
    "OR v.processing_lease_expires_at < now()))) "
    "ORDER BY r.version_id, r.requested_at DESC"
)


def pending_envelopes(conn: psycopg.Connection[Any]) -> tuple[list[Any], int]:
    """(fresh envelopes to enqueue, count of waiting versions whose latest
    request is too old for the consumer). Ids and digests only."""
    from nlw.datasets.envelope import MAX_ENVELOPE_AGE_S, WorkEnvelope

    rows = conn.execute(_SQL_PENDING_REQUESTS, (MAX_ENVELOPE_AGE_S - 3600,)).fetchall()
    fresh = [
        WorkEnvelope(
            request_id=r[0],
            tenant_id=r[1],
            dataset_id=r[2],
            version_id=r[3],
            content_sha256=r[4],
            envelope_sha256=r[5],
            requested_at_us=int(r[6]),
        )
        for r in rows
        if r[7]
    ]
    return fresh, sum(1 for r in rows if not r[7])


def dispatch_pending(
    conn: psycopg.Connection[Any], broker: Any, *, dry_run: bool
) -> dict[str, int]:
    from nlw.datasets.envelope import enqueue_envelope

    fresh, stale = pending_envelopes(conn)
    if not dry_run:
        for env in fresh:
            enqueue_envelope(broker, env)
    return {"enqueued": 0 if dry_run else len(fresh), "pending": len(fresh), "stale": stale}


# --- restore validation --------------------------------------------------------


def verify_objects(conn: psycopg.Connection[Any], store: LocalBlobStore) -> dict[str, list[str]]:
    """Metadata/object consistency (ids only). Every list must be empty."""
    rows = conn.execute(
        "SELECT id, status, storage_object_key, content_sha256 "
        "FROM dataset_versions WHERE storage_object_key IS NOT NULL"
    ).fetchall()
    missing: list[str] = []
    mismatched: list[str] = []
    accounted: set[str] = set()
    for vid, status, key, digest in rows:
        accounted.add(key)
        if status in ("DELETING", "REJECTED"):
            continue  # bytes removed or awaiting purge: absence is expected
        if not store.exists(key):
            missing.append(str(vid))
            continue
        if store.digest(key)[1] != digest:
            mismatched.append(str(vid))
    orphaned = sorted(
        k.rsplit("/", 1)[-1] for area in AREAS for k in list_area(store, area) if k not in accounted
    )
    return {
        "missing_objects": sorted(missing),
        "digest_mismatches": sorted(mismatched),
        "unaccounted_objects": orphaned,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ops.datasets")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pending")
    sub.add_parser("verify-objects")
    dp = sub.add_parser("dispatch-pending")
    dp.add_argument("--dry-run", action="store_true")
    for name in ("purge", "tombstone"):
        sp = sub.add_parser(name)
        sp.add_argument("--dataset", required=True)
        sp.add_argument("--version", default=None)
        if name == "purge":
            sp.add_argument("--operator", required=True)
    args = p.parse_args(argv)
    settings = Settings()
    store = dataset_store(settings)
    try:
        with psycopg.connect(_owner_url(), autocommit=True) as conn:
            if args.cmd == "pending":
                for row in pending(conn):
                    print("\t".join(str(v) for v in row))
                return 0
            if args.cmd == "dispatch-pending":
                from dramatiq.brokers.redis import RedisBroker

                broker = None if args.dry_run else RedisBroker(url=settings.redis_url)  # type: ignore[no-untyped-call]
                result = dispatch_pending(conn, broker, dry_run=args.dry_run)
                print(" ".join(f"{k}={v}" for k, v in result.items()))
                return 0
            if args.cmd == "verify-objects":
                if store is None:
                    raise TombstoneError("no dataset store is configured")
                report = verify_objects(conn, store)
                for key, ids in report.items():
                    print(f"{key}={len(ids)}" + ("" if not ids else " " + ",".join(ids)))
                return 0 if not any(report.values()) else 1
            try:
                ds = uuid.UUID(args.dataset)
                ver = uuid.UUID(args.version) if args.version else None
            except ValueError as exc:
                raise TombstoneError("--dataset and --version must be UUIDs") from exc
            try:
                log = deletion_log_from_settings(
                    settings.dataset_deletion_log,
                    settings.dataset_deletion_log_path,
                    settings.app_env,
                )
            except DeletionLogUnavailable as exc:
                raise TombstoneError(str(exc)) from None
            if args.cmd == "purge":
                result = purge(
                    conn,
                    store,
                    log,
                    dataset_id=ds,
                    version_id=ver,
                    operator=args.operator,
                    environment=settings.app_env,
                )
            else:
                result = tombstone(conn, dataset_id=ds, version_id=ver, store=store, log=log)
            print(" ".join(f"{k}={v}" for k, v in result.items()))
            return 0
    except TombstoneError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
