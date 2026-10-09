"""Operator deletion and restore checks for datasets (ADR-029, ADR-030).

The runtime role can request deletion (-> DELETING) but can never write DELETED
(RLS) or the purge evidence event. The operator applies these steps with the
OWNER credential ``DATABASE_MIGRATION_URL``, exactly like ``python -m nlw.ops.grants``::

    python -m nlw.ops.datasets pending
    python -m nlw.ops.datasets purge --dataset <uuid> [--version <uuid>] --operator <name>
    python -m nlw.ops.datasets tombstone --dataset <uuid> [--version <uuid>]
    python -m nlw.ops.datasets verify-objects
    python -m nlw.ops.datasets dispatch-pending [--dry-run] [--limit N]
    python -m nlw.ops.datasets rejected-pending [--limit N] [--metrics-file PATH]
    python -m nlw.ops.datasets purge-rejected --operator <name> [--dry-run] [--limit N]

``rejected-pending`` / ``purge-rejected`` (ADR-033 D2): a rejected object stays
immutable (the ingest runtime deletes nothing) until the operator removes it.
``purge-rejected`` takes a bounded, oldest-first batch of REJECTED versions
that still reference an object, moves each to DELETING (operator event,
reason ``REJECTED_RETENTION``) and runs the same verified, version-aware purge
as a deletion request; it refuses while the recovery lock is active and is
idempotent (a re-run resumes versions a crash left between the two steps).
The 7-day alert threshold is PROVISIONAL (development/staging), not the O-5
retention policy.

``dispatch-pending`` is the operator recovery sweep for the ingest queue
(ADR-031): it (re)enqueues the work envelope of every committed, still fresh
processing request whose version is waiting (QUARANTINED, or PROFILING with an
expired or missing lease). The database rows are the work items; re-enqueueing
is harmless (the ingest runtime re-verifies each envelope and its lease makes
processing idempotent). Requests too old for the consumer are counted, not
sent: an admin re-dispatch records a fresh request. It processes nothing.

``purge`` physically deletes every stored item of the DELETING version(s)
(the ``versions/`` object with EVERY S3 version and delete marker, in-progress
multipart uploads, local partial files, and legacy development copies),
VERIFIES their absence, appends one receipt per version to the configured deletion log, and
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
from nlw.storage.blob import AREAS, BlobStore, TenantScopedBlobStore, item_key, list_area
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
    store: BlobStore | None,
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
    _require_runtimes_permitted(conn)
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


def _require_runtimes_permitted(conn: psycopg.Connection[Any]) -> None:
    """Physical deletion against a database whose restore is not enabled could
    remove bytes a restored version still references: refuse while the DR
    recovery lock is active or unreadable."""
    from nlw.backup.recovery_lock import (
        RecoveryLocked,
        RecoveryStateUnknown,
        check_recovery_lock_psycopg,
    )

    try:
        check_recovery_lock_psycopg(conn)
    except (RecoveryLocked, RecoveryStateUnknown) as exc:
        raise TombstoneError(
            f"refused: the recovery lock is active ({type(exc).__name__})"
        ) from None


# --- rejected objects (ADR-033 D2) -----------------------------------------------

REJECTED_BATCH = 100
# PROVISIONAL (development/staging, owner 2026-10-09): rejected objects must be
# purged within 7 days. The alert fires past it. NOT the O-5 retention policy.
REJECTED_ALERT_AFTER_S = 7 * 24 * 3600

_SQL_REJECTED = (
    "SELECT tenant_id, dataset_id, id, "
    "floor(extract(epoch FROM now() - rejected_at))::bigint "
    "FROM dataset_versions WHERE status = 'REJECTED' AND storage_object_key IS NOT NULL "
    "ORDER BY rejected_at, id LIMIT %s"
)
_SQL_REJECTED_STATS = (
    "SELECT count(*), coalesce(floor(extract(epoch FROM now() - min(rejected_at))), 0)::bigint "
    "FROM dataset_versions WHERE status = 'REJECTED' AND storage_object_key IS NOT NULL"
)
# Versions purge-rejected moved to DELETING but a crash left un-purged.
_SQL_REJECTED_RESUME = (
    "SELECT v.tenant_id, v.dataset_id, v.id FROM dataset_versions v "
    "WHERE v.status = 'DELETING' AND EXISTS (SELECT 1 FROM dataset_events e "
    "WHERE e.version_id = v.id AND e.event_type = 'VERSION_DELETION_REQUESTED' "
    "AND e.reason_code = 'REJECTED_RETENTION') AND NOT EXISTS (SELECT 1 FROM dataset_events p "
    "WHERE p.version_id = v.id AND p.event_type = 'VERSION_OBJECT_PURGED' "
    "AND p.created_at >= v.deletion_requested_at) "
    "ORDER BY v.deletion_requested_at, v.id LIMIT %s"
)


def _bounded(limit: int) -> int:
    if not 1 <= limit <= 10_000:
        raise TombstoneError("--limit must be between 1 and 10000")
    return limit


def rejected_stats(conn: psycopg.Connection[Any]) -> dict[str, int]:
    """Aggregate only: how many rejected objects are retained, the oldest's age."""
    row = conn.execute(_SQL_REJECTED_STATS).fetchone()
    retained, oldest = (int(row[0]), int(row[1])) if row else (0, 0)
    return {"retained": retained, "oldest_age_s": oldest}


def rejected_pending(
    conn: psycopg.Connection[Any], *, limit: int = REJECTED_BATCH
) -> list[tuple[Any, ...]]:
    """Rejected versions still referencing an object, oldest first (ids and
    age in seconds only)."""
    return conn.execute(_SQL_REJECTED, (_bounded(limit),)).fetchall()


def write_rejected_metrics(path: str, stats: dict[str, int]) -> None:
    """Prometheus textfile (node-exporter textfile collector), written
    atomically. Aggregates only: no workspace, dataset or version label."""
    text = (
        "# HELP nlw_dataset_rejected_retained Rejected dataset objects awaiting operator purge.\n"
        "# TYPE nlw_dataset_rejected_retained gauge\n"
        f"nlw_dataset_rejected_retained {stats['retained']}\n"
        "# HELP nlw_dataset_rejected_oldest_age_seconds Age of the oldest retained rejected "
        "object.\n"
        "# TYPE nlw_dataset_rejected_oldest_age_seconds gauge\n"
        f"nlw_dataset_rejected_oldest_age_seconds {stats['oldest_age_s']}\n"
    )
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def _move_rejected_to_deleting(
    conn: psycopg.Connection[Any], tenant_id: uuid.UUID, dataset_id: uuid.UUID, vid: uuid.UUID
) -> bool:
    with conn.transaction():
        row = conn.execute(
            "SELECT status FROM dataset_versions WHERE id = %s AND dataset_id = %s FOR UPDATE",
            (vid, dataset_id),
        ).fetchone()
        if row is None or row[0] != "REJECTED":
            return False  # a concurrent run or a user deletion got there first
        conn.execute(
            "UPDATE dataset_versions SET status = 'DELETING' WHERE id = %s AND status = 'REJECTED'",
            (vid,),
        )
        _event(
            conn,
            tenant_id,
            dataset_id,
            vid,
            EventType.VERSION_DELETION_REQUESTED,
            "REJECTED",
            to_status="DELETING",
            reason=ReasonCode.REJECTED_RETENTION,
        )
    return True


def purge_rejected(
    conn: psycopg.Connection[Any],
    store: BlobStore | None,
    log: DeletionLog,
    *,
    operator: str,
    environment: str,
    limit: int = REJECTED_BATCH,
    dry_run: bool = False,
) -> dict[str, int]:
    """Purge one bounded, oldest-first batch of retained rejected objects
    (ADR-033 D2). Idempotent; refused while the recovery lock is active."""
    limit = _bounded(limit)
    _require_runtimes_permitted(conn)
    resume = conn.execute(_SQL_REJECTED_RESUME, (limit,)).fetchall()
    fresh = rejected_pending(conn, limit=limit + 1)
    more = len(resume) + len(fresh) > limit
    batch = [(r[0], r[1], r[2], True) for r in resume]
    batch += [(r[0], r[1], r[2], False) for r in fresh[: max(0, limit - len(resume))]]
    if dry_run:
        return {"selected": len(batch), "moved": 0, "purged": 0, "more": int(more), "dry_run": 1}
    if isinstance(log, UnconfiguredDeletionLog):
        raise TombstoneError(
            "no deletion log is configured (the external deletion log is a launch gate)"
        )
    moved = purged = 0
    for tenant_id, dataset_id, vid, resumed in batch:
        if not resumed:
            if not _move_rejected_to_deleting(conn, tenant_id, dataset_id, vid):
                continue
            moved += 1
        result = purge(
            conn, store, log, dataset_id=dataset_id, version_id=vid,
            operator=operator, environment=environment,
        )  # fmt: skip
        purged += int(result["versions_purged"])
    return {"selected": len(batch), "moved": moved, "purged": purged, "more": int(more),
            "dry_run": 0}  # fmt: skip


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
    store: BlobStore | None,
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
    store: BlobStore | None = None,
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

# The latest request of each waiting version, oldest first, one bounded batch
# (deterministic order: request time, then version id).
_SQL_PENDING_REQUESTS = (
    "SELECT * FROM (SELECT DISTINCT ON (r.version_id) r.id, r.tenant_id, r.dataset_id, "
    "r.version_id, r.content_sha256, r.envelope_sha256, "
    "(extract(epoch FROM r.requested_at) * 1000000)::bigint AS requested_at_us, "
    "r.requested_at > now() - make_interval(secs => %s) AS fresh "
    "FROM dataset_processing_requests r JOIN dataset_versions v "
    "ON v.id = r.version_id AND v.tenant_id = r.tenant_id "
    "WHERE r.content_sha256 = v.content_sha256 AND (v.status = 'QUARANTINED' "
    "OR (v.status = 'PROFILING' AND (v.processing_lease_expires_at IS NULL "
    "OR v.processing_lease_expires_at < now()))) "
    "ORDER BY r.version_id, r.requested_at DESC) latest "
    "ORDER BY requested_at_us, version_id LIMIT %s"
)
SWEEP_BATCH = 500


def pending_envelopes(
    conn: psycopg.Connection[Any], *, limit: int = SWEEP_BATCH
) -> tuple[list[Any], int, bool]:
    """(fresh envelopes to enqueue, count of waiting versions whose latest
    request is too old for the consumer, whether more remain beyond ``limit``)
    for the ``limit`` oldest waiting versions. Ids and digests only."""
    from nlw.datasets.envelope import MAX_ENVELOPE_AGE_S, WorkEnvelope

    if not 1 <= limit <= 10_000:
        raise ValueError("limit must be between 1 and 10000")
    rows = conn.execute(_SQL_PENDING_REQUESTS, (MAX_ENVELOPE_AGE_S - 3600, limit + 1)).fetchall()
    more, rows = len(rows) > limit, rows[:limit]
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
    return fresh, sum(1 for r in rows if not r[7]), more


# One sweep at a time (a session advisory lock): a concurrent sweep reports
# ``busy=1`` and sends nothing. Overlapping sends would be harmless anyway (the
# consumer re-verifies every envelope; the lease settles a version once).
_SQL_SWEEP_LOCK = "SELECT pg_try_advisory_lock(hashtext('nlw.ops.datasets.dispatch_pending'))"
_SQL_SWEEP_UNLOCK = "SELECT pg_advisory_unlock(hashtext('nlw.ops.datasets.dispatch_pending'))"


def dispatch_pending(
    conn: psycopg.Connection[Any], broker: Any, *, dry_run: bool, limit: int = SWEEP_BATCH
) -> dict[str, int]:
    """Enqueue one bounded batch (the ``limit`` oldest waiting versions);
    ``more=1`` means run it again. An enqueue failure stops the sweep and
    raises: nothing in the database changes, so a rerun is always safe."""
    from nlw.datasets.envelope import enqueue_envelope

    row = conn.execute(_SQL_SWEEP_LOCK).fetchone()
    if not (row and row[0]):
        return {"enqueued": 0, "pending": 0, "stale": 0, "more": 0, "busy": 1}
    try:
        fresh, stale, more = pending_envelopes(conn, limit=limit)
        if not dry_run:
            for env in fresh:
                enqueue_envelope(broker, env)
    finally:
        conn.execute(_SQL_SWEEP_UNLOCK)
    return {
        "enqueued": 0 if dry_run else len(fresh),
        "pending": len(fresh),
        "stale": stale,
        "more": int(more),
        "busy": 0,
    }


# --- restore validation --------------------------------------------------------


def verify_objects(conn: psycopg.Connection[Any], store: BlobStore) -> dict[str, list[str]]:
    """Metadata/object consistency (ids only). Every list must be empty except
    ``noncurrent_versions`` (expected on S3 until O-5 sets noncurrent expiry,
    reported for visibility). REJECTED objects are retained until
    ``purge-rejected`` (D2): their presence or absence is not an error."""
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
    items = [item for area in AREAS for item in list_area(store, area)]
    current = {item_key(i) for i in items if "#u=" not in i and "#m=" not in i}
    orphaned = sorted({_object_id(item_key(i)) for i in items if item_key(i) not in accounted})
    # S3: more than one version (or a delete marker) of an accounted key.
    seen: dict[str, int] = {}
    for i in items:
        if "#" in i and "#u=" not in i:
            seen[item_key(i)] = seen.get(item_key(i), 0) + 1
    noncurrent = sorted(_object_id(k) for k, n in seen.items() if n > 1 and k in current)
    return {
        "missing_objects": sorted(missing),
        "digest_mismatches": sorted(mismatched),
        "unaccounted_objects": orphaned,
        "noncurrent_versions": noncurrent,
    }


def _object_id(key: str) -> str:
    """The version id a key names (ids only in output)."""
    parts = key.split("/")
    return parts[3] if len(parts) > 3 else parts[-1]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ops.datasets")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pending")
    sub.add_parser("verify-objects")
    dp = sub.add_parser("dispatch-pending")
    dp.add_argument("--dry-run", action="store_true")
    dp.add_argument("--limit", type=int, default=SWEEP_BATCH)
    rp = sub.add_parser("rejected-pending")
    rp.add_argument("--limit", type=int, default=REJECTED_BATCH)
    rp.add_argument("--metrics-file", default=None)
    pr = sub.add_parser("purge-rejected")
    pr.add_argument("--operator", required=True)
    pr.add_argument("--dry-run", action="store_true")
    pr.add_argument("--limit", type=int, default=REJECTED_BATCH)
    for name in ("purge", "tombstone"):
        sp = sub.add_parser(name)
        sp.add_argument("--dataset", required=True)
        sp.add_argument("--version", default=None)
        if name == "purge":
            sp.add_argument("--operator", required=True)
    args = p.parse_args(argv)
    settings = Settings()
    try:
        with psycopg.connect(_owner_url(), autocommit=True) as conn:
            if args.cmd == "rejected-pending":
                stats = rejected_stats(conn)
                for row in rejected_pending(conn, limit=args.limit):
                    print("\t".join(str(v) for v in row))
                print(f"retained={stats['retained']} oldest_age_s={stats['oldest_age_s']}")
                if args.metrics_file:
                    write_rejected_metrics(args.metrics_file, stats)
                return 0
            if args.cmd == "pending":
                for row in pending(conn):
                    print("\t".join(str(v) for v in row))
                return 0
            if args.cmd == "dispatch-pending":
                from dramatiq.brokers.redis import RedisBroker

                broker = None if args.dry_run else RedisBroker(url=settings.redis_url)  # type: ignore[no-untyped-call]
                result = dispatch_pending(conn, broker, dry_run=args.dry_run, limit=args.limit)
                print(" ".join(f"{k}={v}" for k, v in result.items()))
                return 0
            store = dataset_store(settings, service="operator")
            if args.cmd == "verify-objects":
                if store is None:
                    raise TombstoneError("no dataset store is configured")
                report = verify_objects(conn, store)
                for key, ids in report.items():
                    print(f"{key}={len(ids)}" + ("" if not ids else " " + ",".join(ids)))
                return 0 if not any(report.values()) else 1
            try:
                log = deletion_log_from_settings(
                    settings.dataset_deletion_log,
                    settings.dataset_deletion_log_path,
                    settings.app_env,
                )
            except DeletionLogUnavailable as exc:
                raise TombstoneError(str(exc)) from None
            if args.cmd == "purge-rejected":
                rej = purge_rejected(
                    conn, store, log, operator=args.operator, environment=settings.app_env,
                    limit=args.limit, dry_run=args.dry_run,
                )  # fmt: skip
                print(" ".join(f"{k}={v}" for k, v in rej.items()))
                return 0
            try:
                ds = uuid.UUID(args.dataset)
                ver = uuid.UUID(args.version) if args.version else None
            except ValueError as exc:
                raise TombstoneError("--dataset and --version must be UUIDs") from exc
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
