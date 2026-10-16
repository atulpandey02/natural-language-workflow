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
    python -m nlw.ops.datasets reconcile-receipts [--metrics-file PATH]
    python -m nlw.ops.datasets reapply-receipts [--dry-run]
    python -m nlw.ops.datasets restore-objects [--dry-run] [--limit N] [--after VERSION_ID]
    python -m nlw.ops.datasets retention-status [--metrics-file PATH]
    python -m nlw.ops.datasets retention-sweep --operator <name> [--dry-run] [--limit N]
                                              [--metrics-file PATH]

``retention-sweep`` / ``retention-status`` apply and report the O-5 retention
policy (ADR-035; ``nlw.ops.dataset_retention``).

``restore-objects`` (O-4, ADR-036) is a RESTORE step, after ``reapply-receipts``
and before ``enable-runtime``: it copies back, from the bucket AWS Backup
restored a point in time into, each object the restored database still
references (never a DELETING, DELETED or REJECTED version), verified against
its recorded SHA-256 before it is written write-once. Present objects are left
alone; a mismatch is reported, never overwritten. It runs as the restore role
(``nlw-<env>-dataset-restore``), which reads the deletion log but never writes
it; each run is one bounded page, continued with ``--after <next>``.

``reconcile-receipts`` (ADR-034) checks every recorded purge against its
receipt in the configured deletion log, and lists receipts no purge event names
(expected after a purge that failed after its receipt was written, ADR-033
note 3). ``reapply-receipts`` is a RESTORE step: it runs only while the
recovery lock holds a restored database, before any runtime starts. Every
receipt in the external log proves a version's bytes were deleted; a restored
database that predates the deletion may still show that version as usable, or
as DELETING without its purge evidence. It moves such a version to DELETING
and records the receipt as its purge evidence (reason ``RESTORE_REAPPLY``),
reports a version whose content digest differs from the receipt (never
changed), and is idempotent.

``rejected-pending`` / ``purge-rejected`` (ADR-033 D2): a rejected object stays
immutable (the ingest runtime deletes nothing) until the operator removes it.
``purge-rejected`` takes a bounded, oldest-first batch of REJECTED versions
that still reference an object, moves each to DELETING (operator event,
reason ``REJECTED_RETENTION``) and runs the same verified, version-aware purge
as a deletion request; it refuses while the recovery lock is active and is
idempotent (a re-run resumes versions a crash left between the two steps).
The 7-day deadline is the O-5 retention policy (ADR-035); ``retention-sweep``
runs the same purge for rejected, inactive and logically deleted versions.

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
import re
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

import psycopg
from pydantic import ValidationError

from nlw.backup.recovery_lock import RecoveryLocked, RecoveryStateUnknown
from nlw.core.config import Settings
from nlw.core.retention import DAY_S, REJECTED_PURGE_DAYS
from nlw.datasets.deletion_log import (
    DeletionLog,
    DeletionLogUnavailable,
    DeletionReceipt,
    ExpectedReceipt,
    ReceiptCheck,
    ReceiptRef,
    UnconfiguredDeletionLog,
    check_receipt,
    deletion_log_from_settings,
)
from nlw.datasets.lifecycle import ActorKind, EventType, ReasonCode
from nlw.storage.blob import (
    AREAS,
    BlobStore,
    BlobUnavailable,
    TenantScopedBlobStore,
    item_key,
    list_area,
)
from nlw.storage.factory import dataset_store
from nlw.storage.s3_credentials import CredentialError


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
    repeated purge deletes nothing new; it records a fresh receipt and event
    for a version with a recorded key, and nothing for a version without one
    when nothing is stored or no store is configured (ADR-033 note 3)."""
    if not operator.strip() or len(operator) > 64:
        raise TombstoneError("--operator must be a short operator label")
    # Checked BEFORE anything is deleted: physical deletion cannot be undone, so
    # it never happens without a working place to record (and protect) its receipt.
    _preflight(log)
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


def _preflight(log: DeletionLog) -> None:
    try:
        log.preflight()
    except DeletionLogUnavailable as exc:
        raise TombstoneError(str(exc)) from None


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
# O-5 (ADR-035): rejected objects are purged within 7 days; the alert fires past it.
REJECTED_ALERT_AFTER_S = REJECTED_PURGE_DAYS * DAY_S

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
    _preflight(log)
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
        "v.deletion_requested_at, e.reason_code FROM dataset_events e "
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
    sink, receipt_id, digest, content_sha256, requested_at, reason = evidence
    if sink != log.sink_id:
        raise TombstoneError(
            f"deletion receipt for version {version_id} is held by another sink "
            f"({sink_kind(sink)}); the configured verifier is {sink_kind(log.sink_id)}"
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
            not_before=_not_before(requested_at, reason),
        )
    )
    if check is not ReceiptCheck.VERIFIED:
        raise TombstoneError(
            f"deletion receipt for version {version_id} was not verified: {check.value}"
        )


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def sink_kind(sink: str) -> str:
    """A sink's kind for operator output: an S3 sink id names its bucket (and
    so the AWS account), which is never printed."""
    if sink.startswith("s3."):
        return "s3"
    return sink if sink in ("local-fake", "unconfigured") else "other"


def _not_before(requested_at: datetime, reason: str | None) -> datetime:
    """A receipt must postdate the deletion request it answers, except one
    re-applied after a restore (``RESTORE_REAPPLY``): its deletion happened in
    the timeline the restored database forgot, so it necessarily predates the
    request the restore re-created. Identity, digests and live absence are
    still checked."""
    return _EPOCH if reason == ReasonCode.RESTORE_REAPPLY.value else requested_at


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
    # A restored database is not tombstoned before its deletions are re-applied
    # (reapply-receipts) and its runtimes are enabled.
    _require_runtimes_permitted(conn)
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


# --- deletion receipts: reconciliation and restore re-application (ADR-034) -----

_SQL_PURGE_EVIDENCE = (
    "SELECT e.version_id, e.tenant_id, e.dataset_id, e.receipt_sink, e.receipt_id, "
    "e.receipt_digest, v.content_sha256, v.deletion_requested_at, e.reason_code "
    "FROM dataset_events e JOIN dataset_versions v ON v.id = e.version_id "
    "WHERE e.event_type = 'VERSION_OBJECT_PURGED' ORDER BY e.created_at, e.id"
)


def reconcile_receipts(conn: psycopg.Connection[Any], log: DeletionLog) -> dict[str, Any]:
    """Every purge event checked against its receipt, and every receipt no event
    names (ids only). ``unverified`` entries are ``<version>:<check>``. Problems
    (the command exits 1): ``unverified``, ``other_sink``, and
    ``unexpected_objects`` (objects in the log that are not receipts: never
    read, only counted). A receipt without an event is the documented trace of
    a purge that failed after writing it (ADR-033 note 3), not a problem.
    A malformed or malicious receipt is reported as unverified; it never stops
    the check of the others."""
    unverified: list[str] = []
    other_sink: list[str] = []
    named: set[str] = set()
    for vid, tid, did, sink, rid, digest, content, requested, reason in conn.execute(
        _SQL_PURGE_EVIDENCE
    ).fetchall():
        if sink != log.sink_id:
            other_sink.append(str(vid))
            continue
        named.add(rid)
        check = log.verify(
            ExpectedReceipt(
                sink=sink, receipt_id=rid, tenant_id=tid, dataset_id=did, version_id=vid,
                content_sha256=content, deletion_set_sha256=digest,
                not_before=_not_before(requested, reason),
            )
        )  # fmt: skip
        if check is not ReceiptCheck.VERIFIED:
            unverified.append(f"{vid}:{check.value}")
    try:
        refs = sorted(log.refs())
    except DeletionLogUnavailable as exc:
        raise TombstoneError(str(exc)) from None
    without_event = sorted({str(r.version_id) for r in refs if r.receipt_id not in named})
    unexpected = log.unexpected_objects
    from nlw.ops.workspace_offboarding import reconcile_workspace_receipts

    workspaces = reconcile_workspace_receipts(conn, log)
    return {
        "unverified": sorted(unverified),
        "other_sink": sorted(other_sink),
        "receipts_without_event": without_event,
        **workspaces,
        "unexpected_objects": max(unexpected, log.unexpected_objects),
    }


def reconcile_failed(report: dict[str, Any]) -> bool:
    return bool(
        report["unverified"]
        or report["other_sink"]
        or report["unexpected_objects"]
        or report.get("workspace_unverified")
    )


def _self_consistent(record: dict[str, Any], ref: ReceiptRef, sink: str) -> bool:
    """A receipt is re-applied only if it is well formed, filed where it says it
    belongs, from this sink, and its digest recomputes."""
    try:
        expected = ExpectedReceipt(
            sink=sink,
            receipt_id=ref.receipt_id,
            tenant_id=ref.tenant_id,
            dataset_id=ref.dataset_id,
            version_id=ref.version_id,
            content_sha256=record["content_sha256"],
            deletion_set_sha256=record["deletion_set_sha256"],
            not_before=_EPOCH,
        )
    except (KeyError, TypeError):
        return False
    return (
        record.get("receipt_id") == ref.receipt_id
        and check_receipt(record, expected) is ReceiptCheck.VERIFIED
    )


def _require_recovery_locked(conn: psycopg.Connection[Any], command: str) -> None:
    from nlw.backup.recovery_lock import (
        RecoveryLocked,
        RecoveryStateUnknown,
        check_recovery_lock_psycopg,
    )

    try:
        check_recovery_lock_psycopg(conn)
    except RecoveryLocked:
        return
    except RecoveryStateUnknown:
        raise TombstoneError("refused: the recovery lock state is unknown") from None
    raise TombstoneError(f"{command} runs only while the recovery lock holds a restored database")


_REAPPLY_COUNTS = (
    "receipts", "reapplied", "recorded", "already_recorded", "already_tombstoned", "absent",
)  # fmt: skip


def reapply_receipts(
    conn: psycopg.Connection[Any],
    log: DeletionLog,
    *,
    dry_run: bool = False,
    progress: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Re-apply every deletion receipt to a restored database (see the module
    docstring). Counts, plus version ids for ``conflict`` and ``unreadable``,
    and ``unexpected_objects``; any of those three makes the command exit 1.

    The log is listed IN FULL before anything changes: a listing that fails
    or is not what was asked for changes nothing. Each receipt is then applied
    in its own transaction; ``progress`` (if given) holds the counts so far, so
    a run stopped by an operational failure reports its partial progress as
    counts only. Re-running is safe (idempotent)."""
    _require_recovery_locked(conn, "reapply-receipts")
    try:
        refs = sorted(set(log.refs()))
    except DeletionLogUnavailable as exc:
        raise TombstoneError(str(exc)) from None
    counts = progress if progress is not None else {}
    counts.update(dict.fromkeys(_REAPPLY_COUNTS, 0))
    conflict: list[str] = []
    unreadable: list[str] = []
    for ref in refs:
        counts["receipts"] += 1
        try:
            record = log.read(ref)
        except DeletionLogUnavailable:
            record = None
        if record is None or not _self_consistent(record, ref, log.sink_id):
            unreadable.append(str(ref.version_id))
            continue
        outcome = _reapply_one(conn, log, ref, record, dry_run=dry_run)
        if outcome == "conflict":
            conflict.append(str(ref.version_id))
        else:
            counts[outcome] += 1
    unexpected = log.unexpected_objects
    # ADR-037: an offboarded workspace a restore brought back is blocked again.
    from nlw.ops.workspace_offboarding import reapply_workspace_receipts

    workspaces = reapply_workspace_receipts(conn, log, dry_run=dry_run)
    return {
        **counts,
        "conflict": sorted(set(conflict)),
        "unreadable": sorted(set(unreadable)),
        **workspaces,
        "unexpected_objects": max(unexpected, log.unexpected_objects),
        "dry_run": int(dry_run),
    }


def reapply_failed(result: dict[str, Any]) -> bool:
    return bool(
        result["conflict"]
        or result["unreadable"]
        or result["unexpected_objects"]
        or result.get("workspace_unreadable")
    )


def _reapply_one(
    conn: psycopg.Connection[Any],
    log: DeletionLog,
    ref: ReceiptRef,
    record: dict[str, Any],
    *,
    dry_run: bool,
) -> str:
    with conn.transaction():
        row = conn.execute(
            "SELECT v.status, v.content_sha256, d.active_version_id FROM dataset_versions v "
            "JOIN datasets d ON d.id = v.dataset_id AND d.tenant_id = v.tenant_id "
            "WHERE v.id = %s AND v.dataset_id = %s AND v.tenant_id = %s FOR UPDATE OF v, d",
            (ref.version_id, ref.dataset_id, ref.tenant_id),
        ).fetchone()
        if row is None:
            return "absent"  # created after the restored snapshot
        status, content, active = row
        if status == "DELETED":
            return "already_tombstoned"
        if content != record["content_sha256"]:
            return "conflict"  # never altered: the operator investigates
        evidence = (log.sink_id, ref.receipt_id, record["deletion_set_sha256"])
        recorded = conn.execute(
            "SELECT 1 FROM dataset_events WHERE version_id = %s "
            "AND event_type = 'VERSION_OBJECT_PURGED' AND receipt_id = %s",
            (ref.version_id, ref.receipt_id),
        ).fetchone()
        if status == "DELETING" and recorded is not None:
            return "already_recorded"
        if dry_run:
            return "recorded" if status == "DELETING" else "reapplied"
        outcome = "recorded"
        if status != "DELETING":
            conn.execute(
                "UPDATE dataset_versions SET status = 'DELETING' WHERE id = %s AND status = %s",
                (ref.version_id, status),
            )
            if active == ref.version_id:
                conn.execute(
                    "UPDATE datasets SET active_version_id = NULL "
                    "WHERE id = %s AND active_version_id = %s",
                    (ref.dataset_id, ref.version_id),
                )
            _event(
                conn, ref.tenant_id, ref.dataset_id, ref.version_id,
                EventType.VERSION_DELETION_REQUESTED, status, to_status="DELETING",
                reason=ReasonCode.RESTORE_REAPPLY,
            )  # fmt: skip
            outcome = "reapplied"
        _event(
            conn, ref.tenant_id, ref.dataset_id, ref.version_id,
            EventType.VERSION_OBJECT_PURGED, "DELETING", to_status="DELETING",
            reason=ReasonCode.RESTORE_REAPPLY, receipt=evidence,
        )  # fmt: skip
        return outcome


# --- object restore (O-4, ADR-036) ------------------------------------------------

RESTORE_BATCH = 500
_SQL_RESTORE_CANDIDATES = (
    "SELECT id, status, storage_object_key, content_sha256, declared_size_bytes "
    "FROM dataset_versions WHERE storage_object_key IS NOT NULL "
    "AND status NOT IN ('DELETING', 'DELETED') "
    "AND (%(after)s::uuid IS NULL OR (created_at, id) > "
    "(SELECT created_at, id FROM dataset_versions WHERE id = %(after)s::uuid)) "
    "ORDER BY created_at, id LIMIT %(limit)s"
)
_LIVE = ("QUARANTINED", "PROFILING", "PROFILED", "ACTIVE", "SUPERSEDED", "REJECTED")


def _require_receipts_reapplied(conn: psycopg.Connection[Any], log: DeletionLog) -> None:
    """Every deletion the external log proves must already be re-applied, so a
    purged object can never be resurrected by a backup taken before its purge."""
    if isinstance(log, UnconfiguredDeletionLog):
        return  # no log: no purge was ever possible in this environment
    try:
        refs = list(log.refs())
    except DeletionLogUnavailable as exc:
        raise TombstoneError(str(exc)) from None
    for ref in refs:
        row = conn.execute(
            "SELECT status FROM dataset_versions WHERE id = %s AND dataset_id = %s "
            "AND tenant_id = %s",
            (ref.version_id, ref.dataset_id, ref.tenant_id),
        ).fetchone()
        if row is not None and row[0] in _LIVE:
            raise TombstoneError(
                "a deletion receipt is not yet re-applied: run reapply-receipts first"
            )


def restore_objects(
    conn: psycopg.Connection[Any],
    source: BlobStore,
    dest: BlobStore,
    log: DeletionLog,
    *,
    max_bytes: int,
    dry_run: bool = False,
    limit: int = RESTORE_BATCH,
    after: str | None = None,
) -> dict[str, Any]:
    """Copy missing objects back from the restore bucket (see the module
    docstring). One bounded page, oldest first, after version ``after``;
    ``next`` is the cursor for the following page (empty when none is left).
    Idempotent (a present, matching object counts as ``present``). Counts,
    plus version ids for every case an operator must look at."""
    limit = _bounded(limit)
    _require_recovery_locked(conn, "restore-objects")
    _require_receipts_reapplied(conn, log)
    if after is not None:
        try:
            after = str(uuid.UUID(after))
        except ValueError:
            raise TombstoneError("--after must be a version id") from None
        if (
            conn.execute("SELECT 1 FROM dataset_versions WHERE id = %s", (after,)).fetchone()
            is None
        ):
            raise TombstoneError("--after names no dataset version")
    rows = conn.execute(_SQL_RESTORE_CANDIDATES, {"after": after, "limit": limit + 1}).fetchall()
    more, rows = len(rows) > limit, rows[:limit]
    cursor = str(rows[-1][0]) if more else ""
    counts = dict.fromkeys(("present", "restored", "rejected_skipped"), 0)
    problems: dict[str, list[str]] = {
        "missing_in_backup": [],
        "backup_mismatch": [],
        "present_mismatch": [],
        "no_digest": [],
    }
    for vid, status, key, digest, size in rows:
        if status == "REJECTED":
            counts["rejected_skipped"] += 1  # purged by retention, never restored
            continue
        if digest is None:
            problems["no_digest"].append(str(vid))
            continue
        if dest.exists(key):
            bucket = "present" if dest.digest(key)[1] == digest else "present_mismatch"
            if bucket == "present":
                counts["present"] += 1
            else:
                problems["present_mismatch"].append(str(vid))
            continue
        if not source.exists(key):
            problems["missing_in_backup"].append(str(vid))
            continue
        if source.digest(key) != (size, digest):
            problems["backup_mismatch"].append(str(vid))
            continue
        if dry_run:
            counts["restored"] += 1
            continue
        with source.open(key) as stream:
            written = dest.put_stream(key, stream, max_bytes=max_bytes, expected_size=size)
        if written != (size, digest):  # pragma: no cover - verified before writing
            problems["present_mismatch"].append(str(vid))
            continue
        counts["restored"] += 1
    return {**counts, **problems, "more": int(more), "next": cursor, "dry_run": int(dry_run)}


def restore_failed(result: dict[str, Any]) -> bool:
    return any(
        result[k] for k in ("missing_in_backup", "backup_mismatch", "present_mismatch", "no_digest")
    )


# --- restore validation --------------------------------------------------------


def verify_objects(conn: psycopg.Connection[Any], store: BlobStore) -> dict[str, list[str]]:
    """Metadata/object consistency (ids only). Every list must be empty except
    ``noncurrent_versions`` (expected on S3 for up to 30 days, O-5 noncurrent expiry,
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


def configured_deletion_log(settings: Settings) -> DeletionLog:
    """The deletion log for the operator commands. ``s3`` runs as the verified
    operator role (``nlw-<env>-dataset-operator``) with the pinned credential
    file, exactly like the dataset store; it never uses another identity."""
    if settings.dataset_deletion_log != "s3":
        return deletion_log_from_settings(
            settings.dataset_deletion_log, settings.dataset_deletion_log_path, settings.app_env
        )
    from nlw.datasets.deletion_log_s3 import S3DeletionLog
    from nlw.storage.s3_credentials import (
        build_operator_clients,
        expected_role,
        verify_role_path,
    )

    assert settings.dataset_deletion_log_bucket and settings.dataset_s3_bucket  # validated
    try:
        client, iam, _ = build_operator_clients(settings)
    except CredentialError as exc:
        raise DeletionLogUnavailable(str(exc)) from None
    role_name, _account = expected_role(settings.dataset_s3_bucket, "operator")

    def role_check() -> None:
        try:
            verify_role_path(iam, role_name)
        except CredentialError as exc:
            raise DeletionLogUnavailable(str(exc)) from None

    return S3DeletionLog(client, settings.dataset_deletion_log_bucket, role_check=role_check)


def _configured_log(settings: Settings) -> DeletionLog:
    try:
        return configured_deletion_log(settings)
    except DeletionLogUnavailable as exc:
        raise TombstoneError(str(exc)) from None


def restore_receipt_log(settings: Settings) -> DeletionLog:
    """The deletion log as the restore role reads it: listing only, never a
    write (the restore role is granted no receipt write, ADR-036)."""
    if settings.dataset_deletion_log != "s3":
        return _configured_log(settings)
    from nlw.datasets.deletion_log_s3 import S3DeletionLog
    from nlw.storage.s3_credentials import build_clients

    assert settings.dataset_deletion_log_bucket  # validated
    try:
        client, _ = build_clients(settings, "restore")
    except CredentialError as exc:
        raise TombstoneError(str(exc)) from None
    return S3DeletionLog(client, settings.dataset_deletion_log_bucket)


def _restore_objects_cli(
    args: argparse.Namespace, conn: psycopg.Connection[Any], settings: Settings
) -> int:
    from nlw.storage.factory import restore_source_store

    if settings.dataset_storage_backend != "s3" or not settings.dataset_restore_bucket:
        raise TombstoneError(
            "restore-objects needs the S3 dataset store and DATASET_RESTORE_BUCKET"
        )
    source = restore_source_store(settings)
    dest = dataset_store(settings, service="restore")
    assert source is not None and dest is not None
    result = restore_objects(
        conn, source, dest, restore_receipt_log(settings),
        max_bytes=settings.dataset_max_upload_bytes, dry_run=args.dry_run,
        limit=args.limit, after=args.after,
    )  # fmt: skip
    print(_summary(result))
    return 1 if restore_failed(result) else 0


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
    rr = sub.add_parser("reconcile-receipts")
    rr.add_argument("--metrics-file", default=None)
    ra = sub.add_parser("reapply-receipts")
    ra.add_argument("--dry-run", action="store_true")
    ro = sub.add_parser("restore-objects")
    ro.add_argument("--dry-run", action="store_true")
    ro.add_argument("--limit", type=int, default=RESTORE_BATCH)
    ro.add_argument("--after", default=None)
    rs = sub.add_parser("retention-status")
    rs.add_argument("--metrics-file", default=None)
    sw = sub.add_parser("retention-sweep")
    sw.add_argument("--operator", required=True)
    sw.add_argument("--dry-run", action="store_true")
    sw.add_argument("--limit", type=int, default=100)
    sw.add_argument("--metrics-file", default=None)
    for name in ("purge", "tombstone"):
        sp = sub.add_parser(name)
        sp.add_argument("--dataset", required=True)
        sp.add_argument("--version", default=None)
        if name == "purge":
            sp.add_argument("--operator", required=True)
    args = p.parse_args(argv)
    progress: dict[str, int] = {}
    try:
        return _run(args, progress)
    except TombstoneError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValidationError as exc:
        print(f"error: invalid configuration: {config_reasons(exc, Settings)}", file=sys.stderr)
        return 2
    except SAFE_MESSAGE_TYPES as exc:
        # A known operational failure whose message is written by this code
        # (pinned by tests/unit/test_operator_diagnostics.py). It is still
        # checked: anything that looks like an identifier falls back to the class.
        print(
            f"error: {args.cmd} stopped: {safe_message(exc)}. It is safe to re-run.",
            file=sys.stderr,
        )
        if progress:
            print("partial " + " ".join(f"{k}={v}" for k, v in progress.items()), file=sys.stderr)
        return 3
    except Exception as exc:
        # An operational failure (database, network, storage). Its text can
        # carry hosts, bucket names, keys or row values, so only its class is
        # printed; partial progress is reported as counts.
        print(
            f"error: {args.cmd} stopped by an unexpected {type(exc).__name__}; "
            "details are not printed. It is safe to re-run.",
            file=sys.stderr,
        )
        if progress:
            print("partial " + " ".join(f"{k}={v}" for k, v in progress.items()), file=sys.stderr)
        return 3


# Exception types whose messages are author-controlled: fixed text, AWS error
# codes, enum values and role NAMES only (never a value, key, bucket, account,
# path or credential). Pinned at every raise site by an AST test.
SAFE_MESSAGE_TYPES: tuple[type[BaseException], ...] = (
    CredentialError,
    BlobUnavailable,
    DeletionLogUnavailable,
    RecoveryLocked,
    RecoveryStateUnknown,
)
# Defence in depth: a "safe" message that still looks like it carries an
# identifier, a location or a secret is reduced to its class.
_UNSAFE = re.compile(
    r"\d{12}|arn:|://|@|AKIA|ASIA|(?i:secret|password|passwd|token=|session_token)"
    r"|nlw-[a-z]+-(?:datasets|deletion-receipts|dataset-audit)-"
    r"|(?:receipts|versions|quarantine)/|(?:^|\s)/[A-Za-z0-9._-]"
    r"|(?i:\b(?:select|insert|update|delete)\b[^.]*\b(?:from|into|set|where)\b)"
)
_MAX_MESSAGE = 200


def safe_message(exc: BaseException) -> str:
    text = str(exc)
    if not text or len(text) > _MAX_MESSAGE or "\n" in text or _UNSAFE.search(text):
        return f"{type(exc).__name__} (details withheld)"
    return f"{type(exc).__name__}: {text}"


def config_reasons(exc: ValidationError, model: type[Any]) -> str:
    """Each error as ``SETTING: reason``. The setting is named (its environment
    variable); the rejected input is never echoed (pydantic's own rendering
    would include it)."""
    out = []
    for e in exc.errors():
        name = setting_name(model, e.get("loc") or ())
        msg = str(e.get("msg", "invalid")).removeprefix("Value error, ")
        out.append(f"{name}: {msg}" if name else msg)
    return "; ".join(out)


def setting_name(model: type[Any], loc: tuple[Any, ...]) -> str:
    if not loc:
        return ""
    field = model.model_fields.get(str(loc[0]))
    alias = getattr(field, "validation_alias", None) or getattr(field, "alias", None)
    return str(alias) if isinstance(alias, str) and alias else str(loc[0]).upper()


def _run(args: argparse.Namespace, progress: dict[str, int]) -> int:
    settings = Settings()
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
        if args.cmd in ("reconcile-receipts", "reapply-receipts"):
            log = _configured_log(settings)
            if args.cmd == "reconcile-receipts":
                report = reconcile_receipts(conn, log)
                print(_summary(report))
                if args.metrics_file:
                    from nlw.ops import dataset_retention as dr

                    dr.write_textfile(
                        args.metrics_file, dr.receipt_metrics(report, now=datetime.now(UTC))
                    )
                return 1 if reconcile_failed(report) else 0
            result = reapply_receipts(conn, log, dry_run=args.dry_run, progress=progress)
            print(_summary(result))
            return 1 if reapply_failed(result) else 0
        if args.cmd == "retention-status":
            from nlw.ops import dataset_retention as dr

            status = dr.retention_status(conn, datetime.now(UTC))
            print(" ".join(f"{k}={v}" for k, v in status.items()))
            if args.metrics_file:
                dr.write_textfile(args.metrics_file, dr.status_metrics(status))
            return 0
        if args.cmd == "restore-objects":
            # The restore role only: never the operator credentials (ADR-036).
            return _restore_objects_cli(args, conn, settings)
        store = dataset_store(settings, service="operator")
        if args.cmd == "retention-sweep":
            return _retention_sweep(args, conn, store, settings, progress)
        if args.cmd == "verify-objects":
            if store is None:
                raise TombstoneError("no dataset store is configured")
            report = verify_objects(conn, store)
            for key, ids in report.items():
                print(f"{key}={len(ids)}" + ("" if not ids else " " + ",".join(ids)))
            # Noncurrent versions are expected for up to 30 days (O-5 lifecycle):
            # reported, never a failure.
            return 1 if any(v for k, v in report.items() if k != "noncurrent_versions") else 0
        log = _configured_log(settings)
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


def _retention_sweep(
    args: argparse.Namespace,
    conn: psycopg.Connection[Any],
    store: BlobStore | None,
    settings: Settings,
    progress: dict[str, int],
) -> int:
    """Run one sweep; the metrics file records the outcome either way."""
    from nlw.ops import dataset_retention as dr

    now = datetime.now(UTC)
    outcome = "failed"
    try:
        log = _configured_log(settings)
        result = dr.retention_sweep(
            conn, store, log, operator=args.operator, environment=settings.app_env, now=now,
            limit=args.limit, dry_run=args.dry_run, progress=progress,
        )  # fmt: skip
        outcome = "busy" if result["busy"] else "ok"
        print(" ".join(f"{k}={v}" for k, v in result.items()))
        return 0
    except TombstoneError as exc:
        if "recovery lock" in str(exc):
            outcome = "locked"
        raise
    finally:
        if args.metrics_file and not args.dry_run:
            try:
                status = dr.retention_status(conn, now)
            except Exception:
                status = None
            dr.write_textfile(
                args.metrics_file,
                dr.sweep_metrics(args.metrics_file, now=now, outcome=outcome, status=status),
            )


def _summary(result: dict[str, Any]) -> str:
    """One line: counts, and the ids of listed items (ids only)."""
    return " ".join(
        f"{k}={len(v)}" + ("" if not v else " " + ",".join(v))
        if isinstance(v, list)
        else f"{k}={v}"
        for k, v in result.items()
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
