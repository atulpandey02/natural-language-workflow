"""The dataset retention sweep and its status metrics (owner decision O-5, ADR-035).

    python -m nlw.ops.datasets retention-status [--metrics-file PATH]
    python -m nlw.ops.datasets retention-sweep --operator <name> [--dry-run] [--limit N]
                                              [--metrics-file PATH]

``retention-sweep`` applies the policy in ``nlw.core.retention`` with the same
verified, receipted purge as a deletion request. One bounded batch (``--limit``
items in all) is drawn from ONE candidate set, ordered globally by each item's
effective due time (earliest deadline first), so no category can starve
another:

- **logically deleted bytes** (due 7 days after the deletion request): a
  DELETING version that still references an object and has no purge evidence
  since its request is purged. This also resumes versions a crashed sweep
  moved to DELETING;
- **rejected objects** (due 7 days after rejection): moved to DELETING
  (``REJECTED_RETENTION``) and purged;
- **inactive versions** (due when the 30-day retention ends): a QUARANTINED,
  PROFILING (lease expired), PROFILED or SUPERSEDED version is moved to
  DELETING (``INACTIVE_RETENTION``) and purged. Its age runs from
  ``superseded_at`` for a superseded version, otherwise from ``created_at``.

Ties are broken by category (deleted, rejected, inactive), then by version id.

What it never does: touch an ACTIVE version or the dataset's active version
(both excluded in SQL and re-checked under the row lock); delete a database
row; tombstone (that stays the operator's separate, verified step); purge
without a deletion log that can retain the receipt (preflight first).

It is refused while the recovery lock is active, runs at most once at a time
(a session advisory lock: a concurrent run reports ``busy=1`` and changes
nothing), and is idempotent: each item is its own transaction, so a failure
stops the run with earlier items committed and the rest untouched; a re-run
continues from the oldest remaining item.

The textfile metrics (node-exporter textfile collector) are aggregates only,
with no label: counts, oldest ages in seconds and sweep timestamps.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime
from typing import Any

import psycopg

from nlw.core import retention as policy
from nlw.datasets.deletion_log import DeletionLog
from nlw.datasets.lifecycle import EventType, ReasonCode
from nlw.ops import datasets as ops
from nlw.storage.blob import BlobStore

SWEEP_BATCH = 100
_SQL_LOCK = "SELECT pg_try_advisory_lock(hashtext('nlw.ops.datasets.retention_sweep'))"
_SQL_UNLOCK = "SELECT pg_advisory_unlock(hashtext('nlw.ops.datasets.retention_sweep'))"

# A version is unpurged when it references an object and no purge evidence was
# recorded since its deletion request.
_UNPURGED = (
    "v.status = 'DELETING' AND v.storage_object_key IS NOT NULL "
    "AND NOT EXISTS (SELECT 1 FROM dataset_events p WHERE p.version_id = v.id "
    "AND p.event_type = 'VERSION_OBJECT_PURGED' AND p.created_at >= v.deletion_requested_at)"
)
# Inactive: never published, or superseded; never ACTIVE, never the active version,
# never a version being processed under a live lease.
_INACTIVE = (
    "v.status IN ('QUARANTINED', 'PROFILING', 'PROFILED', 'SUPERSEDED') "
    "AND d.status = 'ACTIVE' AND d.active_version_id IS DISTINCT FROM v.id "
    "AND (v.status <> 'PROFILING' OR v.processing_lease_expires_at IS NULL "
    "OR v.processing_lease_expires_at < %(now)s)"
)
_INACTIVE_SINCE = "coalesce(v.superseded_at, v.created_at)"

# One candidate set across the three categories, ordered by each item's
# EFFECTIVE DUE TIME (earliest deadline first), so a backlog in one category
# can never starve another: a deleted or rejected object is due 7 days after its
# request or rejection; an inactive version when its 30-day retention ended.
# Each branch keeps only its own first ``limit`` candidates (in the same order),
# so the global first ``limit`` is exact and the query stays bounded.
_SQL_CANDIDATES = (
    "SELECT kind, tenant_id, dataset_id, id, due FROM ("
    "(SELECT 'deleting' AS kind, v.tenant_id, v.dataset_id, v.id, "
    "v.deletion_requested_at + make_interval(days => %(purge_days)s) AS due "
    f"FROM dataset_versions v WHERE {_UNPURGED} "
    "ORDER BY due, v.id LIMIT %(limit)s) "
    "UNION ALL "
    "(SELECT 'rejected', v.tenant_id, v.dataset_id, v.id, "
    "v.rejected_at + make_interval(days => %(rejected_days)s) AS due "
    "FROM dataset_versions v WHERE v.status = 'REJECTED' AND v.storage_object_key IS NOT NULL "
    "ORDER BY due, v.id LIMIT %(limit)s) "
    "UNION ALL "
    "(SELECT 'inactive', v.tenant_id, v.dataset_id, v.id, "
    f"{_INACTIVE_SINCE} + make_interval(days => %(days)s) AS due "
    "FROM dataset_versions v JOIN datasets d ON d.id = v.dataset_id AND d.tenant_id = v.tenant_id "
    f"WHERE {_INACTIVE} AND {_INACTIVE_SINCE} <= %(now)s - make_interval(days => %(days)s) "
    "ORDER BY due, v.id LIMIT %(limit)s)"
    ") candidates "
    "ORDER BY due, CASE kind WHEN 'deleting' THEN 0 WHEN 'rejected' THEN 1 ELSE 2 END, id "
    "LIMIT %(limit)s"
)


def _aware(now: datetime) -> datetime:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ops.TombstoneError("the sweep clock must be timezone-aware")
    return now


# --- status (read-only) ------------------------------------------------------------

_AGE = "coalesce(floor(extract(epoch FROM %(now)s - min({col})))::bigint, 0)"
_SQL_STATUS = {
    "rejected": (
        f"SELECT count(*), {_AGE.format(col='v.rejected_at')} FROM dataset_versions v "
        "WHERE v.status = 'REJECTED' AND v.storage_object_key IS NOT NULL"
    ),
    "inactive": (
        "SELECT count(*) FILTER (WHERE "
        f"{_INACTIVE_SINCE} <= %(now)s - make_interval(days => %(days)s)), "
        f"{_AGE.format(col=_INACTIVE_SINCE)} FROM dataset_versions v "
        f"JOIN datasets d ON d.id = v.dataset_id AND d.tenant_id = v.tenant_id WHERE {_INACTIVE}"
    ),
    "deleting": (
        f"SELECT count(*), {_AGE.format(col='v.deletion_requested_at')} "
        f"FROM dataset_versions v WHERE {_UNPURGED}"
    ),
    # Latest purge evidence of a version still DELETING (not tombstoned) whose
    # receipt's retention ends within the warning window: the tombstone needs it.
    "receipts": (
        "SELECT count(*), 0 FROM dataset_versions v WHERE v.status = 'DELETING' "
        "AND (SELECT max(p.created_at) FROM dataset_events p WHERE p.version_id = v.id "
        "AND p.event_type = 'VERSION_OBJECT_PURGED') "
        "<= %(now)s - make_interval(days => %(receipt_warn)s)"
    ),
}


def retention_status(conn: psycopg.Connection[Any], now: datetime) -> dict[str, int]:
    """Counts and oldest ages (seconds) of everything the policy bounds."""
    params = {
        "now": _aware(now),
        "days": policy.INACTIVE_RETENTION_DAYS,
        "receipt_warn": policy.RECEIPT_RETENTION_DAYS - policy.RECEIPT_EXPIRY_WARNING_DAYS,
    }
    out: dict[str, int] = {}
    for name, sql in _SQL_STATUS.items():
        row = conn.execute(sql, params).fetchone()
        count, age = (int(row[0]), int(row[1])) if row else (0, 0)
        out[f"{name}_count"] = count
        if name != "receipts":
            out[f"{name}_oldest_age_s"] = max(age, 0)
    return out


# --- the sweep -------------------------------------------------------------------------


def _move_to_deleting(
    conn: psycopg.Connection[Any],
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    vid: uuid.UUID,
    *,
    reason: ReasonCode,
    now: datetime,
) -> bool:
    """Move one version to DELETING if it is STILL eligible under the row lock
    (a concurrent activation, deletion or sweep wins; ACTIVE is never moved)."""
    with conn.transaction():
        row = conn.execute(
            "SELECT v.status, coalesce(v.superseded_at, v.created_at), d.status, "
            "d.active_version_id, v.processing_lease_expires_at, "
            "v.storage_object_key IS NOT NULL FROM dataset_versions v "
            "JOIN datasets d ON d.id = v.dataset_id AND d.tenant_id = v.tenant_id "
            "WHERE v.id = %s AND v.dataset_id = %s AND v.tenant_id = %s FOR UPDATE OF v, d",
            (vid, dataset_id, tenant_id),
        ).fetchone()
        if row is None:
            return False
        status, since, ds_status, active, lease, has_key = row
        if active == vid or status in ("ACTIVE", "DELETING", "DELETED"):
            return False
        if reason is ReasonCode.REJECTED_RETENTION:
            if status != "REJECTED" or not has_key:
                return False
        elif reason is ReasonCode.INACTIVE_RETENTION:
            if (
                status not in ("QUARANTINED", "PROFILING", "PROFILED", "SUPERSEDED")
                or ds_status != "ACTIVE"
                or (status == "PROFILING" and lease is not None and lease >= now)
                or not policy.eligible(since, now, policy.INACTIVE_RETENTION_DAYS)
            ):
                return False
        else:  # pragma: no cover - programming error
            raise ValueError(reason)
        conn.execute(
            "UPDATE dataset_versions SET status = 'DELETING' WHERE id = %s AND status = %s",
            (vid, status),
        )
        ops._event(
            conn, tenant_id, dataset_id, vid, EventType.VERSION_DELETION_REQUESTED, status,
            to_status="DELETING", reason=reason,
        )  # fmt: skip
    return True


_REASON: dict[str, ReasonCode | None] = {
    "deleting": None,
    "rejected": ReasonCode.REJECTED_RETENTION,
    "inactive": ReasonCode.INACTIVE_RETENTION,
}
_COUNTS = (
    "deleting_purged", "rejected_moved", "rejected_purged", "inactive_moved",
    "inactive_purged", "selected",
)  # fmt: skip


def retention_sweep(
    conn: psycopg.Connection[Any],
    store: BlobStore | None,
    log: DeletionLog,
    *,
    operator: str,
    environment: str,
    now: datetime,
    limit: int = SWEEP_BATCH,
    dry_run: bool = False,
    progress: dict[str, int] | None = None,
) -> dict[str, int]:
    """One bounded, oldest-first batch (see the module docstring). ``more=1``
    means run it again; ``busy=1`` that another sweep holds the lock."""
    limit = ops._bounded(limit)
    now = _aware(now)
    ops._require_runtimes_permitted(conn)
    counts = progress if progress is not None else {}
    counts.update(dict.fromkeys(_COUNTS, 0))
    row = conn.execute(_SQL_LOCK).fetchone()
    if not (row and row[0]):
        return {**counts, "more": 0, "busy": 1, "dry_run": int(dry_run)}
    try:
        if not dry_run:
            ops._preflight(log)
        params = {
            "now": now,
            "days": policy.INACTIVE_RETENTION_DAYS,
            "purge_days": policy.DELETED_PURGE_DAYS,
            "rejected_days": policy.REJECTED_PURGE_DAYS,
            "limit": limit + 1,
        }
        rows = conn.execute(_SQL_CANDIDATES, params).fetchall()
        more = len(rows) > limit
        for kind, tenant_id, dataset_id, vid, _due in rows[:limit]:
            counts["selected"] += 1
            if dry_run:
                continue
            reason = _REASON[kind]
            if reason is not None:
                if not _move_to_deleting(conn, tenant_id, dataset_id, vid, reason=reason, now=now):
                    continue  # no longer eligible (activated, deleted, swept concurrently)
                counts[f"{kind}_moved"] += 1
            result = ops.purge(
                conn, store, log, dataset_id=dataset_id, version_id=vid,
                operator=operator, environment=environment,
            )  # fmt: skip
            counts[f"{kind}_purged"] += int(result["versions_purged"])
        return {**counts, "more": int(more), "busy": 0, "dry_run": int(dry_run)}
    finally:
        conn.execute(_SQL_UNLOCK)


# --- textfile metrics ----------------------------------------------------------------

STATUS_METRICS = {
    "rejected_count": (
        "nlw_dataset_rejected_retained",
        "Rejected dataset objects awaiting operator purge.",
    ),
    "rejected_oldest_age_s": (
        "nlw_dataset_rejected_oldest_age_seconds",
        "Age of the oldest retained rejected object.",
    ),
    "inactive_count": (
        "nlw_dataset_inactive_retention_due",
        "Unpublished or superseded versions whose 30-day retention has ended.",
    ),
    "inactive_oldest_age_s": (
        "nlw_dataset_inactive_oldest_age_seconds",
        "Age of the oldest unpublished or superseded version.",
    ),
    "deleting_count": (
        "nlw_dataset_deleting_unpurged",
        "Logically deleted versions whose object is not yet purged.",
    ),
    "deleting_oldest_age_s": (
        "nlw_dataset_deleting_oldest_unpurged_age_seconds",
        "Time since the oldest unpurged deletion request.",
    ),
    "receipts_count": (
        "nlw_dataset_receipts_expiring_untombstoned",
        "Purged but not tombstoned versions whose receipt retention ends within 30 days.",
    ),
}
_METRIC_LINE = re.compile(r"^(nlw_[a-z_]+) (-?[0-9]+(?:\.[0-9]+)?)$")


def read_textfile(path: str) -> dict[str, float]:
    """The values a previous run wrote (missing or unreadable: none)."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return {}
    out = {}
    for line in lines:
        m = _METRIC_LINE.match(line)
        if m:
            out[m.group(1)] = float(m.group(2))
    return out


def write_textfile(path: str, metrics: list[tuple[str, str, float]]) -> None:
    """Atomic, label-free gauges: ``(name, help, value)``."""
    body = "".join(
        f"# HELP {name} {help_}\n# TYPE {name} gauge\n{name} {value:g}\n"
        if isinstance(value, float) and not value.is_integer()
        else f"# HELP {name} {help_}\n# TYPE {name} gauge\n{name} {int(value)}\n"
        for name, help_, value in metrics
    )
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(body)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def status_metrics(status: dict[str, int]) -> list[tuple[str, str, float]]:
    return [(name, help_, float(status[key])) for key, (name, help_) in STATUS_METRICS.items()]


def sweep_metrics(
    path: str, *, now: datetime, outcome: str, status: dict[str, int] | None
) -> list[tuple[str, str, float]]:
    """``outcome``: ``ok``, ``busy``, ``locked`` (recovery lock) or ``failed``.
    The last success survives runs that did not succeed."""
    previous = read_textfile(path)
    ts = now.timestamp()
    last_ok = (
        ts
        if outcome == "ok"
        else previous.get("nlw_dataset_retention_sweep_last_success_timestamp_seconds", 0.0)
    )
    out = status_metrics(status) if status is not None else []
    return out + [
        ("nlw_dataset_retention_sweep_last_run_timestamp_seconds",
         "Time of the last retention sweep attempt.", float(int(ts))),
        ("nlw_dataset_retention_sweep_last_success_timestamp_seconds",
         "Time of the last successful retention sweep.", float(int(last_ok))),
        ("nlw_dataset_retention_sweep_failed",
         "1 if the last retention sweep failed.", 1.0 if outcome == "failed" else 0.0),
        ("nlw_dataset_retention_sweep_recovery_locked",
         "1 if the last sweep was refused by the recovery lock.",
         1.0 if outcome == "locked" else 0.0),
    ]  # fmt: skip


def receipt_metrics(report: dict[str, Any], *, now: datetime) -> list[tuple[str, str, float]]:
    """``reconcile-receipts --metrics-file``: counts only."""
    return [
        ("nlw_dataset_receipts_unverified",
         "Purge events whose receipt is missing, unretained or does not verify.",
         float(len(report["unverified"]) + len(report["other_sink"]))),
        ("nlw_dataset_receipts_unexpected_objects",
         "Objects in the deletion log that are not receipts.",
         float(report["unexpected_objects"])),
        ("nlw_dataset_receipts_without_event",
         "Receipts no purge event names (a purge that failed after its receipt).",
         float(len(report["receipts_without_event"]))),
        ("nlw_dataset_receipts_reconcile_last_success_timestamp_seconds",
         "Time of the last completed receipt reconciliation.", float(int(now.timestamp()))),
    ]  # fmt: skip
