"""The Phase 2 synthetic-pilot retention policy (owner decision O-5, ADR-035).

One source of truth: the provisioning templates, the backup configuration, the
retention sweep, the alerts and the ADR are pinned to these values by contract
tests. Changing a value is an owner decision, never configuration.

Two kinds of period:

- a **guarantee** bounds what the system does on its own: data is kept AT
  LEAST this long (``ACTIVE`` until deletion is requested; inactive versions 30
  days; receipts and audit events 365 days; backups 30 daily and 12 monthly);
- a **target** is an operational deadline for an operator-run job (purge a
  rejected or logically deleted object within 7 days); missing it fires an
  alert, it never deletes anything by itself.

Deadlines use timezone-aware timestamps only. ``eligible`` (a retention period
has ended) is ``>=``: at exactly the period, data may go. ``overdue`` (a
deadline has passed) is ``>``: at exactly the deadline, the job is on time.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

DAY_S = 86_400

# --- dataset objects (S3 ``versions/`` bucket and the database lifecycle) ------
REJECTED_PURGE_DAYS = 7  # target: a REJECTED object is purged within 7 days
INACTIVE_RETENTION_DAYS = 30  # guarantee: an unpublished/superseded version is kept 30 days
DELETED_PURGE_DAYS = 7  # target: logically deleted bytes are purged within 7 days
MULTIPART_ABORT_DAYS = 1  # S3 lifecycle: incomplete multipart uploads aborted after 1 day
NONCURRENT_RETENTION_DAYS = 30  # S3 lifecycle: a noncurrent object version expires after 30 days

# --- evidence ------------------------------------------------------------------
RECEIPT_RETENTION_DAYS = 365  # guarantee: Object Lock default retention of a receipt
AUDIT_RETENTION_DAYS = 365  # guarantee: CloudTrail data events (dataset and receipt buckets)
# A lifecycle expiry is one day past the lock, so no rule acts while it holds.
RECEIPT_EXPIRY_DAYS = RECEIPT_RETENTION_DAYS + 1
AUDIT_EXPIRY_DAYS = AUDIT_RETENTION_DAYS + 1
# A purge event whose receipt expires within this window while its version is
# not yet tombstoned is flagged: the tombstone verifies the receipt.
RECEIPT_EXPIRY_WARNING_DAYS = 30

# --- backups --------------------------------------------------------------------
DB_BACKUP_DAILY = 30  # guarantee: 30 daily recovery points
DB_BACKUP_WEEKLY = 0  # no separate weekly tier
DB_BACKUP_MONTHLY = 12  # guarantee: 12 monthly recovery points
OBJECT_BACKUP_RETENTION_DAYS = 30  # O-4 design constraint: object recovery copies, 30 days

# --- Object Lock ----------------------------------------------------------------
# Synthetic pilot: GOVERNANCE. Real customer data stays blocked until receipt
# and audit storage use COMPLIANCE and a separate GO decision is recorded.
PILOT_OBJECT_LOCK_MODE: Literal["GOVERNANCE"] = "GOVERNANCE"
CUSTOMER_DATA_OBJECT_LOCK_MODE: Literal["COMPLIANCE"] = "COMPLIANCE"

# --- sweep cadence (operational) ------------------------------------------------
SWEEP_STALE_AFTER_S = 36 * 3600  # a daily sweep that has not succeeded for 36 h is stale


Kind = Literal["guarantee", "target"]


@dataclass(frozen=True)
class Rule:
    """One line of the retention matrix (ADR-035)."""

    subject: str
    period_days: int | None  # None: until an event (deletion request)
    kind: Kind
    actor: str
    mechanism: str


POLICY: tuple[Rule, ...] = (
    Rule("ACTIVE published source", None, "guarantee", "none (kept)",
         "retained until dataset or version deletion is requested"),
    Rule("REJECTED object", REJECTED_PURGE_DAYS, "target", "operator (retention-sweep)",
         "physical purge with receipt"),
    Rule("unpublished/inactive version", INACTIVE_RETENTION_DAYS, "guarantee",
         "operator (retention-sweep)", "INACTIVE_RETENTION -> DELETING, then purge"),
    Rule("logically deleted bytes", DELETED_PURGE_DAYS, "target", "operator (retention-sweep)",
         "physical purge with receipt; tombstone stays a separate operator step"),
    Rule("incomplete multipart upload", MULTIPART_ABORT_DAYS, "guarantee", "S3 lifecycle",
         "AbortIncompleteMultipartUpload"),
    Rule("noncurrent S3 object version", NONCURRENT_RETENTION_DAYS, "guarantee", "S3 lifecycle",
         "NoncurrentVersionExpiration"),
    Rule("deletion receipt", RECEIPT_RETENTION_DAYS, "guarantee", "S3 Object Lock",
         "default retention, then lifecycle expiry"),
    Rule("CloudTrail data event", AUDIT_RETENTION_DAYS, "guarantee", "S3 Object Lock",
         "default retention, then lifecycle expiry"),
    Rule("database backup (daily)", DB_BACKUP_DAILY, "guarantee", "backup job (restic forget)",
         "keep-daily"),
    Rule("database backup (monthly)", DB_BACKUP_MONTHLY * 30, "guarantee",
         "backup job (restic forget)", "keep-monthly 12"),
    Rule("object-backup recovery copies", OBJECT_BACKUP_RETENTION_DAYS, "guarantee",
         "O-4 (not implemented)", "design constraint"),
)  # fmt: skip


def _aware(t: datetime, name: str) -> None:
    if t.tzinfo is None or t.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def elapsed(since: datetime, now: datetime) -> timedelta:
    _aware(since, "since")
    _aware(now, "now")
    return now - since


def eligible(since: datetime, now: datetime, days: int) -> bool:
    """A retention period of ``days`` has ended (at exactly the period: yes)."""
    return elapsed(since, now) >= timedelta(days=days)


def overdue(since: datetime, now: datetime, days: int) -> bool:
    """A deadline of ``days`` has passed (at exactly the deadline: not yet)."""
    return elapsed(since, now) > timedelta(days=days)
