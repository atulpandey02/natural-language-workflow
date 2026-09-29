"""Structured record for the real-provider fresh-host DR drill (Phase 2 B03).

The drill itself is a human-gated operator procedure
(``docs/runbooks/dr-real-vps-checklist.md``). This module turns its outcome into
a record that code evaluates, so a drill is never summarised as PASS by hand:

    python -m nlw.ops.dr_evidence check docs/ops/dr-drills/<date>.json

Measured values:

- observed RPO = ``incident_declared_at - snapshot_time`` (data written after the
  snapshot is lost; the drill simulates the incident at declaration time);
- observed RTO = ``runtime_ready_at - incident_declared_at`` (includes provider
  download, host provisioning and human decision time).

A record is PASS only if the repository is a real off-host object store (the
same rule as the rollout ``verify-backup`` gate), the restore target was a fresh
isolated host, every restore-validator check was ``ok``, quiescence was
confirmed before any runtime start, timestamps are ordered, and both objectives
hold. The record holds no secrets: the repository is stored redacted.

This checks the internal consistency of what an operator recorded; it cannot
prove the drill happened. The record must be written from the drill's own
outputs (validator JSON, timestamps), never reconstructed afterwards.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from nlw.ops.rollout.backup_evidence import BackupEvidenceError, check_repository_is_off_host

RPO_OBJECTIVE = timedelta(hours=24)
RTO_OBJECTIVE = timedelta(hours=4)


class DrillRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    drill_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    operator: str = Field(min_length=1, max_length=100)
    provider: str = Field(min_length=1, max_length=100)
    # s3:https://host/bucket — credentials must never appear (checked below).
    repository: str = Field(min_length=4, max_length=300)
    source_release_sha: str = Field(pattern=r"^[0-9a-f]{7,40}$")
    restore_host_fresh: bool
    restore_host_isolated: bool
    snapshot_id: str = Field(pattern=r"^[0-9a-f]{8,64}$")
    snapshot_time: datetime
    incident_declared_at: datetime
    restore_started_at: datetime
    runtime_ready_at: datetime
    backup_duration_s: float | None = Field(default=None, ge=0)
    download_duration_s: float | None = Field(default=None, ge=0)
    validator_checks: dict[str, bool] = Field(min_length=1)
    quiescence_confirmed_before_runtime: bool
    # The deletion-log re-application step becomes mandatory once offboarding
    # exists (docs/security/offboarding-and-deletion.md); until then it is
    # recorded as not applicable, never as done.
    deletion_log_step: str = Field(pattern=r"^(applied|not_applicable_no_offboarding_yet)$")
    issues: list[str] = Field(default_factory=list, max_length=50)


def evaluate(record: DrillRecord) -> dict[str, Any]:
    """Return {verdict, observed_rpo_s, observed_rto_s, reasons}."""
    reasons: list[str] = []
    if "@" in record.repository:
        reasons.append("repository must be recorded without credentials")
    try:
        check_repository_is_off_host(record.repository)
    except BackupEvidenceError as exc:
        reasons.append(f"not a real off-host repository: {exc}")
    if not record.restore_host_fresh or not record.restore_host_isolated:
        reasons.append("restore target must be a fresh, isolated host")
    failed = sorted(k for k, ok in record.validator_checks.items() if not ok)
    if failed:
        reasons.append(f"restore validator checks not ok: {failed}")
    if not record.quiescence_confirmed_before_runtime:
        reasons.append("quiescence was not confirmed before runtime start")
    order = [
        record.snapshot_time,
        record.incident_declared_at,
        record.restore_started_at,
        record.runtime_ready_at,
    ]
    if any(t.tzinfo is None for t in order):
        reasons.append("all timestamps must carry a timezone")
        rpo = rto = None
    else:
        if order != sorted(order):
            reasons.append("timestamps out of order (snapshot <= declared <= start <= ready)")
        rpo = record.incident_declared_at - record.snapshot_time
        rto = record.runtime_ready_at - record.incident_declared_at
        if rpo > RPO_OBJECTIVE:
            reasons.append(f"observed RPO {rpo} exceeds objective {RPO_OBJECTIVE}")
        if rto > RTO_OBJECTIVE:
            reasons.append(f"observed RTO {rto} exceeds objective {RTO_OBJECTIVE}")
    return {
        "verdict": "PASS" if not reasons else "FAIL",
        "observed_rpo_s": rpo.total_seconds() if rpo is not None else None,
        "observed_rto_s": rto.total_seconds() if rto is not None else None,
        "reasons": reasons,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ops.dr_evidence")
    sub = p.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check")
    chk.add_argument("record")
    args = p.parse_args(argv)
    try:
        record = DrillRecord.model_validate(json.loads(Path(args.record).read_text()))
    except (OSError, ValueError, ValidationError) as exc:
        print(f"error: unreadable drill record: {type(exc).__name__}", file=sys.stderr)
        return 2
    result = evaluate(record)
    print(json.dumps(result, indent=2))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
