"""Restore-ready gate artifact (M11.5 P2 addendum C).

The runtime-start gate must be ENFORCEABLE, not merely a runbook instruction or an
easily pre-existing static file. After — and only after — post-restore quiescence
AND full validation commit, the restore writes a small non-secret JSON gate,
atomically, bound to THIS restore generation and THIS database cluster:

  - restore_event_id      : the dr_restore_events row created by this restore
  - restore_generation    : a fresh uuid for this restore run
  - target_project        : the exact Compose project / restore target id
  - snapshot              : the restored snapshot id/selector
  - db_system_identifier  : the Postgres cluster's system identifier (pg_control)
  - database_name         : the restored database name
  - quiescence_cutoff     : the quiescence cutoff instant
  - validation_completed_at: when validation passed

api/worker/scheduler start ONLY in restore-mode after ``verify_restore_gate``
passes. A gate from an earlier drill/database is rejected because its
``db_system_identifier`` and ``restore_event_id`` will not match the live cluster's
newest restore event. The gate carries NO secret or customer data.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Engine

RESTORE_GATE_VERSION = "nlw-restore-gate/1"


class GateError(RuntimeError):
    """Base: the restore-ready gate is missing, malformed, or not bound to this DB."""


class GateMissing(GateError): ...


class GateInvalid(GateError): ...


class GateMismatch(GateError): ...


def db_system_identifier(engine: Engine) -> str:
    """The Postgres cluster's stable system identifier (from pg_control). A fresh
    restore cluster has a distinct value, so a gate cannot be reused on another DB."""
    with engine.connect() as conn:
        sysid = conn.execute(text("SELECT system_identifier FROM pg_control_system()")).scalar_one()
    return str(sysid)


def latest_restore_event_id(engine: Engine) -> str | None:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id FROM dr_restore_events ORDER BY restored_at DESC LIMIT 1")
        ).first()
    return str(row[0]) if row else None


def build_gate(
    *,
    restore_event_id: str,
    restore_generation: str,
    target_project: str,
    snapshot: str,
    db_system_identifier: str,
    database_name: str,
    quiescence_cutoff: datetime,
    validation_completed_at: datetime,
) -> dict[str, Any]:
    return {
        "version": RESTORE_GATE_VERSION,
        "restore_event_id": restore_event_id,
        "restore_generation": restore_generation,
        "target_project": target_project,
        "snapshot": snapshot,
        "db_system_identifier": db_system_identifier,
        "database_name": database_name,
        "quiescence_cutoff": quiescence_cutoff.astimezone(UTC).isoformat(),
        "validation_completed_at": validation_completed_at.astimezone(UTC).isoformat(),
    }


def write_gate(gate: dict[str, Any], path: Path) -> None:
    """Write the gate atomically (temp + os.replace). Mode 0644 — it is non-secret
    binding metadata that a runtime entrypoint reads."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(gate, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


_REQUIRED = (
    "version",
    "restore_event_id",
    "restore_generation",
    "target_project",
    "db_system_identifier",
    "quiescence_cutoff",
    "validation_completed_at",
)


def verify_restore_gate(
    engine: Engine, gate_path: Path, *, expected_project: str | None = None
) -> dict[str, Any]:
    """Fail closed unless a well-formed gate bound to THIS restore generation and
    THIS database cluster exists. Returns the gate dict on success."""
    if not gate_path.exists():
        raise GateMissing(f"restore-ready gate not found at {gate_path}")
    try:
        gate = json.loads(gate_path.read_text())
    except (OSError, ValueError) as exc:
        raise GateInvalid("restore-ready gate is unreadable/malformed") from exc
    if not isinstance(gate, dict):
        raise GateInvalid("restore-ready gate is not an object")
    missing = [k for k in _REQUIRED if not gate.get(k)]
    if missing:
        raise GateInvalid(f"restore-ready gate missing fields: {missing}")
    if gate.get("version") != RESTORE_GATE_VERSION:
        raise GateInvalid(f"unexpected gate version: {gate.get('version')!r}")

    live_sysid = db_system_identifier(engine)
    if gate["db_system_identifier"] != live_sysid:
        raise GateMismatch(
            "restore-ready gate is bound to a different database cluster "
            "(system identifier mismatch) — refusing to start"
        )
    live_event = latest_restore_event_id(engine)
    if live_event is None:
        raise GateMismatch("no restore event on this database — gate not applicable")
    if gate["restore_event_id"] != live_event:
        raise GateMismatch(
            "restore-ready gate is stale (does not match this database's newest restore generation)"
        )
    if expected_project and gate["target_project"] != expected_project:
        raise GateMismatch(
            f"restore-ready gate is for a different project ({gate['target_project']!r} "
            f"!= {expected_project!r})"
        )
    return gate
