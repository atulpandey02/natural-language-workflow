"""Restore-ready gate binding, tampering & reuse rejection (M11.5 P2 addendum C).

The gate must be bound to THIS restore generation and THIS database cluster, and
rejected when missing, malformed, stale, cross-DB, or for the wrong project.
"""

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy import create_engine

from nlw.backup.gate import (
    GateInvalid,
    GateMismatch,
    GateMissing,
    build_gate,
    db_system_identifier,
    verify_restore_gate,
    write_gate,
)
from nlw.backup.quiescence import quiesce

pytestmark = pytest.mark.integration


def _valid_gate(engine, event_id: str, *, project: str = "nlw-dr") -> dict[str, object]:  # type: ignore[no-untyped-def]
    return build_gate(
        restore_event_id=event_id,
        restore_generation=str(uuid.uuid4()),
        target_project=project,
        snapshot="latest",
        db_system_identifier=db_system_identifier(engine),
        database_name="nlw",
        quiescence_cutoff=datetime.now(UTC),
        validation_completed_at=datetime.now(UTC),
    )


def test_valid_gate_passes_and_binds_to_generation_and_cluster(
    pg_stack: SimpleNamespace, tmp_path: Path
) -> None:
    engine = create_engine(pg_stack.owner_sa)
    qr = quiesce(engine)  # records a dr_restore_events row
    assert qr.event_id is not None
    gate_path = tmp_path / "restore-ready.json"
    write_gate(_valid_gate(engine, qr.event_id), gate_path)

    got = verify_restore_gate(engine, gate_path, expected_project="nlw-dr")
    assert got["restore_event_id"] == qr.event_id
    # File is non-secret binding metadata (world-readable, no secrets).
    assert (gate_path.stat().st_mode & 0o777) == 0o644
    blob = gate_path.read_text().lower()
    assert "password" not in blob and "secret" not in blob


def test_missing_gate_rejected(pg_stack: SimpleNamespace, tmp_path: Path) -> None:
    engine = create_engine(pg_stack.owner_sa)
    with pytest.raises(GateMissing):
        verify_restore_gate(engine, tmp_path / "nope.json")


def test_malformed_and_incomplete_gate_rejected(pg_stack: SimpleNamespace, tmp_path: Path) -> None:
    engine = create_engine(pg_stack.owner_sa)
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not json")
    with pytest.raises(GateInvalid):
        verify_restore_gate(engine, bad)
    # Well-formed JSON but missing required binding fields.
    incomplete = tmp_path / "incomplete.json"
    incomplete.write_text(json.dumps({"version": "nlw-restore-gate/1"}))
    with pytest.raises(GateInvalid):
        verify_restore_gate(engine, incomplete)


def test_tampered_cluster_binding_rejected(pg_stack: SimpleNamespace, tmp_path: Path) -> None:
    engine = create_engine(pg_stack.owner_sa)
    qr = quiesce(engine)
    assert qr.event_id is not None
    gate = _valid_gate(engine, qr.event_id)
    gate["db_system_identifier"] = "9999999999999999999"  # pretend a different cluster
    p = tmp_path / "g.json"
    write_gate(gate, p)
    with pytest.raises(GateMismatch, match="different database cluster"):
        verify_restore_gate(engine, p)


def test_wrong_project_rejected(pg_stack: SimpleNamespace, tmp_path: Path) -> None:
    engine = create_engine(pg_stack.owner_sa)
    qr = quiesce(engine)
    assert qr.event_id is not None
    p = tmp_path / "g.json"
    write_gate(_valid_gate(engine, qr.event_id, project="nlw-dr"), p)
    with pytest.raises(GateMismatch):
        verify_restore_gate(engine, p, expected_project="some-other-project")


def test_stale_generation_gate_rejected(pg_stack: SimpleNamespace, tmp_path: Path) -> None:
    engine = create_engine(pg_stack.owner_sa)
    qr1 = quiesce(engine)  # generation 1
    assert qr1.event_id is not None
    p = tmp_path / "g.json"
    write_gate(_valid_gate(engine, qr1.event_id), p)

    # A NEW restore generation (changed state -> new dr_restore_events row).
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        m = pg_stack.seed_member()
        wf, ver, run = (uuid.uuid4() for _ in range(3))
        c.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, m.tenant_id)
        )
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,'{\"steps\":[]}'::jsonb)",
            (ver, m.tenant_id, wf),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) "
            "VALUES (%s,%s,%s,%s,'RUNNING')",
            (run, m.tenant_id, wf, ver),
        )
    qr2 = quiesce(engine)
    assert qr2.event_id is not None and qr2.event_id != qr1.event_id

    # The generation-1 gate no longer matches this DB's newest restore generation.
    with pytest.raises(GateMismatch, match="stale"):
        verify_restore_gate(engine, p)
