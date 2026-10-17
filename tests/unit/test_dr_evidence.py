"""B03 preparation: a DR drill record is judged by code, never by hand."""

import json
from pathlib import Path
from typing import Any

import pytest

from nlw.ops import dr_evidence
from nlw.ops.dr_evidence import DrillRecord, evaluate

GOOD: dict[str, Any] = {
    "drill_date": "2026-10-05",
    "operator": "named-operator",
    "provider": "example object storage",
    "repository": "s3:https://s3.eu-central-1.example-provider.com/nlw-backups/staging",
    "source_release_sha": "b1a3058",
    "restore_host_fresh": True,
    "restore_host_isolated": True,
    "snapshot_id": "0a1b2c3d4e5f",
    "snapshot_time": "2026-10-05T02:00:00Z",
    "incident_declared_at": "2026-10-05T09:00:00Z",
    "restore_started_at": "2026-10-05T09:20:00Z",
    "runtime_ready_at": "2026-10-05T11:10:00Z",
    "validator_checks": {"security_definer_owners_and_search_path": True, "rls_forced": True},
    "quiescence_confirmed_before_runtime": True,
    "deletion_log_step": "applied",
    "objects_step": "restored_and_verified",
}


def _eval(**over: Any) -> dict[str, Any]:
    return evaluate(DrillRecord.model_validate({**GOOD, **over}))


def test_a_complete_real_provider_drill_passes_with_measured_rpo_rto() -> None:
    r = _eval()
    assert r == {
        "verdict": "PASS",
        "observed_rpo_s": 7 * 3600.0,
        "observed_rto_s": 2 * 3600.0 + 600.0,
        "reasons": [],
    }


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"repository": "s3:https://minio.local/nlw"}, "not a real off-host repository"),
        ({"repository": "s3:http://s3.example.com/b"}, "not a real off-host repository"),
        ({"repository": "/srv/backups/restic"}, "not a real off-host repository"),
        ({"repository": "s3:https://key:secret@s3.example.com/b"}, "without credentials"),
        ({"restore_host_fresh": False}, "fresh, isolated host"),
        ({"validator_checks": {"rls_forced": False}}, "validator checks not ok"),
        ({"quiescence_confirmed_before_runtime": False}, "quiescence"),
        ({"snapshot_time": "2026-10-03T02:00:00Z"}, "observed RPO"),
        ({"runtime_ready_at": "2026-10-05T14:00:01Z"}, "observed RTO"),
        ({"restore_started_at": "2026-10-05T08:00:00Z"}, "out of order"),
        ({"snapshot_time": "2026-10-05T02:00:00"}, "timezone"),
    ],
)
def test_incomplete_or_fixture_drills_fail(over: dict[str, Any], reason: str) -> None:
    r = _eval(**over)
    assert r["verdict"] == "FAIL"
    assert any(reason in x for x in r["reasons"]), r["reasons"]


def test_record_rejects_unknown_fields_and_a_claimed_deletion_step() -> None:
    with pytest.raises(ValueError):
        DrillRecord.model_validate({**GOOD, "verdict": "PASS"})
    with pytest.raises(ValueError):
        DrillRecord.model_validate({**GOOD, "deletion_log_step": "done"})


def test_the_obsolete_no_offboarding_value_is_refused() -> None:
    """ADR-037: offboarding exists, so evidence can no longer claim it does not."""
    with pytest.raises(ValueError):
        DrillRecord.model_validate(
            {**GOOD, "deletion_log_step": "not_applicable_no_offboarding_yet"}
        )


def test_no_deletion_log_is_accepted_only_where_no_dataset_store_exists() -> None:
    none = {
        "deletion_log_step": "not_applicable_no_deletion_log",
        "objects_step": "not_applicable_no_dataset_store",
    }
    assert _eval(**none)["verdict"] == "PASS"
    r = _eval(**{**none, "objects_step": "restored_and_verified"})
    assert r["verdict"] == "FAIL"
    assert any("deletion log must be re-applied" in x for x in r["reasons"])


@pytest.mark.parametrize("step", ["done", "restored", "", "applied"])
def test_an_objects_step_is_never_assumed(step: str) -> None:
    with pytest.raises(ValueError):
        DrillRecord.model_validate({**GOOD, "objects_step": step})
    without = {k: v for k, v in GOOD.items() if k != "objects_step"}
    with pytest.raises(ValueError):
        DrillRecord.model_validate(without)
    assert _eval(objects_step="not_applicable_no_dataset_store")["verdict"] == "PASS"


def test_cli_exit_codes(tmp_path: Path) -> None:
    good, bad = tmp_path / "good.json", tmp_path / "bad.json"
    good.write_text(json.dumps(GOOD))
    bad.write_text(json.dumps({**GOOD, "restore_host_isolated": False}))
    assert dr_evidence.main(["check", str(good)]) == 0
    assert dr_evidence.main(["check", str(bad)]) == 1
    assert dr_evidence.main(["check", str(tmp_path / "missing.json")]) == 2
