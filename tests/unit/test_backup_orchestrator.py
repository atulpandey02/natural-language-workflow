"""Backup orchestrator step-sequencing + fail-closed semantics (P2).

Uses a fake restic + fake dump/db-info seams so the ordering/failure logic is
tested without a real Postgres or repository.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nlw.backup.backup import DbInfo, run_backup
from nlw.backup.config import BackupSettings
from nlw.backup.metrics_file import _LAST_SUCCESS_RE


class FakeRestic:
    def __init__(self, fail_on: str | None = None) -> None:
        self.calls: list[str] = []
        self.fail_on = fail_on

    def _maybe_fail(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_on == name:
            raise RuntimeError(f"fake restic {name} failed")

    def ensure_repository(self) -> None:
        self._maybe_fail("ensure_repository")

    def backup_dir(self, path: Path, tags: object = ()) -> str:
        self._maybe_fail("backup_dir")
        return "snap123"

    def check(self) -> None:
        self._maybe_fail("check")

    def snapshot_exists(self, snapshot_id: str) -> bool:
        return True

    def forget_prune(self, *, daily: int, weekly: int, monthly: int) -> None:
        self._maybe_fail("forget_prune")


def _settings(tmp_path: Path) -> BackupSettings:
    return BackupSettings(
        app_env="local",
        NLW_BACKUP_DATABASE_URL="postgresql://nlw:pw@db/nlw",  # type: ignore[arg-type]
        NLW_BACKUP_WORK_DIR=str(tmp_path / "work"),
        NLW_BACKUP_METRICS_FILE=str(tmp_path / "m.prom"),
    )


def _dump(work: Path, url: str) -> dict[str, Path]:
    db = work / "db.dump"
    db.write_bytes(b"dump")
    g = work / "globals.sql"
    g.write_text("-- roles\n")
    return {"db.dump": db, "globals.sql": g}


def _info(url: str) -> DbInfo:
    return DbInfo(pg_version="16.2", alembic_revision="0014_dr_restore_events", database_name="nlw")


def _run(tmp_path: Path, restic: FakeRestic):  # type: ignore[no-untyped-def]
    return run_backup(
        _settings(tmp_path),
        restic=restic,  # type: ignore[arg-type]
        dump_fn=_dump,
        db_info_fn=_info,
        tool_versions_fn=lambda: {"pg_dump": "16", "restic": "0.16"},
        now_fn=lambda: datetime(2026, 5, 1, tzinfo=UTC),
    )


def _metrics(tmp_path: Path) -> str:
    return (tmp_path / "m.prom").read_text()


def test_success_verifies_off_host_then_prunes_and_records_last_success(tmp_path: Path) -> None:
    restic = FakeRestic()
    result = _run(tmp_path, restic)
    assert result.ok and result.snapshot_id == "snap123"
    # verify happened BEFORE retention.
    assert restic.calls.index("check") < restic.calls.index("forget_prune")
    m = _metrics(tmp_path)
    assert "nlw_backup_success 1" in m
    assert _LAST_SUCCESS_RE.search(m)  # last-success advanced
    assert not (tmp_path / "work").exists()  # work dir wiped


def test_upload_failure_reports_failure_and_does_not_advance_last_success(tmp_path: Path) -> None:
    restic = FakeRestic(fail_on="backup_dir")
    with pytest.raises(RuntimeError):
        _run(tmp_path, restic)
    assert "forget_prune" not in restic.calls  # retention NOT run
    m = _metrics(tmp_path)
    assert "nlw_backup_success 0" in m
    assert _LAST_SUCCESS_RE.search(m) is None  # last-success NOT advanced (dump never off-host)
    assert not (tmp_path / "work").exists()  # wiped on failure too


def test_verify_failure_blocks_retention_and_last_success(tmp_path: Path) -> None:
    restic = FakeRestic(fail_on="check")
    with pytest.raises(RuntimeError):
        _run(tmp_path, restic)
    assert "forget_prune" not in restic.calls
    m = _metrics(tmp_path)
    assert "nlw_backup_repository_verify_success 0" in m
    assert _LAST_SUCCESS_RE.search(m) is None


def test_local_dump_that_never_reached_off_host_cannot_update_timestamp(tmp_path: Path) -> None:
    # First: a real success writes a last-success timestamp.
    _run(tmp_path, FakeRestic())
    good = _LAST_SUCCESS_RE.search(_metrics(tmp_path))
    assert good is not None
    prior = good.group(1)
    # Then a run that dumps fine but fails to reach off-host must PRESERVE (not
    # overwrite/advance) the previous last-success timestamp.
    with pytest.raises(RuntimeError):
        _run(tmp_path, FakeRestic(fail_on="backup_dir"))
    after = _LAST_SUCCESS_RE.search(_metrics(tmp_path))
    assert after is not None and after.group(1) == prior  # unchanged


def test_manifest_written_with_required_metadata(tmp_path: Path) -> None:
    # Capture the manifest by making backup_dir read it before the work dir is wiped.
    seen: dict[str, object] = {}

    class CapturingRestic(FakeRestic):
        def backup_dir(self, path: Path, tags: object = ()) -> str:
            seen.update(json.loads((path / "manifest.json").read_text()))
            return super().backup_dir(path, tags)

    _run(tmp_path, CapturingRestic())
    assert seen["alembic_revision"] == "0014_dr_restore_events"
    assert seen["pg_version"] == "16.2"
    blob = json.dumps(seen).lower()
    assert "password" not in blob and "://" not in blob  # secret-free
