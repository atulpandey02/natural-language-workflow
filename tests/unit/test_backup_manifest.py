"""Backup manifest: integrity hashes, required metadata, secret-free (P2)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from nlw.backup.config import BACKUP_FORMAT_VERSION
from nlw.backup.manifest import (
    assert_manifest_is_secret_free,
    build_manifest,
    sha256_file,
    verify_manifest,
    write_manifest,
)


def _files(tmp_path: Path) -> dict[str, Path]:
    db = tmp_path / "db.dump"
    db.write_bytes(b"PGDMP-fake-dump")
    glob = tmp_path / "globals.sql"
    glob.write_text("-- roles only, no passwords\n")
    return {"db.dump": db, "globals.sql": glob}


def _manifest(tmp_path: Path) -> dict[str, object]:
    return build_manifest(
        started_at=datetime(2026, 5, 1, tzinfo=UTC),
        completed_at=datetime(2026, 5, 1, 0, 1, tzinfo=UTC),
        files=_files(tmp_path),
        alembic_revision="0014_dr_restore_events",
        app_version="abc123",
        pg_version="16.2",
        database_name="nlw",
        tool_versions={"pg_dump": "pg_dump (PostgreSQL) 16.2", "restic": "restic 0.16.4"},
    )


def test_manifest_has_required_metadata(tmp_path: Path) -> None:
    m = _manifest(tmp_path)
    assert m["format"] == BACKUP_FORMAT_VERSION
    assert m["alembic_revision"] == "0014_dr_restore_events"
    assert m["pg_version"] == "16.2"
    assert m["database"] == "nlw"
    artifacts: dict[str, dict[str, object]] = m["artifacts"]  # type: ignore[assignment]
    assert set(artifacts) == {"db.dump", "globals.sql"}
    for art in artifacts.values():
        assert len(str(art["sha256"])) == 64 and int(art["bytes"]) > 0  # type: ignore[call-overload]
    tools: dict[str, object] = m["tools"]  # type: ignore[assignment]
    assert "pg_dump" in tools and "restic" in tools


def test_manifest_is_secret_free_check_catches_secrets() -> None:
    assert_manifest_is_secret_free({"format": BACKUP_FORMAT_VERSION, "note": "safe"})
    for leak in (
        {"password": "hunter2"},
        {"url": "postgresql://u:p@h/db"},
        {"token": "xoxb-abc"},
        {"x": "the passphrase is here"},
    ):
        with pytest.raises(ValueError):
            assert_manifest_is_secret_free(leak)


def test_verify_manifest_detects_tampering(tmp_path: Path) -> None:
    files = _files(tmp_path)
    m = build_manifest(
        started_at=datetime(2026, 5, 1, tzinfo=UTC),
        completed_at=datetime(2026, 5, 1, tzinfo=UTC),
        files=files,
        alembic_revision="r",
        app_version=None,
        pg_version="16",
        database_name="nlw",
        tool_versions={},
    )
    verify_manifest(m, files)  # matches
    files["db.dump"].write_bytes(b"tampered")  # corrupt after hashing
    with pytest.raises(ValueError, match="integrity check failed"):
        verify_manifest(m, files)
    # Missing artifact.
    with pytest.raises(ValueError, match="missing artifact"):
        verify_manifest(m, {"nope.dump": files["db.dump"], "globals.sql": files["globals.sql"]})
    # Wrong format.
    with pytest.raises(ValueError, match="unexpected backup format"):
        verify_manifest({**m, "format": "other/9"}, files)


def test_write_manifest_is_secret_free_and_0600(tmp_path: Path) -> None:
    path = write_manifest(_manifest(tmp_path), tmp_path)
    assert (path.stat().st_mode & 0o777) == 0o600
    assert sha256_file(path)  # readable
