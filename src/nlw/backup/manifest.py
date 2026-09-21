"""Backup manifest: safe, non-secret provenance + integrity hashes (M11.5 P2).

The manifest is a small JSON document snapshotted alongside the dump. It carries
ONLY non-secret metadata (format/version/revision/hashes/tool versions) — never
passwords, connection URLs, tenant payloads, emails, connector config, tokens, or
secret values. Restic provides content-addressed repository integrity; the
manifest adds app-level provenance and an independent hash check at restore.
"""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nlw.backup.config import BACKUP_FORMAT_VERSION

MANIFEST_NAME = "manifest.json"

# Keys that must NEVER appear in a manifest (defence-in-depth check).
_FORBIDDEN_SUBSTRINGS = ("password", "secret", "token", "passphrase", "@", "://")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(
    *,
    started_at: datetime,
    completed_at: datetime,
    files: dict[str, Path],
    alembic_revision: str | None,
    app_version: str | None,
    pg_version: str | None,
    database_name: str,
    tool_versions: dict[str, str],
) -> dict[str, Any]:
    """Assemble the manifest dict. ``files`` maps a logical name -> path; each is
    hashed. No secret-bearing value is accepted here."""
    return {
        "format": BACKUP_FORMAT_VERSION,
        "started_at": started_at.astimezone(UTC).isoformat(),
        "completed_at": completed_at.astimezone(UTC).isoformat(),
        "alembic_revision": alembic_revision,
        "app_version": app_version,
        "pg_version": pg_version,
        "database": database_name,
        "artifacts": {
            name: {"bytes": path.stat().st_size, "sha256": sha256_file(path)}
            for name, path in sorted(files.items())
        },
        "tools": tool_versions,
    }


def assert_manifest_is_secret_free(manifest: dict[str, Any]) -> None:
    """Fail closed if any obviously secret-bearing token leaked into the manifest.
    (The manifest is assembled from safe fields, so this is defence-in-depth.)"""
    blob = json.dumps(manifest, default=str).lower()
    for needle in _FORBIDDEN_SUBSTRINGS:
        if needle in blob:
            raise ValueError(f"manifest may contain a secret-bearing value ({needle!r})")


def write_manifest(manifest: dict[str, Any], work_dir: Path) -> Path:
    assert_manifest_is_secret_free(manifest)
    path = work_dir / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    path.chmod(0o600)
    return path


def verify_manifest(manifest: dict[str, Any], files: dict[str, Path]) -> None:
    """Verify each recorded artifact's sha256 against the restored files. Raises on
    any mismatch, missing artifact, or format mismatch."""
    if manifest.get("format") != BACKUP_FORMAT_VERSION:
        raise ValueError(
            f"unexpected backup format {manifest.get('format')!r} "
            f"(expected {BACKUP_FORMAT_VERSION!r})"
        )
    recorded = manifest.get("artifacts", {})
    for name, path in files.items():
        if name not in recorded:
            raise ValueError(f"manifest missing artifact {name!r}")
        if not path.exists():
            raise ValueError(f"restored artifact {name!r} not found at {path}")
        actual = sha256_file(path)
        expected = recorded[name]["sha256"]
        if actual != expected:
            raise ValueError(f"integrity check failed for {name!r}: sha256 mismatch")
