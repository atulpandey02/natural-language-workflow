"""Pre-deployment backup evidence gate (M12A-Prep §G).

Consumes the non-secret evidence the P2 backup path already produces — the
node_exporter metrics textfile (``nlw_backup.prom``) and restic's snapshot
listing (id, time, hostname, ``nlw-db`` / ``rev-<revision>`` tags) — plus the
sanitized repository location, and decides whether a REAL, VERIFIED, OFF-HOST
backup of the pre-upgrade schema exists. ``pg_dump`` success alone is never
enough: the last-success timestamp advances only on a verified off-host
snapshot, and that is the field this gate trusts.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from nlw.backup.metrics_file import parse_metrics_text

_FIXTURE_HOSTS = ("minio", "localhost", "localhost.localdomain")
_FIXTURE_HOST_PARTS = ("minio", "drill", "fixture", "test")


class BackupEvidenceError(ValueError):
    """No acceptable pre-deployment backup evidence."""


@dataclass(frozen=True)
class SnapshotEvidence:
    snapshot_id: str
    time: datetime
    hostname: str
    tags: tuple[str, ...]

    @property
    def source_revision(self) -> str | None:
        for t in self.tags:
            if t.startswith("rev-"):
                return t[4:]
        return None


@dataclass(frozen=True)
class BackupEvidence:
    repository: str  # sanitized restic repository (scheme + host + path; no credentials)
    metrics_text: str
    snapshot: SnapshotEvidence | None
    artifact_names: tuple[str, ...]  # files inside the latest snapshot (names only)

    def summary(self) -> dict[str, Any]:
        return {
            "repository_host": repository_host(self.repository),
            "snapshot_id": self.snapshot.snapshot_id if self.snapshot else None,
            "snapshot_time": self.snapshot.time.isoformat() if self.snapshot else None,
            "snapshot_hostname": self.snapshot.hostname if self.snapshot else None,
            "source_revision": self.snapshot.source_revision if self.snapshot else None,
            "artifacts": list(self.artifact_names),
        }


def redact_repository(repo: str) -> str:
    """Never echo credentials that may be embedded in a repository URL."""
    return re.sub(r"://[^/@]+@", "://<redacted>@", repo)


def repository_host(repo: str) -> str:
    """``host[:port]`` of an ``s3:https://host/...`` repository (no scheme, path or
    credentials); the raw value for anything else is never returned."""
    if repo.startswith("s3:"):
        url = urlparse(repo[3:])
        if url.hostname:
            return f"{url.hostname}:{url.port}" if url.port else url.hostname
    return "<non-s3-repository>"


def parse_snapshots_json(doc: object) -> SnapshotEvidence | None:
    """restic ``snapshots --json --latest 1`` -> the newest snapshot or None."""
    if not isinstance(doc, list) or not doc:
        return None
    newest: dict[str, Any] | None = None
    for item in doc:
        if not isinstance(item, dict) or "time" not in item or "id" not in item:
            raise BackupEvidenceError("malformed restic snapshot entry")
        if newest is None or str(item["time"]) > str(newest["time"]):
            newest = item
    assert newest is not None
    try:
        ts = datetime.fromisoformat(str(newest["time"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise BackupEvidenceError("restic snapshot time is not ISO-8601") from exc
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return SnapshotEvidence(
        snapshot_id=str(newest["id"]),
        time=ts.astimezone(UTC),
        hostname=str(newest.get("hostname", "")),
        tags=tuple(str(t) for t in newest.get("tags") or ()),
    )


def check_repository_is_off_host(repository: str) -> None:
    """A production gate accepts only an S3-compatible HTTPS endpoint that is not
    loopback, private, link-local or an obvious local fixture. Local paths,
    SFTP-to-self, REST servers on the host, and MinIO drills never qualify."""
    if not repository.startswith("s3:"):
        raise BackupEvidenceError("backup repository must be an s3: object store (off-host)")
    url = urlparse(repository[3:])
    if url.scheme != "https" or not url.hostname:
        raise BackupEvidenceError("backup repository must use https:// (s3:https://host/bucket)")
    host = url.hostname.lower()
    if host in _FIXTURE_HOSTS or any(part in host.split(".") for part in _FIXTURE_HOST_PARTS):
        raise BackupEvidenceError(f"backup repository host {host!r} is a local/test fixture")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (
        ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_unspecified
    ):
        raise BackupEvidenceError("backup repository host is not a public object store")
    if "." not in host:
        raise BackupEvidenceError("backup repository host must be a fully-qualified endpoint")
    if not url.path.strip("/"):
        raise BackupEvidenceError("backup repository must name a bucket/path")


def evaluate_backup_evidence(
    ev: BackupEvidence,
    *,
    expected_source_revision: str,
    expected_hostname: str | None,
    max_age: timedelta,
    now: datetime,
    allow_fixture_repository: bool = False,
) -> dict[str, Any]:
    """Return a non-secret evidence record or raise ``BackupEvidenceError``.
    ``allow_fixture_repository`` exists ONLY for the disposable local rehearsal;
    a production gate never passes it."""
    if allow_fixture_repository:
        if not ev.repository.startswith("s3:"):
            raise BackupEvidenceError("even a fixture repository must be an s3: object store")
    else:
        check_repository_is_off_host(ev.repository)
    m = parse_metrics_text(ev.metrics_text)
    if m.success is not True:
        raise BackupEvidenceError("last backup job did not succeed (nlw_backup_success != 1)")
    if m.verify_success is not True:
        raise BackupEvidenceError("repository verification did not pass (verify_success != 1)")
    if m.last_success is None:
        raise BackupEvidenceError("no verified off-host backup recorded (last_success absent)")
    last = datetime.fromtimestamp(m.last_success, tz=UTC)
    if now - last > max_age:
        raise BackupEvidenceError(f"verified backup is too old ({(now - last)!s} > {max_age!s})")
    if ev.snapshot is None:
        raise BackupEvidenceError("no restic snapshot listed in the repository")
    if abs((ev.snapshot.time - last).total_seconds()) > 3600:
        raise BackupEvidenceError("newest snapshot does not correspond to the verified backup")
    if ev.snapshot.source_revision != expected_source_revision:
        raise BackupEvidenceError(
            f"snapshot source revision {ev.snapshot.source_revision!r} != expected pre-deployment "
            f"revision {expected_source_revision!r}"
        )
    if "nlw-db" not in ev.snapshot.tags:
        raise BackupEvidenceError("snapshot is not tagged as an nlw database backup")
    if expected_hostname and ev.snapshot.hostname and ev.snapshot.hostname != expected_hostname:
        raise BackupEvidenceError("snapshot was taken on a different host/environment")
    for name in ev.artifact_names:
        if name.endswith(".key") or "ctx-keys" in name or name.endswith(".pem"):
            raise BackupEvidenceError(f"backup contains a key-like artifact: {name}")
    return {
        "verified_at": last.isoformat(),
        "snapshot_id": ev.snapshot.snapshot_id,
        "snapshot_time": ev.snapshot.time.isoformat(),
        "source_revision": ev.snapshot.source_revision,
        "hostname": ev.snapshot.hostname,
        # Host only: the rollout state file refuses anything URL-shaped, and the
        # host is all an operator needs to correlate with the provider console.
        "repository_host": repository_host(ev.repository),
        "artifacts": list(ev.artifact_names),
    }
