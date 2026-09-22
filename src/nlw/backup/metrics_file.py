"""Host-readable backup metrics for the node_exporter textfile collector (P2).

The one-shot backup container cannot be scraped directly, so it writes a Prometheus
textfile that a host node_exporter (``--collector.textfile.directory``) exposes.

Trust boundary: the file is written by the backup job (owner of the textfile dir)
and read by node_exporter; nothing tenant-controlled is written, and there are no
high-cardinality labels (no tenant id, snapshot id, filename, bucket, endpoint, or
exception text). The write is ATOMIC (temp file + ``os.replace``) so a scrape never
sees a half-written file.

Critically, ``nlw_backup_last_success_timestamp_seconds`` advances ONLY on a fully
verified off-host success; a failed run preserves the previous value, so a local
dump that never reached the repository can never masquerade as a fresh backup.
"""

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

_LAST_SUCCESS_RE = re.compile(
    r"^nlw_backup_last_success_timestamp_seconds\s+([0-9.eE+-]+)\s*$", re.MULTILINE
)


@dataclass(frozen=True)
class BackupMetrics:
    success: bool  # the whole job (dump + off-host + verify + retention)
    duration_seconds: float
    verify_success: bool
    retention_success: bool
    verified_off_host: bool  # dump reached the repo AND the snapshot read back OK


def _read_previous_last_success(path: Path) -> float | None:
    try:
        m = _LAST_SUCCESS_RE.search(path.read_text())
    except OSError:
        return None
    return float(m.group(1)) if m else None


def render(metrics: BackupMetrics, *, now: float, previous_last_success: float | None) -> str:
    # Advance last-success ONLY when the backup verifiably reached off-host storage.
    last_success = now if metrics.verified_off_host else previous_last_success
    lines = [
        "# HELP nlw_backup_success Whether the last backup run fully succeeded (1) or failed (0).",
        "# TYPE nlw_backup_success gauge",
        f"nlw_backup_success {1 if metrics.success else 0}",
        "# HELP nlw_backup_duration_seconds Duration of the last backup run.",
        "# TYPE nlw_backup_duration_seconds gauge",
        f"nlw_backup_duration_seconds {metrics.duration_seconds:.3f}",
        "# HELP nlw_backup_repository_verify_success Whether repository verification passed.",
        "# TYPE nlw_backup_repository_verify_success gauge",
        f"nlw_backup_repository_verify_success {1 if metrics.verify_success else 0}",
        "# HELP nlw_backup_retention_success Whether retention pruning succeeded.",
        "# TYPE nlw_backup_retention_success gauge",
        f"nlw_backup_retention_success {1 if metrics.retention_success else 0}",
        "# HELP nlw_backup_last_success_timestamp_seconds Unix time of last verified backup.",
        "# TYPE nlw_backup_last_success_timestamp_seconds gauge",
    ]
    if last_success is not None:
        lines.append(f"nlw_backup_last_success_timestamp_seconds {last_success:.0f}")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class ParsedBackupMetrics:
    """The gauges a consumer (alerts, the rollout backup gate) reads back."""

    success: bool | None
    verify_success: bool | None
    retention_success: bool | None
    last_success: float | None


def parse_metrics_text(text: str) -> ParsedBackupMetrics:
    """Parse the exposition this module renders. Missing samples -> None (never
    assumed true)."""

    def gauge(name: str) -> float | None:
        m = re.search(rf"^{re.escape(name)}\s+([0-9.eE+-]+)\s*$", text, re.MULTILINE)
        return float(m.group(1)) if m else None

    def flag(name: str) -> bool | None:
        v = gauge(name)
        return None if v is None else v == 1.0

    return ParsedBackupMetrics(
        success=flag("nlw_backup_success"),
        verify_success=flag("nlw_backup_repository_verify_success"),
        retention_success=flag("nlw_backup_retention_success"),
        last_success=gauge("nlw_backup_last_success_timestamp_seconds"),
    )


def write_metrics(path_str: str, metrics: BackupMetrics, *, now: float | None = None) -> None:
    now = time.time() if now is None else now
    path = Path(path_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = _read_previous_last_success(path)
    content = render(metrics, now=now, previous_last_success=previous)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content)
    os.replace(tmp, path)  # atomic within the same directory
