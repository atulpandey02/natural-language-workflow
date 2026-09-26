"""Thin, testable wrapper around the ``restic`` CLI (M11.5 P2).

Restic is a mature client-side-encrypted, deduplicating backup tool with native
S3-compatible backends (AWS S3, Backblaze B2, MinIO) and repository-side retention
(``forget --prune``). We do NOT implement custom cryptography — restic encrypts the
repository with ``RESTIC_PASSWORD``.

Secrets are passed to restic via the ENVIRONMENT (``RESTIC_PASSWORD``,
``AWS_*``), never on argv (so they can't appear in a process listing). The command
runner is injectable so unit tests can simulate failures without a real repository;
integration/drill runs use the real subprocess against MinIO.
"""

import json
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# A runner takes (argv, env) and returns (returncode, stdout, stderr). No secret
# is ever placed in argv; env carries restic's credentials.
Runner = Callable[[Sequence[str], dict[str, str]], "ResticResult"]


@dataclass(frozen=True)
class ResticResult:
    returncode: int
    stdout: str
    stderr: str


class ResticError(RuntimeError):
    """A restic operation failed. Message is sanitized (no repo password)."""


def _subprocess_runner(argv: Sequence[str], env: dict[str, str]) -> ResticResult:
    proc = subprocess.run(list(argv), env=env, capture_output=True, text=True, check=False)
    return ResticResult(proc.returncode, proc.stdout, proc.stderr)


class Restic:
    def __init__(self, env: dict[str, str], runner: Runner | None = None) -> None:
        self._env = env
        self._run = runner or _subprocess_runner

    def _restic(self, *args: str) -> ResticResult:
        res = self._run(["restic", "--json", *args], self._env)
        return res

    def _restic_checked(self, *args: str, what: str) -> ResticResult:
        res = self._restic(*args)
        if res.returncode != 0:
            # NEVER echo the repo password / env; restic's stderr is safe-ish but we
            # keep the message to the operation name + return code.
            raise ResticError(f"restic {what} failed (exit {res.returncode})")
        return res

    def ensure_repository(self) -> None:
        """Initialize the repository if it does not already exist (idempotent)."""
        cat = self._restic("cat", "config")
        if cat.returncode == 0:
            return
        self._restic_checked("init", what="init")

    def backup_dir(self, path: Path, tags: Sequence[str] = ()) -> str:
        """Snapshot ``path``; return the created snapshot short id."""
        args = ["backup", str(path)]
        for t in tags:
            args += ["--tag", t]
        res = self._restic_checked(*args, what="backup")
        # restic --json emits one JSON object per line; the summary carries the id.
        snapshot_id = ""
        for line in res.stdout.splitlines():
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if obj.get("message_type") == "summary" and obj.get("snapshot_id"):
                snapshot_id = str(obj["snapshot_id"])
        return snapshot_id

    def check(self) -> None:
        """Verify repository structure + that pack files are intact."""
        self._restic_checked("check", what="check")

    def snapshot_exists(self, snapshot_id: str) -> bool:
        res = self._restic("snapshots", snapshot_id)
        return res.returncode == 0

    def latest_snapshots(self, *, tag: str = "nlw-db") -> list[dict[str, Any]]:
        """Non-secret metadata (id, time, hostname, tags) of the newest snapshot(s)
        carrying ``tag``, NEWEST FIRST; ``[]`` when the repository has none.

        ``restic snapshots --latest 1`` keeps the latest snapshot PER host+paths
        group, and every one-shot backup container has its own hostname, so a
        repository written by several rollouts/timer runs answers with several
        entries in repository order. Callers take ``[0]`` as "the newest": sort by
        time so the evidence (manifest, artifact names) belongs to the newest
        snapshot — the one the pre-deployment gate binds to."""
        res = self._restic_checked("snapshots", "--tag", tag, "--latest", "1", what="snapshots")
        try:
            doc = json.loads(res.stdout or "[]")
        except ValueError as exc:
            raise ResticError("restic snapshots returned malformed JSON") from exc
        if not isinstance(doc, list):
            raise ResticError("restic snapshots returned a non-list")
        snaps = [
            {
                "id": str(s.get("id", "")),
                "short_id": str(s.get("short_id", "")),
                "time": str(s.get("time", "")),
                "hostname": str(s.get("hostname", "")),
                "tags": [str(t) for t in (s.get("tags") or [])],
            }
            for s in doc
            if isinstance(s, dict)
        ]
        return sorted(snaps, key=_snapshot_time, reverse=True)

    def snapshot_manifest(self, snapshot_id: str) -> dict[str, Any] | None:
        """The ``manifest.json`` INSIDE a snapshot (parsed), or None if absent.
        Read straight from the repository — never from a host file."""
        res = self._restic_checked("ls", snapshot_id, what="ls")
        path = ""
        for line in res.stdout.splitlines():
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if obj.get("struct_type") == "node" and obj.get("name") == "manifest.json":
                path = str(obj.get("path", ""))
        if not path:
            return None
        dumped = self._restic_checked("dump", snapshot_id, path, what="dump")
        try:
            doc = json.loads(dumped.stdout)
        except ValueError as exc:
            raise ResticError("manifest.json inside the snapshot is not valid JSON") from exc
        return doc if isinstance(doc, dict) else None

    def snapshot_file_names(self, snapshot_id: str) -> list[str]:
        """Base names of the files inside a snapshot (no contents)."""
        res = self._restic_checked("ls", snapshot_id, what="ls")
        names: list[str] = []
        for line in res.stdout.splitlines():
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if obj.get("struct_type") == "node" and obj.get("type") == "file":
                names.append(str(obj.get("name", "")))
        return names

    def restore(self, snapshot: str, target: Path) -> None:
        self._restic_checked("restore", snapshot, "--target", str(target), what="restore")

    def forget_prune(self, *, daily: int, weekly: int, monthly: int) -> None:
        """Apply retention against the REPOSITORY (never shell globs) and prune."""
        self._restic_checked(
            "forget",
            "--keep-daily",
            str(daily),
            "--keep-weekly",
            str(weekly),
            "--keep-monthly",
            str(monthly),
            "--prune",
            what="forget/prune",
        )


def _snapshot_time(snap: dict[str, Any]) -> datetime:
    """ISO-8601 (restic emits RFC 3339 with nanoseconds) -> aware datetime; an
    unparseable time sorts oldest so a malformed entry is never "the newest"."""
    raw = str(snap.get("time", "")).replace("Z", "+00:00")
    # datetime.fromisoformat accepts at most 6 fractional digits.
    raw = re.sub(r"(\.\d{6})\d+", r"\1", raw)
    try:
        ts = datetime.fromisoformat(raw)
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)
