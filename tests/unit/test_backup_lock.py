"""Multi-process single-execution backup lock (M11.5 P2 addendum A).

Uses REAL separate OS processes (multiprocessing 'spawn'), not two sequential
function calls, to prove that while one process holds the lock a second independent
backup fails fast and runs NO dump / upload / prune / metrics write — and that after
the first releases, a later backup can acquire the lock and complete.
"""

import multiprocessing as mp
import time
from pathlib import Path

from nlw.backup.backup import DbInfo, run_backup
from nlw.backup.config import BackupSettings
from nlw.backup.locking import BackupAlreadyRunning, backup_lock

_CTX = mp.get_context("spawn")


def _settings(tmp: str) -> BackupSettings:
    d = Path(tmp)
    return BackupSettings(
        app_env="local",
        NLW_BACKUP_DATABASE_URL="postgresql://nlw:pw@db/nlw",  # type: ignore[arg-type]
        NLW_BACKUP_WORK_DIR=str(d / "work"),
        NLW_BACKUP_METRICS_FILE=str(d / "m.prom"),
        NLW_BACKUP_LOCK_FILE=str(d / "backup.lock"),
    )


class _FakeRestic:
    """Records off-host operations by touching marker files under ``markers``."""

    def __init__(self, markers: Path) -> None:
        self.markers = markers

    def _mark(self, name: str) -> None:
        (self.markers / name).write_text("1")

    def ensure_repository(self) -> None:
        self._mark("ensure_repository")

    def backup_dir(self, path: Path, tags: object = ()) -> str:
        self._mark("backup_dir")
        return "snap-x"

    def check(self) -> None:
        self._mark("check")

    def snapshot_exists(self, snapshot_id: str) -> bool:
        return True

    def forget_prune(self, *, daily: int, weekly: int, monthly: int) -> None:
        self._mark("forget_prune")


def _dump(work: Path, url: str) -> dict[str, Path]:
    (work.parent / "dump_ran").write_text("1")
    db = work / "db.dump"
    db.write_bytes(b"dump")
    g = work / "globals.sql"
    g.write_text("-- roles\n")
    return {"db.dump": db, "globals.sql": g}


def _info(url: str) -> DbInfo:
    return DbInfo(pg_version="16.2", alembic_revision="0014_dr_restore_events", database_name="nlw")


def _hold_lock(tmp: str, ready: str, release: str) -> None:
    """Process 1: acquire the lock and BLOCK at a controlled seam until released."""
    with backup_lock(Path(tmp) / "backup.lock"):
        Path(ready).write_text("1")
        for _ in range(500):  # up to ~25s
            if Path(release).exists():
                return
            time.sleep(0.05)


def _attempt_backup(tmp: str, markers: str, result: str) -> None:
    """Independent process: try a full backup; record what happened."""
    settings = _settings(tmp)
    try:
        run_backup(
            settings,
            restic=_FakeRestic(Path(markers)),  # type: ignore[arg-type]
            dump_fn=_dump,
            db_info_fn=_info,
            tool_versions_fn=lambda: {"pg_dump": "16", "restic": "0.18"},
        )
        Path(result).write_text("ok")
    except BackupAlreadyRunning:
        Path(result).write_text("already_running")
    except Exception as exc:  # pragma: no cover - surface unexpected failures
        Path(result).write_text(f"error:{type(exc).__name__}")


def test_second_concurrent_backup_fails_fast_and_does_no_work(tmp_path: Path) -> None:
    tmp = str(tmp_path)
    markers = tmp_path / "markers"
    markers.mkdir()
    ready = tmp_path / "ready"
    release = tmp_path / "release"
    result = tmp_path / "result2"

    holder = _CTX.Process(target=_hold_lock, args=(tmp, str(ready), str(release)))
    holder.start()
    try:
        # Wait for process 1 to actually hold the lock.
        for _ in range(200):
            if ready.exists():
                break
            time.sleep(0.05)
        assert ready.exists(), "holder never acquired the lock"

        # (2)(3) second independent process must fail/defer within a bounded time.
        t0 = time.monotonic()
        p2 = _CTX.Process(target=_attempt_backup, args=(tmp, str(markers), str(result)))
        p2.start()
        p2.join(timeout=15)
        assert not p2.is_alive(), "second backup did not fail fast"
        elapsed = time.monotonic() - t0
        assert elapsed < 15

        # (1) it reported "already running" and (4) ran NO dump/upload/prune/metrics.
        assert result.read_text() == "already_running"
        assert not (tmp_path / "dump_ran").exists(), "second process must not run pg_dump"
        assert not any(markers.iterdir()), "second process must not touch the repository"
        assert not (tmp_path / "m.prom").exists(), "second process must not write metrics"
    finally:
        release.write_text("1")
        holder.join(timeout=15)

    # (5) after release, a later backup can acquire the lock and complete.
    result3 = tmp_path / "result3"
    markers3 = tmp_path / "markers3"
    markers3.mkdir()
    p3 = _CTX.Process(target=_attempt_backup, args=(tmp, str(markers3), str(result3)))
    p3.start()
    p3.join(timeout=20)
    assert not p3.is_alive()
    assert result3.read_text() == "ok"
    assert (markers3 / "backup_dir").exists() and (markers3 / "check").exists()
