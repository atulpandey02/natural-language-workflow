"""The isolated profiler process is always stopped and reaped (review follow-up).

Normal exit, cancellation while the child is reading, cancellation while it is
returning its result, the wall-clock timeout, and a child that ignores SIGTERM:
in every case the parent ends with the child's exit status collected (no
zombie) and no process left behind (no orphan). Misbehaving children are
substituted through ``ingestion._runner_argv``; synchronization is by marker
files, not by sleeping and hoping.
"""

import asyncio
import io
import json
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from nlw.datasets import ingestion
from nlw.ingest.strict import StrictLimits

CSV = b"region,amount\n" + b"".join(f"r{i % 3},{i}\n".encode() for i in range(30))


def _config(timeout_s: float = 30) -> ingestion.IngestionConfig:
    return ingestion.IngestionConfig(limits=StrictLimits(timeout_s=timeout_s), memory_mb=768)


@pytest.fixture
def spawned(monkeypatch: pytest.MonkeyPatch) -> list[asyncio.subprocess.Process]:
    procs: list[asyncio.subprocess.Process] = []
    real = asyncio.create_subprocess_exec

    async def capture(*a: Any, **k: Any) -> asyncio.subprocess.Process:
        p = await real(*a, **k)
        procs.append(p)
        return p

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture)
    return procs


def _child(monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    monkeypatch.setattr(ingestion, "_runner_argv", lambda _args: [sys.executable, "-c", code])


def _gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def _assert_reaped(proc: asyncio.subprocess.Process) -> None:
    assert proc.returncode is not None, "exit status never collected"
    assert _gone(proc.pid), "the child process still exists"


async def _wait_for(path: Path) -> None:
    for _ in range(400):
        if path.exists():
            return
        await asyncio.sleep(0.025)
    raise AssertionError(f"marker {path.name} never appeared")


async def test_normal_exit_is_reaped(spawned: list[asyncio.subprocess.Process]) -> None:
    outcome = await ingestion.run_profiler(lambda: io.BytesIO(CSV), _config())
    assert outcome.status == "profiled"
    _assert_reaped(spawned[0])
    assert spawned[0].returncode == 0


async def test_cancellation_while_the_child_is_reading_terminates_it(
    spawned: list[asyncio.subprocess.Process],
) -> None:
    release = threading.Event()

    class Blocking(io.RawIOBase):
        def readable(self) -> bool:
            return True

        def read(self, n: int | None = -1) -> bytes:
            release.wait(10)
            return b""

    def opener() -> Any:
        return Blocking()

    task = asyncio.create_task(ingestion.run_profiler(opener, _config()))
    for _ in range(200):
        if spawned:
            break
        await asyncio.sleep(0.025)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    _assert_reaped(spawned[0])
    assert spawned[0].returncode == -signal.SIGTERM


async def test_cancellation_while_the_child_returns_its_result_terminates_it(
    spawned: list[asyncio.subprocess.Process],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker = tmp_path / "read-all"
    _child(
        monkeypatch,
        "import sys, time, pathlib\n"
        "sys.stdin.buffer.read()\n"
        f"pathlib.Path({str(marker)!r}).touch()\n"
        "time.sleep(60)\n"
        "print('{}')\n",
    )
    task = asyncio.create_task(ingestion.run_profiler(lambda: io.BytesIO(CSV), _config()))
    await _wait_for(marker)  # input fully consumed; the child is "computing"
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    _assert_reaped(spawned[0])


async def test_timeout_terminates_the_child_and_reports_parse_timeout(
    spawned: list[asyncio.subprocess.Process], monkeypatch: pytest.MonkeyPatch
) -> None:
    _child(monkeypatch, "import sys, time\nsys.stdin.buffer.read()\ntime.sleep(60)\n")
    monkeypatch.setattr(ingestion, "_TERM_GRACE_S", 2.0)
    cfg = ingestion.IngestionConfig(limits=StrictLimits(timeout_s=0.001), memory_mb=768)
    # The parent's wall clock is timeout_s + 10: keep the test fast but real.
    real_timeout = asyncio.timeout
    monkeypatch.setattr(asyncio, "timeout", lambda _s: real_timeout(0.5))
    outcome = await ingestion.run_profiler(lambda: io.BytesIO(CSV), cfg)
    assert (outcome.status, outcome.code) == ("rejected", "PARSE_TIMEOUT")
    _assert_reaped(spawned[0])


async def test_a_child_ignoring_sigterm_is_force_killed_within_the_grace(
    spawned: list[asyncio.subprocess.Process],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker = tmp_path / "ignoring"
    _child(
        monkeypatch,
        "import signal, time, pathlib\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"pathlib.Path({str(marker)!r}).touch()\n"
        "time.sleep(60)\n",
    )
    monkeypatch.setattr(ingestion, "_TERM_GRACE_S", 0.3)
    task = asyncio.create_task(ingestion.run_profiler(lambda: io.BytesIO(CSV), _config()))
    await _wait_for(marker)  # SIGTERM is ignored from here on
    task.cancel()
    loop = asyncio.get_running_loop()
    started = loop.time()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert loop.time() - started < 5  # bounded: grace + kill, never the child's 60 s
    _assert_reaped(spawned[0])
    assert spawned[0].returncode == -signal.SIGKILL


async def test_the_child_environment_carries_no_credentials(
    monkeypatch: pytest.MonkeyPatch, spawned: list[asyncio.subprocess.Process], tmp_path: Path
) -> None:
    for name in ("DATABASE_URL", "DATABASE_MIGRATION_URL", "NLW_LLM_API_KEY", "RESTIC_PASSWORD"):
        monkeypatch.setenv(name, "zz-canary-credential")
    out = tmp_path / "env.json"
    _child(
        monkeypatch,
        f"import json, os\njson.dump(dict(os.environ), open({str(out)!r}, 'w'))\nprint('{{}}')\n",
    )
    await ingestion.run_profiler(lambda: io.BytesIO(CSV), _config())
    env = json.loads(out.read_text())
    assert "zz-canary-credential" not in json.dumps(env)
    assert set(env) <= {
        "PATH",
        "LANG",
        "LC_ALL",
        "SYSTEMROOT",
        "TMPDIR",
        "PYTHONHASHSEED",
        "PYTHONDONTWRITEBYTECODE",
        "__CF_USER_TEXT_ENCODING",
        "LC_CTYPE",
    }  # fmt: skip (LC_CTYPE: set by the interpreter's locale coercion)
    _assert_reaped(spawned[0])
