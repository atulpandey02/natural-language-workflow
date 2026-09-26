"""Real worker startup integration for the DR recovery lock.

Launches the REAL production entrypoint (``python -m dramatiq nlw.worker.actors``,
the same command Compose runs) against a real throwaway Postgres (testcontainers,
migrated to head, ``nlw_worker`` role) and a real throwaway Redis, and proves:

  locked (quiesced / validated-not-enabled)  -> process exits non-zero, never ready
  unknown (unreachable database)              -> process exits non-zero, never ready
  never restored                              -> reaches "ready for action"
  newest generation validated + enabled       -> reaches "ready for action"
  a later un-enabled generation               -> refused again
  container healthcheck while locked          -> exit 1 with the recovery_lock reason

No message is ever processed and no production database is touched.
"""

import os
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy import create_engine
from testcontainers.community.redis import RedisContainer

from nlw.backup.quiescence import quiesce
from nlw.backup.recovery_lock import enable_runtime, mark_validated

pytestmark = pytest.mark.integration

_PROJECT = "nlw-dr-project"
_READY = "Worker process is ready for action."
_WORKER_CMD = [
    sys.executable,
    "-m",
    "dramatiq",
    "nlw.worker.actors",
    "--processes",
    "1",
    "--threads",
    "1",
]


@pytest.fixture
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:7") as container:
        yield f"redis://{container.get_container_host_ip()}:{container.get_exposed_port(6379)}/0"


def _env(database_url: str, redis_url: str) -> dict[str, str]:
    return {
        **os.environ,
        "DATABASE_URL": database_url,
        "REDIS_URL": redis_url,
        "APP_ENV": "local",
        "METRICS_ENABLED": "false",
    }


def _spawn(
    env: dict[str, str], argv: list[str] | None = None
) -> tuple[subprocess.Popen[bytes], Path]:
    out = Path(tempfile.mkstemp(prefix="nlw-worker-boot-", suffix=".log")[1])
    proc = subprocess.Popen(
        argv or _WORKER_CMD,
        env=env,
        stdout=open(out, "wb"),  # noqa: SIM115 - handed to the child for its lifetime
        stderr=subprocess.STDOUT,
    )
    return proc, out


def _expect_refused(env: dict[str, str]) -> tuple[int, str]:
    proc, out = _spawn(env)
    try:
        code = proc.wait(timeout=90)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)
        pytest.fail(f"worker did not exit on its own; output:\n{out.read_text()}")
    text = out.read_text()
    assert code != 0, f"worker exited 0 against a locked/unknown database:\n{text}"
    assert "WorkerBootRefused" in text, text
    assert _READY not in text, f"worker reported ready despite refusal:\n{text}"
    return code, text


def _expect_ready(env: dict[str, str]) -> str:
    proc, out = _spawn(env)
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            text = out.read_text()
            if _READY in text:
                return text
            if proc.poll() is not None:
                pytest.fail(f"worker exited {proc.returncode} before becoming ready:\n{text}")
            time.sleep(0.2)
        pytest.fail(f"worker never became ready:\n{out.read_text()}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def _assert_sanitized(text: str, database_url: str) -> None:
    assert database_url not in text
    assert "postgresql+psycopg://" not in text
    assert "postgresql://" not in text


def test_locked_and_unknown_states_refuse_boot_never_restored_boots(
    pg_stack: SimpleNamespace, redis_url: str
) -> None:
    worker_url = pg_stack.worker_settings.database_url
    env = _env(worker_url, redis_url)

    # Never restored: the ordinary boot path is reached (control).
    _expect_ready(env)

    # A restore generation exists but is NOT validated -> refused.
    owner = create_engine(pg_stack.owner_sa)
    qr = quiesce(owner)
    assert qr.event_id is not None
    code_locked, text_locked = _expect_refused(env)
    assert "RecoveryLocked" in text_locked and "not validated" in text_locked
    _assert_sanitized(text_locked, worker_url)

    # Validated but NOT operator-enabled -> still refused.
    mark_validated(owner, qr.event_id, target_project=_PROJECT)
    code_locked2, text_locked2 = _expect_refused(env)
    assert "not operator-enabled" in text_locked2

    # The container healthcheck must not report healthy while locked, and it
    # names the recovery lock as the reason (class only).
    hc = subprocess.run(
        [sys.executable, "-m", "nlw.ops.healthcheck"], env=env, capture_output=True, text=True
    )
    assert hc.returncode == 1
    assert "healthcheck recovery_lock failed: RecoveryLocked" in hc.stderr
    _assert_sanitized(hc.stderr, worker_url)

    # Unknown: the database cannot be reached at all -> refused (fail closed).
    unknown_env = _env("postgresql+psycopg://nlw_worker:nlw_worker@127.0.0.1:1/nlw", redis_url)
    code_unknown, text_unknown = _expect_refused(unknown_env)
    assert "RecoveryStateUnknown" in text_unknown
    _assert_sanitized(text_unknown, "postgresql+psycopg://nlw_worker:nlw_worker@127.0.0.1:1/nlw")

    # The exit status is stable and non-zero across refusal reasons.
    assert code_locked == code_locked2 == code_unknown
    assert code_locked != 0


def test_enabled_generation_boots_and_a_later_generation_relocks(
    pg_stack: SimpleNamespace, redis_url: str
) -> None:
    worker_url = pg_stack.worker_settings.database_url
    env = _env(worker_url, redis_url)
    owner = create_engine(pg_stack.owner_sa)

    qr1 = quiesce(owner)
    assert qr1.event_id is not None
    mark_validated(owner, qr1.event_id, target_project=_PROJECT)
    enable_runtime(owner, event_id=qr1.event_id, confirm_project=_PROJECT, operator="op")
    _expect_ready(env)  # validated AND enabled -> normal boot

    # A later restore (changed state -> a new, un-enabled generation) re-locks.
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
    qr2 = quiesce(owner)
    assert qr2.event_id is not None and qr2.event_id != qr1.event_id
    code, text = _expect_refused(env)
    assert "RecoveryLocked" in text
    assert code != 0
