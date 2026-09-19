"""End-to-end: enqueue advance_run -> Redis -> real worker subprocess chains a
run to completion, against real Postgres (worker as nlw_worker) and Redis.
"""

import os
import subprocess
import sys
import time
import uuid
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy import text
from testcontainers.community.redis import RedisContainer

from nlw.core.config import Settings
from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.runs import create_run, create_workflow_with_version
from nlw.worker.actors import advance_run
from nlw.worker.broker import make_broker

pytestmark = pytest.mark.integration

_PLAN = WorkflowPlan.model_validate(
    {
        "steps": [
            {"id": "a", "tool": "fake.echo", "args": {"step": "a"}},
            {"id": "b", "tool": "fake.echo", "args": {"step": "b"}, "depends_on": ["a"]},
            {"id": "c", "tool": "fake.echo", "args": {"step": "c"}, "depends_on": ["b"]},
        ]
    }
)


def _seed(pg_stack: SimpleNamespace) -> uuid.UUID:
    member = pg_stack.seed_member()
    engine = create_sync_engine(pg_stack.settings)
    try:
        sm = create_sync_sessionmaker(engine)
        with sm() as s, s.begin():
            s.execute(
                text("SELECT set_config('app.user_id', :u, true)"), {"u": str(member.user_id)}
            )
            s.execute(
                text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(member.tenant_id)}
            )
            wf, ver = create_workflow_with_version(s, member.tenant_id, "wf", _PLAN)
            run = create_run(s, member.tenant_id, wf.id, ver.id)
            return run.id
    finally:
        engine.dispose()


def test_worker_subprocess_runs_to_completion(pg_stack: SimpleNamespace) -> None:
    run_id = _seed(pg_stack)

    with RedisContainer("redis:7") as redis_c:
        redis_url = f"redis://{redis_c.get_container_host_ip()}:{redis_c.get_exposed_port(6379)}/0"
        worker = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "dramatiq",
                "nlw.worker.actors",
                "--processes",
                "1",
                "--threads",
                "1",
            ],
            env={
                **os.environ,
                "APP_ENV": "local",
                "REDIS_URL": redis_url,
                "DATABASE_URL": pg_stack.worker_settings.database_url,
            },
        )
        try:
            broker = make_broker(Settings(_env_file=None, redis_url=redis_url))  # type: ignore[call-arg]
            broker.declare_queue("default")
            broker.enqueue(advance_run.message(str(run_id)))

            deadline = time.time() + 30
            status = None
            while time.time() < deadline:
                with psycopg.connect(pg_stack.owner_libpq) as c:
                    row = c.execute(
                        "SELECT status FROM workflow_runs WHERE id=%s", (run_id,)
                    ).fetchone()
                status = row[0] if row else None
                if status in ("COMPLETED", "FAILED"):
                    break
                time.sleep(0.3)
        finally:
            worker.terminate()
            worker.wait(timeout=10)

    assert status == "COMPLETED"
    with psycopg.connect(pg_stack.owner_libpq) as c:
        rows = c.execute(
            "SELECT status, attempt FROM step_runs WHERE run_id=%s", (run_id,)
        ).fetchall()
    assert len(rows) == 3
    assert all(r[0] == "SUCCESS" and r[1] == 1 for r in rows)
