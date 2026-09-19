"""Durable engine execution against real Postgres (app=nlw_app, worker=nlw_worker).

Seeds workflows/runs as nlw_app (under RLS), advances as nlw_worker (which
derives tenant via the SECURITY DEFINER resolver), and asserts durable,
idempotent, tenant-isolated, concurrency-safe behavior.
"""

import threading
import uuid
from collections import Counter
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy import text

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine import execution as execmod
from nlw.engine.execution import execute_advancement, process_advance
from nlw.engine.runs import create_run, create_workflow_with_version

pytestmark = pytest.mark.integration


def _plan(*step_ids: str, tool: str = "fake.echo") -> WorkflowPlan:
    steps = []
    prev: list[str] = []
    for sid in step_ids:
        steps.append({"id": sid, "tool": tool, "args": {"step": sid}, "depends_on": list(prev)})
        prev = [sid]
    return WorkflowPlan.model_validate({"steps": steps})


@pytest.fixture
def sms(pg_stack: SimpleNamespace) -> object:
    app_engine = create_sync_engine(pg_stack.settings)
    worker_engine = create_sync_engine(pg_stack.worker_settings)
    try:
        yield SimpleNamespace(
            app=create_sync_sessionmaker(app_engine),
            worker=create_sync_sessionmaker(worker_engine),
        )
    finally:
        app_engine.dispose()
        worker_engine.dispose()


def _seed(app_sm: object, tenant_id: uuid.UUID, plan: WorkflowPlan) -> uuid.UUID:
    with app_sm() as s, s.begin():  # type: ignore[operator]
        s.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)})
        wf, ver = create_workflow_with_version(s, tenant_id, "wf", plan)
        run = create_run(s, tenant_id, wf.id, ver.id)
        return run.id


def _steps(owner_libpq: str, run_id: uuid.UUID) -> dict[str, tuple[str, int]]:
    with psycopg.connect(owner_libpq) as c:
        rows = c.execute(
            "SELECT step_id, status, attempt FROM step_runs WHERE run_id=%s", (run_id,)
        ).fetchall()
    return {r[0]: (r[1], r[2]) for r in rows}


def _run_status(owner_libpq: str, run_id: uuid.UUID) -> str:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT status FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
    assert row is not None
    return str(row[0])


def test_happy_path_runs_to_completion(pg_stack: SimpleNamespace, sms: SimpleNamespace) -> None:
    run_id = _seed(sms.app, uuid.uuid4(), _plan("a", "b", "c"))
    results = []
    for _ in range(6):
        outcome = execute_advancement(sms.worker, run_id)
        results.append(outcome.result)
        if outcome.result in ("completed", "failed", "noop"):
            break
    assert results == ["advanced", "advanced", "advanced", "completed"]
    assert _run_status(pg_stack.owner_libpq, run_id) == "COMPLETED"
    steps = _steps(pg_stack.owner_libpq, run_id)
    assert steps == {"a": ("SUCCESS", 1), "b": ("SUCCESS", 1), "c": ("SUCCESS", 1)}


def test_duplicate_delivery_is_idempotent(pg_stack: SimpleNamespace, sms: SimpleNamespace) -> None:
    run_id = _seed(sms.app, uuid.uuid4(), _plan("a"))
    outcomes = [execute_advancement(sms.worker, run_id).result for _ in range(5)]
    # one advance, one completion, the rest no-ops; the step runs exactly once
    assert outcomes[0] == "advanced"
    assert "completed" in outcomes
    assert _steps(pg_stack.owner_libpq, run_id)["a"] == ("SUCCESS", 1)
    assert _run_status(pg_stack.owner_libpq, run_id) == "COMPLETED"


def test_failed_step_fails_run(pg_stack: SimpleNamespace, sms: SimpleNamespace) -> None:
    run_id = _seed(sms.app, uuid.uuid4(), _plan("a", tool="fake.fail"))
    assert execute_advancement(sms.worker, run_id).result == "failed"
    assert execute_advancement(sms.worker, run_id).result == "noop"
    assert _steps(pg_stack.owner_libpq, run_id)["a"][0] == "FAILED"
    assert _run_status(pg_stack.owner_libpq, run_id) == "FAILED"


def test_commit_before_enqueue_crash_resume(
    pg_stack: SimpleNamespace, sms: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    counter: Counter[str] = Counter()
    lock = threading.Lock()

    def counting(name: str, args: dict[str, object]) -> dict[str, object]:
        with lock:
            counter[str(args.get("step", name))] += 1
        return {"echo": args}

    monkeypatch.setattr(execmod, "run_tool", counting)

    run_id = _seed(sms.app, uuid.uuid4(), _plan("a", "b", "c"))
    execute_advancement(sms.worker, run_id)  # a COMMITTED
    execute_advancement(sms.worker, run_id)  # b COMMITTED
    # simulate crash BEFORE advance_run.send(): we simply never enqueued.
    # redelivery == calling advancement again:
    assert execute_advancement(sms.worker, run_id).step_id == "c"
    execute_advancement(sms.worker, run_id)  # completion
    assert counter == Counter({"a": 1, "b": 1, "c": 1})  # A/B not repeated
    assert _run_status(pg_stack.owner_libpq, run_id) == "COMPLETED"


def test_enqueue_error_propagates_and_step_is_durable(
    pg_stack: SimpleNamespace, sms: SimpleNamespace
) -> None:
    run_id = _seed(sms.app, uuid.uuid4(), _plan("a", "b"))

    def boom(_rid: uuid.UUID) -> None:
        raise RuntimeError("enqueue failed")

    # The enqueue failure must NOT be swallowed.
    with pytest.raises(RuntimeError):
        process_advance(sms.worker, run_id, boom)
    # ...but the step it executed is durably committed.
    assert _steps(pg_stack.owner_libpq, run_id)["a"] == ("SUCCESS", 1)
    # A clean re-invocation resumes at the next step.
    process_advance(sms.worker, run_id, lambda _rid: None)
    assert _steps(pg_stack.owner_libpq, run_id)["b"][0] == "SUCCESS"


def test_concurrent_advancement_executes_each_step_once(
    pg_stack: SimpleNamespace, sms: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    counter: Counter[str] = Counter()
    lock = threading.Lock()

    def counting(name: str, args: dict[str, object]) -> dict[str, object]:
        with lock:
            counter[str(args.get("step", name))] += 1
        return {"echo": args}

    monkeypatch.setattr(execmod, "run_tool", counting)

    run_id = _seed(sms.app, uuid.uuid4(), _plan("a"))
    barrier = threading.Barrier(2)
    errors: list[Exception] = []

    def worker() -> None:
        barrier.wait()
        try:
            execute_advancement(sms.worker, run_id)
        except Exception as exc:  # noqa: BLE001 - recorded for assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert counter["a"] == 1  # FOR UPDATE serialized; step ran exactly once
    assert _steps(pg_stack.owner_libpq, run_id)["a"] == ("SUCCESS", 1)


def test_tenant_isolation_in_worker(pg_stack: SimpleNamespace, sms: SimpleNamespace) -> None:
    tenant_a = uuid.uuid4()
    run_id = _seed(sms.app, tenant_a, _plan("a"))

    # Worker gets only run_id, derives tenant A from Postgres, executes.
    assert execute_advancement(sms.worker, run_id).result == "advanced"
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute("SELECT tenant_id FROM step_runs WHERE run_id=%s", (run_id,)).fetchone()
    assert row is not None and row[0] == tenant_a

    # Under a different tenant context, the run/steps are invisible (RLS).
    with psycopg.connect(pg_stack.worker_libpq) as c:
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (str(uuid.uuid4()),))
        runs = c.execute("SELECT count(*) FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
        steps = c.execute("SELECT count(*) FROM step_runs WHERE run_id=%s", (run_id,)).fetchone()
        c.rollback()
    assert runs is not None and runs[0] == 0
    assert steps is not None and steps[0] == 0
