"""Final external-action classification matrix, end-to-end (M11.5 P1C, part A).

Table-driven: each row drives ONE first automatic attempt through the real engine
and asserts the durable outcome — external-action status, step/run status, whether
a retry is scheduled, whether a second AUTOMATIC transmission occurs on immediate
redelivery, the stable sanitized error code, and that no response body / URL
secret / credential / raw exception internal leaks into any persisted surface.
"""

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from types import SimpleNamespace

import httpx
import psycopg
import pytest
from test_action_execution import (  # sibling module (pytest prepend import mode)
    ActionRunner,
    Sink,
    _approve,
    _ea,
    _noop_enqueue,
    _runner,
    _seed_run,
    _seed_webhook,
    _step,
    _webhook_plan,
    _worker_sm,
)

from nlw.engine.actions import ACTION_OUTCOME_UNKNOWN, ActionExecResult, ActionTask, run_action
from nlw.engine.execution import execute_advancement, process_advance
from nlw.secrets.store import EnvironmentSecretStore

pytestmark = pytest.mark.integration

# The ONLY error codes that may ever be persisted (stable, sanitized).
_ALLOWED_ERROR_CLASSES = {None, "retryable", "deterministic", "auth", ACTION_OUTCOME_UNKNOWN}


def _status_runner(code: int) -> Callable[[Sink], ActionRunner]:
    def make(sink: Sink) -> ActionRunner:
        sink.responses = [httpx.Response(code)]
        return _runner(sink)

    return make


def _exc_runner(exc: Exception) -> Callable[[Sink], ActionRunner]:
    class _Raise(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            raise exc

    def make(sink: Sink) -> ActionRunner:
        def run(task: ActionTask) -> ActionExecResult:
            sink.calls.append(httpx.Request("POST", "https://sink.example/hook"))
            return run_action(task, transport=_Raise())

        return run

    return make


@dataclass(frozen=True)
class Case:
    name: str
    make_runner: Callable[[Sink], ActionRunner]
    ea_status: str
    step_status: str
    run_status: str
    retry_scheduled: bool
    error_class: str | None


_CASES = [
    Case("2xx_success", _status_runner(200), "success", "SUCCESS", "COMPLETED", False, None),
    Case(
        "429_rate_limited", _status_runner(429), "pending", "RUNNING", "RUNNING", True, "retryable"
    ),
    Case(
        "400_client_error",
        _status_runner(400),
        "failed",
        "FAILED",
        "FAILED",
        False,
        "deterministic",
    ),
    Case("401_auth", _status_runner(401), "failed", "FAILED", "FAILED", False, "auth"),
    Case(
        "5xx_server_error",
        _status_runner(503),
        "unknown",
        "FAILED",
        "FAILED",
        False,
        ACTION_OUTCOME_UNKNOWN,
    ),
    Case(
        "connect_error_pre_transmission",
        _exc_runner(httpx.ConnectError("refused")),
        "pending",
        "RUNNING",
        "RUNNING",
        True,
        "retryable",
    ),
    Case(
        "read_error_post_transmission",
        _exc_runner(httpx.ReadError("reset after send")),
        "unknown",
        "FAILED",
        "FAILED",
        False,
        ACTION_OUTCOME_UNKNOWN,
    ),
]


def _run_status(owner_libpq: str, run_id: uuid.UUID) -> str:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT status FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
    assert row is not None
    return str(row[0])


@pytest.mark.parametrize("case", _CASES, ids=[c.name for c in _CASES])
def test_classification_matrix(pg_stack: SimpleNamespace, case: Case) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id, url="https://sink.example/secret-path?t=cred")
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    store = EnvironmentSecretStore({})
    sink = Sink()
    runner = case.make_runner(sink)

    process_advance(sm, run_id, _noop_enqueue, store, runner)  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)

    # First AUTOMATIC attempt.
    process_advance(sm, run_id, _noop_enqueue, store, runner)
    calls_after_first = len(sink.calls)
    assert calls_after_first == 1, "exactly one transmission on the first attempt"

    # Immediate redelivery must NOT produce a second automatic transmission
    # (terminal -> noop; retry -> deferred by next_attempt_at; success -> done).
    execute_advancement(sm, run_id, store)
    assert len(sink.calls) == calls_after_first, "no second automatic transmission"

    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == case.ea_status
    assert ea["error_class"] == case.error_class
    assert _step(pg_stack.owner_libpq, run_id)[0] == case.step_status
    assert _run_status(pg_stack.owner_libpq, run_id) == case.run_status

    retry_scheduled = ea["status"] == "pending" and ea["next_attempt_at"] is not None
    assert retry_scheduled == case.retry_scheduled

    # No leak: only stable sanitized codes are persisted; no response body, URL
    # path/query, credential, or raw exception text on any durable surface.
    assert ea["error_class"] in _ALLOWED_ERROR_CLASSES
    assert ea["destination_summary"] == "sink.example"  # host only, no path/query
    with psycopg.connect(pg_stack.owner_libpq) as c:
        ea_row = c.execute(
            "SELECT to_jsonb(e) FROM external_actions e WHERE run_id=%s", (run_id,)
        ).fetchone()
        step_row = c.execute("SELECT error FROM step_runs WHERE run_id=%s", (run_id,)).fetchone()
    ea_dump = json.dumps(ea_row[0], default=str) if ea_row else ""
    step_err = step_row[0] if step_row else None  # scalar text or None
    blob = ea_dump + (step_err or "")
    for forbidden in (
        "secret-path",
        "t=cred",
        "Traceback",
        "https://",
        "refused",
        "reset after send",
    ):
        assert forbidden not in blob, f"leak of {forbidden!r} in persisted state"
    # A step failure message, when present, is a stable phrase — never a raw
    # provider status code or exception text.
    if step_err is not None:
        assert "503" not in step_err and "400" not in step_err
