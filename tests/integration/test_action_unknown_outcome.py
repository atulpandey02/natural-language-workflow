"""Ambiguous-outcome (UNKNOWN) external-action safety (M11.5 P1C, parts B/C/H).

An action whose outcome cannot be proven (transmission may have happened, the
response was lost, or the final attempt expired without proof) becomes a
TERMINAL UNKNOWN: the external_action row is ``unknown``, the step/run FAIL with
the distinguishing ``ACTION_OUTCOME_UNKNOWN`` code, and the side effect is NEVER
resent, reclaimed, or retried.
"""

import uuid
from types import SimpleNamespace

import httpx
import psycopg
import pytest
from sqlalchemy.orm import Session, sessionmaker
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

from nlw.engine.actions import (
    ACTION_OUTCOME_UNKNOWN,
    ActionExecResult,
    ActionTask,
    effective_attempt_cap,
    run_action,
)
from nlw.engine.execution import execute_advancement, process_advance
from nlw.secrets.store import EnvironmentSecretStore, SecretStore

pytestmark = pytest.mark.integration


def _run_status(owner_libpq: str, run_id: uuid.UUID) -> str:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT status FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
    assert row is not None
    return str(row[0])


def _row_error(owner_libpq: str, run_id: uuid.UUID) -> object:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT error FROM step_runs WHERE run_id=%s", (run_id,)).fetchone()
    assert row is not None
    return row[0]


class _AmbiguousTransport(httpx.BaseTransport):
    """Simulates a post-write connection reset: httpx.ReadError -> AMBIGUOUS."""

    def __init__(self, sink: Sink) -> None:
        self._sink = sink

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self._sink.calls.append(request)
        raise httpx.ReadError("connection reset")


def _ambiguous_runner(sink: Sink) -> ActionRunner:
    def run(task: ActionTask) -> ActionExecResult:
        return run_action(task, transport=_AmbiguousTransport(sink))

    return run


def _prepare_approved(
    pg_stack: SimpleNamespace,
) -> tuple[uuid.UUID, sessionmaker[Session], SecretStore, Sink]:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})
    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park for approval
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    return run_id, sm, store, sink


def test_ambiguous_send_becomes_unknown_and_is_not_resent(pg_stack: SimpleNamespace) -> None:
    run_id, sm, store, sink = _prepare_approved(pg_stack)

    # One delivery attempt whose outcome is unprovable (read error after write).
    out = process_advance(sm, run_id, _noop_enqueue, store, _ambiguous_runner(sink))
    assert out.result == "failed"
    assert len(sink.calls) == 1  # the send was attempted exactly once

    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "unknown"
    assert ea["error_class"] == ACTION_OUTCOME_UNKNOWN
    assert ea["lease_token"] is None  # lease released, not held
    assert ea["next_attempt_at"] is None  # never scheduled for retry

    step_status, _out = _step(pg_stack.owner_libpq, run_id)
    assert step_status == "FAILED"
    step_err = _row_error(pg_stack.owner_libpq, run_id)
    assert step_err == ACTION_OUTCOME_UNKNOWN  # distinguishing code, not "action failed: ..."
    assert _run_status(pg_stack.owner_libpq, run_id) == "FAILED"

    # UNKNOWN is TERMINAL: any replay is a noop and NEVER resends.
    replay = process_advance(sm, run_id, _noop_enqueue, store, _ambiguous_runner(sink))
    assert replay.result == "noop"
    assert len(sink.calls) == 1  # still exactly one attempt — no redelivery


def test_webhook_5xx_becomes_unknown_and_is_not_resent(pg_stack: SimpleNamespace) -> None:
    """A generic webhook 5xx is no longer retried (P1C): the receiver may have
    performed the effect and then failed responding, so the outcome is UNKNOWN and
    is never automatically resent."""
    run_id, sm, store, sink = _prepare_approved(pg_stack)
    sink.responses = [httpx.Response(503)]  # server error AFTER the request was sent

    out = process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
    assert out.result == "failed"
    assert len(sink.calls) == 1

    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "unknown"
    assert ea["error_class"] == ACTION_OUTCOME_UNKNOWN
    assert ea["next_attempt_at"] is None  # NOT scheduled for retry
    assert _run_status(pg_stack.owner_libpq, run_id) == "FAILED"

    # No automatic redelivery on replay.
    replay = process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
    assert replay.result == "noop"
    assert len(sink.calls) == 1


def test_expired_final_attempt_is_unknown_not_failed(pg_stack: SimpleNamespace) -> None:
    run_id, sm, store, sink = _prepare_approved(pg_stack)

    # Claim attempt 1 (live lease), then simulate a crash and push the action to
    # its FINAL attempt with the lease already expired: the prior send cannot be
    # disproven, so a resume must NOT re-execute and must NOT mark it FAILED.
    claim = execute_advancement(sm, run_id, store)
    assert claim.action_task is not None
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE external_actions SET attempts=%s, "
            "lease_expires_at = now() - interval '1 second', next_attempt_at = NULL "
            "WHERE run_id=%s",
            (effective_attempt_cap(), run_id),
        )

    out = execute_advancement(sm, run_id, store)
    assert out.result == "failed"
    assert len(sink.calls) == 0  # the expired final attempt is NEVER re-sent

    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "unknown"
    assert ea["error_class"] == ACTION_OUTCOME_UNKNOWN
    assert _row_error(pg_stack.owner_libpq, run_id) == ACTION_OUTCOME_UNKNOWN
    assert _run_status(pg_stack.owner_libpq, run_id) == "FAILED"


def test_provable_pretransmission_cap_exhaustion_is_definite_failure(
    pg_stack: SimpleNamespace,
) -> None:
    """Contrast case: when every attempt PROVABLY failed before transmission
    (connect refused -> RetryableActionError), cap exhaustion is a DEFINITE
    failure, not UNKNOWN — the side effect provably never happened."""
    run_id, sm, store, sink = _prepare_approved(pg_stack)

    class _ConnRefused(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

    def runner(task: ActionTask) -> ActionExecResult:
        return run_action(task, transport=_ConnRefused())

    result = "retry"
    for _ in range(effective_attempt_cap() + 3):
        out = process_advance(sm, run_id, _noop_enqueue, store, runner)
        result = out.result
        if result == "failed":
            break
        with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
            c.execute(
                "UPDATE external_actions SET next_attempt_at = now() - interval '1 second', "
                "lease_expires_at = now() - interval '1 second' WHERE run_id=%s",
                (run_id,),
            )
    assert result == "failed"
    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "failed"  # DEFINITE failure, not unknown
    assert ea["error_class"] != ACTION_OUTCOME_UNKNOWN
