"""Two-transaction, out-of-lock action execution (M7, ADR-013).

Side-effecting tools do NOT run inside the M3 run lock. Instead:

    Txn1 (execution.py): claim the step (RUNNING) + create/lease a durable
        external_actions row with a STABLE idempotency key -> COMMIT (lock freed)
    run_action(): perform the external side effect with NO DB txn / run lock
    finalize_action(): re-lock, finalize SUCCESS/FAILED/retry idempotently -> COMMIT

The idempotency key is generated once per (run, step) and reused on every
retry/resume. We do NOT claim exactly-once: an external success followed by a
crash before finalize can re-send the same request (same key) and duplicate a
side effect against a non-idempotent receiver. An ambiguous outcome once the
request may have been transmitted is NOT retried — it becomes a terminal UNKNOWN
(ACTION_OUTCOME_UNKNOWN; see ADR-013) so the platform never auto-resends it.
"""

import enum
import os
import random
import socket
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import func
from sqlalchemy.orm import Session, sessionmaker

from nlw.db.models import ExternalAction, StepRun, WorkflowRun
from nlw.domain.workflow import (
    RunStatus,
    StepStatus,
    assert_transition_run,
    assert_transition_step,
)
from nlw.registry.registry import (
    REGISTRY,
    ActionAuthError,
    ActionContext,
    AmbiguousActionError,
    RetryableActionError,
    ToolExecutionError,
)

# Stable, sanitized error code for an ambiguous external outcome (P1C).
ACTION_OUTCOME_UNKNOWN = "ACTION_OUTCOME_UNKNOWN"

# Lease must outlast the hard-max action network timeout (15s) + margin, so a
# lease only expires on genuine worker death, not on a slow-but-alive send.
LEASE_DURATION_S = 45
# Retry budget (attempts count durable CLAIMS, not guaranteed network sends).
MAX_ACTION_ATTEMPTS = 5  # default
HARD_MAX_ACTION_ATTEMPTS = 10  # platform ceiling
_BACKOFF_BASE_S = 2.0
_BACKOFF_CAP_S = 300.0

WORKER_ID = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


def _set_run_status(run: WorkflowRun, new: RunStatus) -> None:
    """Guarded run-status assignment (M12B-A). Self-edge is legal (idempotent)."""
    run.status = assert_transition_run(RunStatus(run.status), new)


def _set_step_status(step: StepRun, new: StepStatus) -> None:
    step.status = assert_transition_step(StepStatus(step.status), new)


def _now() -> datetime:
    return datetime.now(UTC)


def effective_attempt_cap() -> int:
    return min(MAX_ACTION_ATTEMPTS, HARD_MAX_ACTION_ATTEMPTS)


class ActionKind(enum.StrEnum):
    SUCCESS = "success"
    FAILED_DETERMINISTIC = "failed_deterministic"
    FAILED_AUTH = "failed_auth"
    RETRY = "retry"
    # Transmission may have occurred; outcome unprovable -> terminal UNKNOWN.
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ActionTask:
    """Everything needed to run + finalize one action attempt, out of the lock."""

    run_id: uuid.UUID
    tenant_id: uuid.UUID
    step_id: str
    tool: str
    connector_type: str
    connector_name: str
    connector_id: uuid.UUID
    config: dict[str, Any]
    secret: str | None
    args: dict[str, Any]
    external_action_id: uuid.UUID
    external_action_key: uuid.UUID
    attempt: int
    lease_token: uuid.UUID


@dataclass(frozen=True)
class ActionExecResult:
    kind: ActionKind
    output: dict[str, Any] | None = None
    provider_request_id: str | None = None
    http_status: int | None = None
    error_class: str | None = None
    retry_after_s: float | None = None


def run_action(task: ActionTask, transport: httpx.BaseTransport | None = None) -> ActionExecResult:
    """Perform the external side effect and classify the outcome. No DB here."""
    from nlw.connectors.base import ConnectorContext

    spec = REGISTRY.get(task.tool)
    assert spec.execute_action is not None
    args_model = spec.input_model.model_validate(task.args)
    connector_ctx = ConnectorContext(
        type=task.connector_type,
        name=task.connector_name,
        config=task.config,
        secret=task.secret,
        connector_id=task.connector_id,
    )
    action_ctx = ActionContext(
        idempotency_key=task.external_action_key, attempt=task.attempt, transport=transport
    )
    try:
        result = spec.execute_action(args_model, connector_ctx, action_ctx)
    except ActionAuthError:
        return ActionExecResult(kind=ActionKind.FAILED_AUTH, error_class="auth")
    except AmbiguousActionError:
        # May have transmitted; not safely retryable -> terminal UNKNOWN.
        return ActionExecResult(kind=ActionKind.UNKNOWN, error_class=ACTION_OUTCOME_UNKNOWN)
    except RetryableActionError as exc:
        return ActionExecResult(
            kind=ActionKind.RETRY, error_class="retryable", retry_after_s=exc.retry_after_s
        )
    except ToolExecutionError:
        return ActionExecResult(kind=ActionKind.FAILED_DETERMINISTIC, error_class="deterministic")
    http_status = result.output.get("http_status") if isinstance(result.output, dict) else None
    return ActionExecResult(
        kind=ActionKind.SUCCESS,
        output=result.output,
        provider_request_id=result.provider_request_id,
        http_status=http_status if isinstance(http_status, int) else None,
    )


def _backoff_seconds(attempt: int, retry_after_s: float | None) -> float:
    if retry_after_s is not None:
        return max(0.0, min(retry_after_s, _BACKOFF_CAP_S))
    base: float = _BACKOFF_BASE_S * float(2 ** max(0, attempt - 1))
    return float(min(base, _BACKOFF_CAP_S) + random.uniform(0, 1.0))


@dataclass(frozen=True)
class FinalizeOutcome:
    result: str  # 'advanced' | 'failed' | 'retry' | 'noop'
    enqueue_next: bool = False
    defer_seconds: float | None = None


def mark_transmission_started(
    session_factory: sessionmaker[Session],
    task: ActionTask,
    set_context: Callable[[Session, uuid.UUID, uuid.UUID], None],
) -> bool:
    """Txn1.5 (ADR-013 crash window): commit the durable ambiguity boundary BEFORE
    the out-of-lock network transmission.

    Persists ``transmission_started_at`` on the leased action, guarded by the lease
    token, so a worker death anywhere between here and ``finalize_action`` recovers
    as terminal UNKNOWN instead of silently resending a non-idempotent side effect.
    The first boundary timestamp is preserved across a re-mark (``COALESCE``).

    Returns True when the boundary is durably committed for THIS lease; False when
    the lease is no longer held, is already EXPIRED, or the action is already
    finalized (the caller must then NOT transmit — another worker may reclaim it).

    The expired-lease refusal is race-free: the check runs under the same
    ``FOR UPDATE`` row lock that a reclaim ``_resume_action`` must also acquire, so
    a lease that reads as expired here cannot be simultaneously live for anyone
    else. Refusing before setting the boundary leaves ``transmission_started_at``
    NULL, so the action stays safely retryable (nothing was transmitted); the
    conservative UNKNOWN fallback still applies once a boundary IS crossed.
    """
    from nlw.engine.execution import _resolve_tenant  # avoid cycle

    with session_factory() as session, session.begin():
        tenant_id = _resolve_tenant(session, task.run_id)
        if tenant_id is None:
            return False
        set_context(session, tenant_id, task.run_id)
        ea = (
            session.query(ExternalAction)
            .filter(ExternalAction.id == task.external_action_id)
            .with_for_update()
            .one_or_none()
        )
        if ea is None or ea.lease_token != task.lease_token or ea.status != "pending":
            return False
        # Do not cross the boundary (and do not transmit) under an already-expired
        # lease: the action is eligible for another worker's reclaim.
        if ea.lease_expires_at is None or ea.lease_expires_at <= _now():
            return False
        if ea.transmission_started_at is None:
            ea.transmission_started_at = _now()
        return True


def finalize_action(
    session_factory: sessionmaker[Session],
    task: ActionTask,
    result: ActionExecResult,
    set_context: Callable[[Session, uuid.UUID, uuid.UUID], None],
) -> FinalizeOutcome:
    """Txn2: finalize the action idempotently, guarded by the lease token.

    ``set_context(session, tenant_id, run_id)`` establishes the SIGNED
    ``worker_execution`` context for this transaction (P3B); the tenant is
    re-resolved from the run row, never trusted from the task.
    """
    from nlw.engine.execution import _resolve_tenant, _set_connector_status  # avoid cycle

    with session_factory() as session, session.begin():
        tenant_id = _resolve_tenant(session, task.run_id)
        if tenant_id is None:
            return FinalizeOutcome("noop")
        set_context(session, tenant_id, task.run_id)

        run = (
            session.query(WorkflowRun).filter(WorkflowRun.id == task.run_id).with_for_update().one()
        )
        ea = (
            session.query(ExternalAction)
            .filter(ExternalAction.id == task.external_action_id)
            .with_for_update()
            .one_or_none()
        )
        step = (
            session.query(StepRun)
            .filter(StepRun.run_id == task.run_id, StepRun.step_id == task.step_id)
            .one_or_none()
        )
        if ea is None or step is None:
            return FinalizeOutcome("noop")
        # Lease guard: only the current leaseholder may finalize.
        if ea.lease_token != task.lease_token:
            return FinalizeOutcome("noop")
        if ea.status != "pending":
            return FinalizeOutcome("noop")

        now = _now()
        if result.kind == ActionKind.SUCCESS:
            ea.status = "success"
            ea.provider_request_id = result.provider_request_id
            ea.http_status = result.http_status
            ea.error_class = None
            ea.lease_token = None
            ea.lease_owner = None
            ea.lease_expires_at = None
            ea.next_attempt_at = None
            _set_step_status(step, StepStatus.SUCCESS)
            step.output = result.output
            step.finished_at = now
            run.last_progress_at = func.now()  # action outcome finalized (success)
            return FinalizeOutcome("advanced", enqueue_next=True)

        if result.kind == ActionKind.UNKNOWN:
            # Ambiguous: the side effect MAY have occurred. Terminal, NEVER resent.
            # The external action is UNKNOWN; step/run FAIL with a distinguishing
            # code so the UI reports "may have occurred", not a definite failure.
            ea.status = "unknown"
            ea.error_class = ACTION_OUTCOME_UNKNOWN
            ea.http_status = result.http_status
            ea.lease_token = None
            ea.lease_owner = None
            ea.lease_expires_at = None
            ea.next_attempt_at = None
            _set_step_status(step, StepStatus.FAILED)
            step.error = ACTION_OUTCOME_UNKNOWN
            step.finished_at = now
            _set_run_status(run, RunStatus.FAILED)
            run.finished_at = now
            run.last_progress_at = func.now()  # run terminal (UNKNOWN outcome)
            return FinalizeOutcome("failed")

        if result.kind == ActionKind.RETRY and task.attempt < effective_attempt_cap():
            delay = _backoff_seconds(task.attempt, result.retry_after_s)
            ea.error_class = result.error_class
            ea.http_status = result.http_status
            ea.last_attempt_at = now
            ea.next_attempt_at = now + timedelta(seconds=delay)
            ea.lease_token = None
            ea.lease_owner = None
            ea.lease_expires_at = None
            # RETRY is raised ONLY for an outcome that is safe to re-attempt: a
            # provable pre-transmission failure (DNS/pool/connect/TLS) or a
            # contractual throttle (Slack 429 — the message was not accepted). The
            # next attempt therefore starts from a FRESH ambiguity boundary; clear
            # this one so resume does not misread it as "transmission may have
            # started" and force a spurious UNKNOWN.
            ea.transmission_started_at = None
            run.last_progress_at = func.now()  # retry scheduled (genuine progress)
            # Step stays RUNNING; a delayed advance_run resumes it.
            return FinalizeOutcome("retry", defer_seconds=delay)

        # Deterministic / auth / retry-cap-exhausted -> terminal failure.
        ea.status = "failed"
        ea.error_class = result.error_class or "failed"
        ea.http_status = result.http_status
        ea.lease_token = None
        ea.lease_owner = None
        ea.lease_expires_at = None
        _set_step_status(step, StepStatus.FAILED)
        step.error = f"action failed: {result.error_class}"
        step.finished_at = now
        _set_run_status(run, RunStatus.FAILED)
        run.finished_at = now
        run.last_progress_at = func.now()  # run terminal (deterministic/auth/cap)
        if result.kind == ActionKind.FAILED_AUTH:
            _set_connector_status(session, task.connector_id, "error")
        return FinalizeOutcome("failed")
