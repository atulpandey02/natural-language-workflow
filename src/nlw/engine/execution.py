"""Durable single-step advancement (M3) + two-phase action execution (M7).

Inline (read/processing) tools still run one-per-advancement inside a single
``FOR UPDATE``-locked transaction (M3/M5). Side-effecting ACTION tools instead
use the two-transaction, out-of-lock pattern (ADR-013): Txn1 claims the step and
creates a durable, leased ``external_actions`` row with a stable idempotency key
and COMMITs (releasing the lock); the side effect runs with no lock held; Txn2
finalizes idempotently. Approval-gated actions park the run at WAITING_APPROVAL
until a human decision arrives (the worker remains the sole run/step writer).
"""

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ValidationError
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

import nlw.tools.builtin  # noqa: F401  (populates the tool + connector-type registries)
from nlw.connectors.base import (
    ConnectorConfigError,
    ConnectorContext,
    ConnectorDisabledError,
    ConnectorError,
    ConnectorNotFoundError,
    ConnectorUnhealthyError,
    MissingConnectorSelectorError,
    get_connector_type,
)
from nlw.db.models import Approval, ExternalAction, StepRun, WorkflowRun, WorkflowVersion
from nlw.domain.workflow import (
    RunStatus,
    StepStatus,
    WorkflowPlan,
    WorkflowStep,
    all_succeeded,
    any_failed,
    select_next_step,
)
from nlw.engine.actions import (
    LEASE_DURATION_S,
    WORKER_ID,
    ActionExecResult,
    ActionTask,
    effective_attempt_cap,
    finalize_action,
    run_action,
)
from nlw.observability import metrics
from nlw.registry.registry import REGISTRY, ToolExecutionError, ToolSpec, UnknownToolError
from nlw.secrets.store import SecretError, SecretStore, build_secret_store
from nlw.tenancy.session import set_current_tenant_sync

Result = Literal["advanced", "completed", "failed", "noop", "waiting", "retry", "deferred"]

# Deterministic step-failure exceptions (business failures -> step/run FAILED).
_STEP_FAILURES = (
    ToolExecutionError,
    UnknownToolError,
    ConnectorError,
    SecretError,
    ValidationError,
)


@dataclass(frozen=True)
class AdvanceOutcome:
    result: Result
    enqueue_next: bool
    step_id: str | None = None
    action_task: ActionTask | None = None
    defer_seconds: float | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _mark_progress(run: WorkflowRun) -> None:
    """Stamp genuine execution-state advancement using SERVER time (P1D).

    Call ONLY where the run/step/action state machine actually advances (run
    entering execution, step claim/start, step terminal, retry scheduling/claim,
    approval resolution that unblocks work, action finalization, run terminal).
    NEVER call it for a reconciler scan, a read, or an unrelated metadata write.
    The reconciler reads this to distinguish a genuinely stuck run from one still
    progressing. Server time (``func.now()`` = transaction time) keeps the signal
    authoritative under cross-process app-clock skew.
    """
    run.last_progress_at = func.now()


def _resolve_tenant(session: Session, run_id: uuid.UUID) -> uuid.UUID | None:
    result = session.execute(
        text("SELECT resolve_run_tenant(:rid)"), {"rid": str(run_id)}
    ).scalar_one_or_none()
    return result


def _set_connector_status(session: Session, connector_id: uuid.UUID, status: str) -> None:
    session.execute(
        text("UPDATE connectors SET status = :s, updated_at = now() WHERE id = :id"),
        {"s": status, "id": str(connector_id)},
    )


def _resolve_connector(
    session: Session,
    tenant_id: uuid.UUID,
    connector_type: str,
    connector_name: str | None,
    secret_store: SecretStore,
) -> ConnectorContext:
    """Inline-tool connector resolution: load (RLS-scoped), health-check, activate."""
    if connector_name is None:
        raise MissingConnectorSelectorError(connector_type)
    row = session.execute(
        text(
            "SELECT id, config, secret_ref, status FROM connectors "
            "WHERE tenant_id = :t AND type = :ty AND name = :n"
        ),
        {"t": str(tenant_id), "ty": connector_type, "n": connector_name},
    ).one_or_none()
    if row is None:
        raise ConnectorNotFoundError(f"{connector_type}:{connector_name}")
    connector_id, config, secret_ref, status = row
    if status == "disabled":
        raise ConnectorDisabledError(connector_name)
    spec = get_connector_type(connector_type)
    secret: str | None = None
    if spec.secret_required:
        if not secret_ref:
            _set_connector_status(session, connector_id, "error")
            raise ConnectorConfigError(f"{connector_name}: secret required but no secret_ref")
        try:
            secret = secret_store.resolve(tenant_id, secret_ref)
        except SecretError:
            _set_connector_status(session, connector_id, "error")
            raise
    ctx = ConnectorContext(
        type=connector_type,
        name=connector_name,
        config=dict(config),
        secret=secret,
        connector_id=connector_id,
    )
    if status != "active":
        if spec.health_check is not None:
            try:
                spec.health_check(ctx)
            except Exception:
                _set_connector_status(session, connector_id, "error")
                raise
        _set_connector_status(session, connector_id, "active")
    return ctx


def _load_action_connector(
    session: Session,
    tenant_id: uuid.UUID,
    connector_type: str,
    connector_name: str | None,
    secret_store: SecretStore,
) -> tuple[uuid.UUID, dict[str, Any], str | None]:
    """Action connector load WITHOUT a network health probe (no I/O in the lock).

    Delivery itself is the liveness proof (ADR-013). Returns (id, config, secret).
    """
    if connector_name is None:
        raise MissingConnectorSelectorError(connector_type)
    row = session.execute(
        text(
            "SELECT id, config, secret_ref, status FROM connectors "
            "WHERE tenant_id = :t AND type = :ty AND name = :n"
        ),
        {"t": str(tenant_id), "ty": connector_type, "n": connector_name},
    ).one_or_none()
    if row is None:
        raise ConnectorNotFoundError(f"{connector_type}:{connector_name}")
    connector_id, config, secret_ref, status = row
    if status == "disabled":
        raise ConnectorDisabledError(connector_name)
    secret: str | None = None
    if secret_ref:
        secret = secret_store.resolve(tenant_id, secret_ref)
    return connector_id, dict(config), secret


def execute_tool(
    spec: ToolSpec, args: BaseModel, connector: ConnectorContext | None
) -> dict[str, Any]:
    """Dispatch an INLINE tool's execute(). Patch seam for tests."""
    assert spec.execute is not None
    return spec.execute(args, connector)


def _destination_summary(tool: str, config: dict[str, Any], step: WorkflowStep) -> str | None:
    if tool == "webhook.send":
        from nlw.connectors.http_guard import validate_url

        try:
            host, _ = validate_url(str(config.get("url", "")))
            return host
        except Exception:
            return None
    if tool == "slack.send_message":
        ch = step.args.get("channel") if isinstance(step.args, dict) else None
        return str(ch) if ch else str(config.get("default_channel", "") or "") or None
    return None


def _fail_run_step(
    session: Session, run: WorkflowRun, step: StepRun, message: str
) -> AdvanceOutcome:
    now = _now()
    step.status = StepStatus.FAILED
    step.error = message
    step.finished_at = now
    run.status = RunStatus.FAILED
    run.finished_at = now
    _mark_progress(run)  # run terminal transition
    metrics.observe_run_completion("failed", (now - run.created_at).total_seconds())
    return AdvanceOutcome("failed", enqueue_next=False, step_id=step.step_id)


def _action_unknown(
    session: Session, run: WorkflowRun, step: StepRun, ea: ExternalAction, message: str
) -> AdvanceOutcome:
    """Terminal UNKNOWN: the external side effect MAY have occurred but cannot be
    proven. The action is UNKNOWN (never resent/reclaimed); step/run FAIL with the
    distinguishing ACTION_OUTCOME_UNKNOWN code so the UI reports "may have
    occurred", not a definite failure."""
    from nlw.engine.actions import ACTION_OUTCOME_UNKNOWN

    now = _now()
    ea.status = "unknown"
    ea.error_class = ACTION_OUTCOME_UNKNOWN
    ea.lease_token = None
    ea.lease_owner = None
    ea.lease_expires_at = None
    ea.next_attempt_at = None
    step.status = StepStatus.FAILED
    step.error = ACTION_OUTCOME_UNKNOWN
    step.finished_at = now
    run.status = RunStatus.FAILED
    run.finished_at = now
    _mark_progress(run)  # run terminal transition (UNKNOWN action outcome)
    metrics.observe_run_completion("failed", (now - run.created_at).total_seconds())
    return AdvanceOutcome("failed", enqueue_next=False, step_id=step.step_id)


def _get_step(step_rows: list[StepRun], step_id: str) -> StepRun | None:
    return next((s for s in step_rows if s.step_id == step_id), None)


def _claim_action(
    session: Session,
    run: WorkflowRun,
    tenant_id: uuid.UUID,
    plan_step: WorkflowStep,
    step: StepRun,
    spec: ToolSpec,
    secret_store: SecretStore,
    expected_connector_id: uuid.UUID | None = None,
) -> AdvanceOutcome:
    """Txn1 fresh claim: step -> RUNNING, create leased external_actions row."""
    assert spec.connector_type is not None
    connector_id, config, _secret = _load_action_connector(
        session, tenant_id, spec.connector_type, plan_step.connector, secret_store
    )
    # Pin to the APPROVED connector identity: a post-approval connector edit /
    # recreate (same name, different id, possibly a different destination) must
    # NOT silently redirect an already-approved side effect. Require fresh
    # approval by failing deterministically instead.
    if expected_connector_id is not None and connector_id != expected_connector_id:
        raise ConnectorError("connector changed after approval; re-approval required")
    now = _now()
    step.status = StepStatus.RUNNING
    step.started_at = now
    _mark_progress(run)  # step claim/start (durable in-flight action)
    ea = ExternalAction(
        tenant_id=tenant_id,
        run_id=run.id,
        step_id=plan_step.id,
        connector_id=connector_id,
        tool=spec.name,
        external_action_key=uuid.uuid4(),
        destination_summary=_destination_summary(spec.name, config, plan_step),
        status="pending",
        attempts=1,
        last_attempt_at=now,
        lease_token=uuid.uuid4(),
        lease_owner=WORKER_ID,
        lease_expires_at=now + timedelta(seconds=LEASE_DURATION_S),
    )
    session.add(ea)
    session.flush()
    return _build_action_task_outcome(session, tenant_id, run, plan_step, spec, ea, secret_store)


def _build_action_task_outcome(
    session: Session,
    tenant_id: uuid.UUID,
    run: WorkflowRun,
    plan_step: WorkflowStep,
    spec: ToolSpec,
    ea: ExternalAction,
    secret_store: SecretStore,
) -> AdvanceOutcome:
    assert spec.connector_type is not None
    connector_id, config, secret = _load_action_connector(
        session, tenant_id, spec.connector_type, plan_step.connector, secret_store
    )
    assert ea.lease_token is not None
    task = ActionTask(
        run_id=run.id,
        tenant_id=tenant_id,
        step_id=plan_step.id,
        tool=spec.name,
        connector_type=spec.connector_type,
        connector_name=plan_step.connector or "",
        connector_id=connector_id,
        config=config,
        secret=secret,
        args=dict(plan_step.args),
        external_action_id=ea.id,
        external_action_key=ea.external_action_key,
        attempt=ea.attempts,
        lease_token=ea.lease_token,
    )
    return AdvanceOutcome("advanced", enqueue_next=False, step_id=plan_step.id, action_task=task)


def _resume_action(
    session: Session,
    run: WorkflowRun,
    plan: WorkflowPlan,
    step: StepRun,
    tenant_id: uuid.UUID,
    secret_store: SecretStore,
) -> AdvanceOutcome:
    """Txn1 resume of a durably RUNNING action: CAS-acquire the lease or defer."""
    plan_step = plan.step(step.step_id)
    spec = REGISTRY.get(step.tool)
    ea = session.execute(
        select(ExternalAction)
        .where(ExternalAction.run_id == run.id, ExternalAction.step_id == step.step_id)
        .with_for_update()
    ).scalar_one_or_none()
    if ea is None:
        return _fail_run_step(session, run, step, "in-flight action missing its record")
    now = _now()
    if ea.status != "pending":
        return AdvanceOutcome("noop", enqueue_next=False)
    # ORDER MATTERS (P1C): a LIVE lease is authoritative BEFORE the attempt cap.
    # A duplicate/redelivered message must defer without mutating another worker's
    # live attempt — never clear/replace its lease, never mark it failed, never
    # increment attempts. (The old order checked the cap first and could fail a
    # legitimate live final attempt and steal its lease.)
    if ea.lease_token is not None and ea.lease_expires_at is not None and ea.lease_expires_at > now:
        return AdvanceOutcome(
            "deferred",
            enqueue_next=False,
            defer_seconds=(ea.lease_expires_at - now).total_seconds(),
        )
    if ea.next_attempt_at is not None and now < ea.next_attempt_at:
        return AdvanceOutcome(
            "deferred", enqueue_next=False, defer_seconds=(ea.next_attempt_at - now).total_seconds()
        )
    if ea.attempts >= effective_attempt_cap():
        # No live lease and the retry budget is exhausted: this is an EXPIRED FINAL
        # attempt. Its prior send cannot be disproven, so it is NOT a definite
        # delivery failure -> terminal UNKNOWN (never resent).
        return _action_unknown(session, run, step, ea, "action retry cap reached")
    # Acquire the lease (CAS is serialized by the run FOR UPDATE lock we hold).
    ea.lease_token = uuid.uuid4()
    ea.lease_owner = WORKER_ID
    ea.lease_expires_at = now + timedelta(seconds=LEASE_DURATION_S)
    ea.attempts = ea.attempts + 1
    ea.last_attempt_at = now
    _mark_progress(run)  # retry claim (a fresh delivery attempt is genuine progress)
    session.flush()
    return _build_action_task_outcome(session, tenant_id, run, plan_step, spec, ea, secret_store)


def _handle_waiting(
    session: Session,
    run: WorkflowRun,
    plan: WorkflowPlan,
    step: StepRun,
    tenant_id: uuid.UUID,
    secret_store: SecretStore,
) -> AdvanceOutcome:
    """A WAITING_APPROVAL step: act on the durable approval decision."""
    approval = session.execute(
        select(Approval).where(Approval.run_id == run.id, Approval.step_id == step.step_id)
    ).scalar_one_or_none()
    if approval is None or approval.status == "pending":
        return AdvanceOutcome("waiting", enqueue_next=False, step_id=step.step_id)
    if approval.status == "rejected":
        return _fail_run_step(session, run, step, "action rejected by approver")
    # approved -> claim and execute.
    plan_step = plan.step(step.step_id)
    spec = REGISTRY.get(step.tool)
    if run.status == RunStatus.WAITING_APPROVAL:
        run.status = RunStatus.RUNNING
        _mark_progress(run)  # approval resolution unblocked execution
    try:
        return _claim_action(
            session,
            run,
            tenant_id,
            plan_step,
            step,
            spec,
            secret_store,
            expected_connector_id=approval.connector_id,
        )
    except _STEP_FAILURES as exc:
        return _fail_run_step(session, run, step, str(exc))


def _park_for_approval(
    session: Session,
    run: WorkflowRun,
    tenant_id: uuid.UUID,
    plan_step: WorkflowStep,
    step: StepRun,
    spec: ToolSpec,
    secret_store: SecretStore,
) -> AdvanceOutcome:
    """Create a PENDING approval and park run + step at WAITING_APPROVAL."""
    assert spec.connector_type is not None
    connector_id, _config, _secret = _load_action_connector(
        session, tenant_id, spec.connector_type, plan_step.connector, secret_store
    )
    step.status = StepStatus.WAITING_APPROVAL
    existing = session.execute(
        select(Approval).where(Approval.run_id == run.id, Approval.step_id == plan_step.id)
    ).scalar_one_or_none()
    if existing is None:
        session.add(
            Approval(
                tenant_id=tenant_id,
                run_id=run.id,
                step_id=plan_step.id,
                connector_id=connector_id,
                connector_name=plan_step.connector or "",
                tool=spec.name,
                status="pending",
                requested_at=_now(),
            )
        )
    run.status = RunStatus.WAITING_APPROVAL
    _mark_progress(run)  # run advanced to needing approval (a genuine transition)
    return AdvanceOutcome("waiting", enqueue_next=False, step_id=plan_step.id)


def execute_advancement(
    session_factory: sessionmaker[Session],
    run_id: uuid.UUID,
    secret_store: SecretStore | None = None,
) -> AdvanceOutcome:
    """Txn1: advance a run by one step (or claim/resume/park an action)."""
    store = secret_store if secret_store is not None else build_secret_store()
    with session_factory() as session, session.begin():
        tenant_id = _resolve_tenant(session, run_id)
        if tenant_id is None:
            return AdvanceOutcome("noop", enqueue_next=False)
        set_current_tenant_sync(session, tenant_id)

        run = session.execute(
            select(WorkflowRun).where(WorkflowRun.id == run_id).with_for_update()
        ).scalar_one_or_none()
        if run is None or run.status in (RunStatus.COMPLETED, RunStatus.FAILED):
            return AdvanceOutcome("noop", enqueue_next=False)

        version = session.get(WorkflowVersion, run.workflow_version_id)
        if version is None:
            return AdvanceOutcome("noop", enqueue_next=False)
        plan = WorkflowPlan.model_validate(version.plan)

        step_rows = list(
            session.execute(select(StepRun).where(StepRun.run_id == run_id)).scalars().all()
        )
        states: dict[str, StepStatus] = {s.step_id: StepStatus(s.status) for s in step_rows}

        if run.status == RunStatus.PENDING:
            run.status = RunStatus.RUNNING
            run.started_at = _now()
            _mark_progress(run)  # run entering execution

        if any_failed(states):
            run.status = RunStatus.FAILED
            run.finished_at = _now()
            _mark_progress(run)  # run terminal transition
            metrics.observe_run_completion(
                "failed", (run.finished_at - run.created_at).total_seconds()
            )
            return AdvanceOutcome("failed", enqueue_next=False)

        # 1) Resume a durably in-flight action (only actions persist RUNNING).
        running = next((s for s in step_rows if s.status == StepStatus.RUNNING.value), None)
        if running is not None:
            try:
                return _resume_action(session, run, plan, running, tenant_id, store)
            except _STEP_FAILURES as exc:
                return _fail_run_step(session, run, running, str(exc))

        # 2) Act on an approval decision.
        waiting = next(
            (s for s in step_rows if s.status == StepStatus.WAITING_APPROVAL.value), None
        )
        if waiting is not None:
            return _handle_waiting(session, run, plan, waiting, tenant_id, store)

        # 3) Select the next runnable step.
        nxt = select_next_step(plan, states)
        if nxt is None:
            if all_succeeded(plan, states):
                run.status = RunStatus.COMPLETED
                run.finished_at = _now()
                _mark_progress(run)  # run terminal transition
                metrics.observe_run_completion(
                    "completed", (run.finished_at - run.created_at).total_seconds()
                )
                return AdvanceOutcome("completed", enqueue_next=False)
            return AdvanceOutcome("noop", enqueue_next=False)

        step = _get_step(step_rows, nxt.id)
        if step is None:
            step = StepRun(
                tenant_id=tenant_id,
                run_id=run_id,
                step_id=nxt.id,
                tool=nxt.tool,
                status=StepStatus.PENDING,
                attempt=0,
                input=nxt.args,
            )
            session.add(step)

        connector_ctx: ConnectorContext | None = None
        try:
            spec = REGISTRY.get(nxt.tool)
            args_model = spec.input_model.model_validate(nxt.args)

            if spec.side_effecting:
                if spec.requires_approval:
                    return _park_for_approval(session, run, tenant_id, nxt, step, spec, store)
                step.attempt = step.attempt + 1
                return _claim_action(session, run, tenant_id, nxt, step, spec, store)

            # Inline (M3/M5) path: execute in-lock.
            step.status = StepStatus.RUNNING
            step.attempt = step.attempt + 1
            step.started_at = _now()
            connector_ctx = (
                _resolve_connector(session, tenant_id, spec.connector_type, nxt.connector, store)
                if spec.connector_type is not None
                else None
            )
            inline_start = time.perf_counter()
            output = execute_tool(spec, args_model, connector_ctx)
            metrics.observe_tool(spec.name, "success", time.perf_counter() - inline_start)
        except _STEP_FAILURES as exc:
            if (
                connector_ctx is not None
                and connector_ctx.connector_id is not None
                and isinstance(exc, ConnectorUnhealthyError)
            ):
                _set_connector_status(session, connector_ctx.connector_id, "error")
            return _fail_run_step(session, run, step, str(exc))

        step.status = StepStatus.SUCCESS
        step.output = output
        step.finished_at = _now()
        _mark_progress(run)  # step terminal transition (inline success)
        return AdvanceOutcome("advanced", enqueue_next=True, step_id=nxt.id)


# Enqueue callback: (run_id, delay_seconds | None).
EnqueueFn = Callable[[uuid.UUID, float | None], None]
ActionRunner = Callable[[ActionTask], ActionExecResult]


def process_advance(
    session_factory: sessionmaker[Session],
    run_id: uuid.UUID,
    enqueue: EnqueueFn,
    secret_store: SecretStore | None = None,
    action_runner: ActionRunner | None = None,
) -> AdvanceOutcome:
    """Run one advancement; for actions perform the side effect OUT of the lock,
    then finalize. Enqueue (possibly delayed) the next advancement after commit."""
    store = secret_store if secret_store is not None else build_secret_store()
    outcome = execute_advancement(session_factory, run_id, store)

    if outcome.action_task is not None:
        runner = action_runner if action_runner is not None else run_action
        action_start = time.perf_counter()
        result = runner(outcome.action_task)
        final = finalize_action(
            session_factory, outcome.action_task, result, set_current_tenant_sync
        )
        _outcome_label = {"advanced": "success", "retry": "retry", "failed": "failed"}.get(
            final.result, "noop"
        )
        metrics.observe_tool(
            outcome.action_task.tool, _outcome_label, time.perf_counter() - action_start
        )
        metrics.record_action_attempt(outcome.action_task.tool, _outcome_label)
        if final.result == "advanced":
            enqueue(run_id, None)
        elif final.result == "retry":
            enqueue(run_id, final.defer_seconds)
        # 'failed'/'noop' -> nothing to enqueue.
        return AdvanceOutcome(
            final.result if final.result != "noop" else "noop",  # type: ignore[arg-type]
            enqueue_next=final.result in ("advanced", "retry"),
            step_id=outcome.step_id,
        )

    if outcome.result == "deferred" and outcome.defer_seconds is not None:
        enqueue(run_id, outcome.defer_seconds)
        return outcome

    if outcome.enqueue_next:
        enqueue(run_id, None)
    return outcome
