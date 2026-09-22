"""Deterministic grounded run summary (M12B-A, audit F2, Part H).

A pure, non-LLM function that turns the PERSISTED run state into a grounded
outcome summary. It exists so the product can present "what happened" without a
model inventing results. Design invariants (tested):

- consumes only the immutable plan + persisted step/action state (no I/O, no
  model call, no tool call, never mutates anything);
- distinguishes SUCCESS / FAILED / UNKNOWN / SKIPPED / WAITING_APPROVAL /
  RUNNING / PENDING per step, keyed to the step id;
- **never reports a step as succeeded when its external action outcome is
  UNKNOWN**, and never turns FAILED/SKIPPED/UNKNOWN into success at the run
  level;
- is bounded: the number of step lines and each step's detail are capped;
- every conclusion maps to concrete step ids (grounding), and it invents nothing
  for steps that did not run.

The API exposes this at ``GET /runs/{id}/summary``. An optional LLM synthesis
stage (not built here) would have to consume this exact grounded structure and
keep it as the authoritative fallback.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel

from nlw.domain.workflow import RunStatus, StepStatus, WorkflowPlan

# The distinguishing error class the engine writes for an ambiguous external
# action (engine/actions.py). Mirrored here (not imported) to keep this module a
# leaf with no engine-execution dependency.
ACTION_OUTCOME_UNKNOWN = "ACTION_OUTCOME_UNKNOWN"

# Bounds (never silently drop meaning — we cap and flag).
MAX_SUMMARY_STEPS = 200
MAX_DETAIL_CHARS = 240


class StepOutcome(enum.StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"  # external action outcome ambiguous — may or may not have occurred
    SKIPPED = "SKIPPED"  # never executed (run reached a terminal state first)
    WAITING_APPROVAL = "WAITING_APPROVAL"
    RUNNING = "RUNNING"
    PENDING = "PENDING"


class RunOutcome(enum.StrEnum):
    COMPLETED = "COMPLETED"  # every step succeeded
    FAILED = "FAILED"  # a step failed and no ambiguity
    FAILED_WITH_UNKNOWN = "FAILED_WITH_UNKNOWN"  # a side effect may or may not have occurred
    WAITING_APPROVAL = "WAITING_APPROVAL"
    IN_PROGRESS = "IN_PROGRESS"
    PENDING = "PENDING"


class StepView(BaseModel):
    """Persisted step facts the summary reads (adapted from ORM rows by the API)."""

    step_id: str
    tool: str
    status: StepStatus
    error: str | None = None
    has_output: bool = False


class ActionView(BaseModel):
    """Persisted external-action facts (status carries the 'unknown' outcome)."""

    step_id: str
    status: str  # 'pending' | 'success' | 'failed' | 'unknown'


class StepSummary(BaseModel):
    step_id: str
    tool: str
    outcome: StepOutcome
    detail: str


class RunSummary(BaseModel):
    run_status: RunStatus
    outcome: RunOutcome
    headline: str
    steps: list[StepSummary]
    total_steps: int
    succeeded: int
    failed: int
    unknown: int
    skipped: int
    truncated: bool


def _clip(text: str) -> str:
    text = text.strip()
    return text if len(text) <= MAX_DETAIL_CHARS else text[: MAX_DETAIL_CHARS - 1] + "…"


def _step_outcome(
    status: StepStatus, error: str | None, action_status: str | None, run_terminal: bool
) -> StepOutcome:
    if status == StepStatus.SUCCESS:
        return StepOutcome.SUCCESS
    if status == StepStatus.WAITING_APPROVAL:
        return StepOutcome.WAITING_APPROVAL
    if status == StepStatus.RUNNING:
        return StepOutcome.RUNNING
    if status == StepStatus.FAILED:
        # An ambiguous external action is UNKNOWN, never a definite failure/success.
        if action_status == "unknown" or error == ACTION_OUTCOME_UNKNOWN:
            return StepOutcome.UNKNOWN
        return StepOutcome.FAILED
    # PENDING: if the run already reached a terminal state, this step never ran.
    return StepOutcome.SKIPPED if run_terminal else StepOutcome.PENDING


def _detail(outcome: StepOutcome, tool: str, error: str | None, has_output: bool) -> str:
    match outcome:
        case StepOutcome.SUCCESS:
            return _clip(f"{tool} completed" + (" with output" if has_output else ""))
        case StepOutcome.UNKNOWN:
            return _clip(
                f"{tool}: the external action may or may not have completed; "
                "the outcome could not be confirmed and it was not retried"
            )
        case StepOutcome.FAILED:
            return _clip(f"{tool} failed: {error}" if error else f"{tool} failed")
        case StepOutcome.SKIPPED:
            return _clip(f"{tool} did not run because an earlier step ended the run")
        case StepOutcome.WAITING_APPROVAL:
            return _clip(f"{tool} is waiting for a human approval decision")
        case StepOutcome.RUNNING:
            return _clip(f"{tool} is running")
        case _:
            return _clip(f"{tool} has not started")


def _run_outcome(run_status: RunStatus, unknown: int, failed: int) -> RunOutcome:
    if run_status == RunStatus.COMPLETED:
        return RunOutcome.COMPLETED
    if run_status == RunStatus.FAILED:
        return RunOutcome.FAILED_WITH_UNKNOWN if unknown else RunOutcome.FAILED
    if run_status == RunStatus.WAITING_APPROVAL:
        return RunOutcome.WAITING_APPROVAL
    if run_status == RunStatus.RUNNING:
        return RunOutcome.IN_PROGRESS
    return RunOutcome.PENDING


def _headline(outcome: RunOutcome, total: int, succeeded: int, failed: int, unknown: int) -> str:
    match outcome:
        case RunOutcome.COMPLETED:
            return f"All {total} step(s) completed successfully."
        case RunOutcome.FAILED_WITH_UNKNOWN:
            return (
                f"The run failed. {succeeded} step(s) succeeded; {unknown} external action(s) "
                "may or may not have completed and were not retried. Review before re-running."
            )
        case RunOutcome.FAILED:
            return f"The run failed. {succeeded} step(s) succeeded, {failed} failed."
        case RunOutcome.WAITING_APPROVAL:
            return f"The run is paused: {succeeded}/{total} step(s) done, awaiting approval."
        case RunOutcome.IN_PROGRESS:
            return f"The run is in progress: {succeeded}/{total} step(s) done."
        case _:
            return f"The run has not started yet ({total} planned step(s))."


def summarize_run(
    *,
    run_status: RunStatus,
    plan: WorkflowPlan,
    steps: list[StepView],
    actions: list[ActionView] | None = None,
) -> RunSummary:
    """Grounded, deterministic summary of a persisted run. Pure; no I/O."""
    run_terminal = run_status in (RunStatus.COMPLETED, RunStatus.FAILED)
    by_step = {s.step_id: s for s in steps}
    action_status = {a.step_id: a.status for a in (actions or [])}

    ordered_ids = [s.id for s in plan.steps]
    # Include any executed step not in the plan spine (defensive; should not happen).
    for s in steps:
        if s.step_id not in ordered_ids:
            ordered_ids.append(s.step_id)

    summaries: list[StepSummary] = []
    succeeded = failed = unknown = skipped = 0
    truncated = len(ordered_ids) > MAX_SUMMARY_STEPS
    tool_by_id = {s.id: s.tool for s in plan.steps}

    for step_id in ordered_ids[:MAX_SUMMARY_STEPS]:
        sv = by_step.get(step_id)
        status = sv.status if sv else StepStatus.PENDING
        error = sv.error if sv else None
        has_output = sv.has_output if sv else False
        tool = tool_by_id.get(step_id) or (sv.tool if sv else "unknown")
        step_outcome = _step_outcome(status, error, action_status.get(step_id), run_terminal)
        if step_outcome == StepOutcome.SUCCESS:
            succeeded += 1
        elif step_outcome == StepOutcome.FAILED:
            failed += 1
        elif step_outcome == StepOutcome.UNKNOWN:
            unknown += 1
        elif step_outcome == StepOutcome.SKIPPED:
            skipped += 1
        summaries.append(
            StepSummary(
                step_id=step_id,
                tool=tool,
                outcome=step_outcome,
                detail=_detail(step_outcome, tool, error, has_output),
            )
        )

    run_outcome = _run_outcome(run_status, unknown, failed)
    total = len(ordered_ids)
    return RunSummary(
        run_status=run_status,
        outcome=run_outcome,
        headline=_headline(run_outcome, total, succeeded, failed, unknown),
        steps=summaries,
        total_steps=total,
        succeeded=succeeded,
        failed=failed,
        unknown=unknown,
        skipped=skipped,
        truncated=truncated,
    )
