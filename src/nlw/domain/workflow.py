"""Workflow domain model and pure execution helpers.

Deterministic, side-effect-free logic that the durable engine relies on:
the plan/step shapes, the run/step state machines, and next-step selection.
No database or I/O here (mypy strict).
"""

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# Step ids are used as dependency references and as durable step keys, so keep
# them short and to a safe identifier charset.
STEP_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"


class RunStatus(enum.StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    # M7: parked while a requires_approval action step awaits a human decision.
    WAITING_APPROVAL = "WAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class StepStatus(enum.StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    # M7: an approval-gated action step awaiting a decision.
    WAITING_APPROVAL = "WAITING_APPROVAL"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


# M3 has no conditional execution, so SKIPPED is intentionally absent.
# M7 adds WAITING_APPROVAL (run + step) for approval-gated actions.
_RUN_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    RunStatus.PENDING: frozenset({RunStatus.RUNNING}),
    RunStatus.RUNNING: frozenset(
        {RunStatus.WAITING_APPROVAL, RunStatus.COMPLETED, RunStatus.FAILED}
    ),
    RunStatus.WAITING_APPROVAL: frozenset({RunStatus.RUNNING, RunStatus.FAILED}),
    RunStatus.COMPLETED: frozenset(),
    RunStatus.FAILED: frozenset(),
}

_STEP_TRANSITIONS: dict[StepStatus, frozenset[StepStatus]] = {
    # PENDING -> FAILED is a real edge: the engine can fail a step before it is
    # marked RUNNING (a pre-execution error, or a rejected/undecided approval
    # path). It was missing from this table before M12B-A; wiring the transition
    # guard (assert_transition_step) into the engine surfaced it, and completing
    # the table is the behavior-preserving fix (no test asserted it was illegal).
    StepStatus.PENDING: frozenset(
        {StepStatus.RUNNING, StepStatus.WAITING_APPROVAL, StepStatus.FAILED}
    ),
    StepStatus.WAITING_APPROVAL: frozenset({StepStatus.RUNNING, StepStatus.FAILED}),
    StepStatus.RUNNING: frozenset({StepStatus.SUCCESS, StepStatus.FAILED}),
    StepStatus.SUCCESS: frozenset(),
    StepStatus.FAILED: frozenset(),
}

_TERMINAL_STEP: frozenset[StepStatus] = frozenset({StepStatus.SUCCESS, StepStatus.FAILED})


class IllegalTransitionError(RuntimeError):
    """A run/step state transition not permitted by the state machine (M12B-A).

    Raised as a defense-in-depth guard at the engine's write points. The DB
    CHECK constraints bound the *set* of statuses; this guards the *edges*. It
    must never fire in normal operation — if it does, the engine attempted an
    illegal transition and failing loudly is safer than persisting it.
    """


def can_transition_run(current: RunStatus, new: RunStatus) -> bool:
    return new in _RUN_TRANSITIONS[current]


def can_transition_step(current: StepStatus, new: StepStatus) -> bool:
    return new in _STEP_TRANSITIONS[current]


def assert_transition_run(current: RunStatus, new: RunStatus) -> RunStatus:
    """Return ``new`` if the run edge is legal, else raise. A no-op self-edge
    (current == new) is permitted so idempotent re-drives never trip the guard."""
    if new != current and not can_transition_run(current, new):
        raise IllegalTransitionError(f"illegal run transition {current} -> {new}")
    return new


def assert_transition_step(current: StepStatus, new: StepStatus) -> StepStatus:
    """Return ``new`` if the step edge is legal, else raise (self-edge allowed)."""
    if new != current and not can_transition_step(current, new):
        raise IllegalTransitionError(f"illegal step transition {current} -> {new}")
    return new


class WorkflowStep(BaseModel):
    # Strict: unknown keys are a hard error so a plan cannot smuggle fields past
    # deterministic validation. Existing M3/M5 plans use only the fields below.
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=STEP_ID_PATTERN)
    tool: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)
    # Name of the tenant connector to use (required for connector-backed tools).
    connector: str | None = None


class WorkflowPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    steps: list[WorkflowStep]

    def step(self, step_id: str) -> WorkflowStep:
        for s in self.steps:
            if s.id == step_id:
                return s
        raise KeyError(step_id)


def select_next_step(plan: WorkflowPlan, states: dict[str, StepStatus]) -> WorkflowStep | None:
    """First step (plan order) that is runnable: not terminal, not running, and
    all dependencies SUCCESS. Returns None when nothing is runnable."""
    for step in plan.steps:
        status = states.get(step.id, StepStatus.PENDING)
        if status != StepStatus.PENDING:
            continue
        if all(states.get(dep) == StepStatus.SUCCESS for dep in step.depends_on):
            return step
    return None


def all_succeeded(plan: WorkflowPlan, states: dict[str, StepStatus]) -> bool:
    return all(states.get(s.id) == StepStatus.SUCCESS for s in plan.steps)


def any_failed(states: dict[str, StepStatus]) -> bool:
    return any(status == StepStatus.FAILED for status in states.values())
