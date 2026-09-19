"""Workflow domain model and pure execution helpers.

Deterministic, side-effect-free logic that the durable engine relies on:
the plan/step shapes, the run/step state machines, and next-step selection.
No database or I/O here (mypy strict).
"""

import enum
from typing import Any

from pydantic import BaseModel, Field


class RunStatus(enum.StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class StepStatus(enum.StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


# M3 has no conditional execution, so SKIPPED is intentionally absent.
_RUN_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    RunStatus.PENDING: frozenset({RunStatus.RUNNING}),
    RunStatus.RUNNING: frozenset({RunStatus.COMPLETED, RunStatus.FAILED}),
    RunStatus.COMPLETED: frozenset(),
    RunStatus.FAILED: frozenset(),
}

_STEP_TRANSITIONS: dict[StepStatus, frozenset[StepStatus]] = {
    StepStatus.PENDING: frozenset({StepStatus.RUNNING}),
    StepStatus.RUNNING: frozenset({StepStatus.SUCCESS, StepStatus.FAILED}),
    StepStatus.SUCCESS: frozenset(),
    StepStatus.FAILED: frozenset(),
}

_TERMINAL_STEP: frozenset[StepStatus] = frozenset({StepStatus.SUCCESS, StepStatus.FAILED})


def can_transition_run(current: RunStatus, new: RunStatus) -> bool:
    return new in _RUN_TRANSITIONS[current]


def can_transition_step(current: StepStatus, new: StepStatus) -> bool:
    return new in _STEP_TRANSITIONS[current]


class WorkflowStep(BaseModel):
    id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)


class WorkflowPlan(BaseModel):
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
