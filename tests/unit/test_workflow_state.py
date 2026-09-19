"""Run and step state-machine transitions (M3: no SKIPPED)."""

from nlw.domain.workflow import (
    RunStatus,
    StepStatus,
    can_transition_run,
    can_transition_step,
)


def test_run_transitions() -> None:
    assert can_transition_run(RunStatus.PENDING, RunStatus.RUNNING)
    assert can_transition_run(RunStatus.RUNNING, RunStatus.COMPLETED)
    assert can_transition_run(RunStatus.RUNNING, RunStatus.FAILED)
    assert not can_transition_run(RunStatus.PENDING, RunStatus.COMPLETED)
    assert not can_transition_run(RunStatus.COMPLETED, RunStatus.RUNNING)
    assert not can_transition_run(RunStatus.FAILED, RunStatus.RUNNING)


def test_step_transitions() -> None:
    assert can_transition_step(StepStatus.PENDING, StepStatus.RUNNING)
    assert can_transition_step(StepStatus.RUNNING, StepStatus.SUCCESS)
    assert can_transition_step(StepStatus.RUNNING, StepStatus.FAILED)
    assert not can_transition_step(StepStatus.PENDING, StepStatus.SUCCESS)
    assert not can_transition_step(StepStatus.SUCCESS, StepStatus.RUNNING)


def test_step_status_has_no_skipped() -> None:
    assert not hasattr(StepStatus, "SKIPPED")
    assert {s.value for s in StepStatus} == {"PENDING", "RUNNING", "SUCCESS", "FAILED"}
