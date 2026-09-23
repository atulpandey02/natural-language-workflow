"""Run/step transition guard (M12B-A, audit F5).

The domain declares the legal state-machine edges. Before M12B-A the
``can_transition_*`` predicates were tested in isolation but never used as a
gate: the engine set statuses directly, so legality rested on code structure and
the DB CHECK constraints (which bound the status *set*, not the *edges*). These
tests lock the guard's behavior and the table's internal consistency; the engine
now assigns every run/step status through ``assert_transition_*``.
"""

import pytest

from nlw.domain.workflow import (
    IllegalTransitionError,
    RunStatus,
    StepStatus,
    assert_transition_run,
    assert_transition_step,
    can_transition_run,
    can_transition_step,
)

# The status sets the DB CHECK constraints allow (db/models.py ck_run_status /
# ck_step_status). The transition tables must not reference a status outside these.
_RUN_DB_STATUSES = {"PENDING", "RUNNING", "WAITING_APPROVAL", "COMPLETED", "FAILED"}
_STEP_DB_STATUSES = {"PENDING", "RUNNING", "WAITING_APPROVAL", "SUCCESS", "FAILED"}


def test_run_and_step_enums_match_db_check_sets() -> None:
    assert {s.value for s in RunStatus} == _RUN_DB_STATUSES
    assert {s.value for s in StepStatus} == _STEP_DB_STATUSES


def test_terminal_states_have_no_outgoing_edges() -> None:
    for run_terminal in (RunStatus.COMPLETED, RunStatus.FAILED):
        assert all(not can_transition_run(run_terminal, r) for r in RunStatus)
    for step_terminal in (StepStatus.SUCCESS, StepStatus.FAILED):
        assert all(not can_transition_step(step_terminal, st) for st in StepStatus)


def test_assert_transition_returns_new_on_legal_edge() -> None:
    assert assert_transition_run(RunStatus.PENDING, RunStatus.RUNNING) == RunStatus.RUNNING
    assert assert_transition_step(StepStatus.RUNNING, StepStatus.SUCCESS) == StepStatus.SUCCESS


def test_self_edge_is_permitted_for_idempotent_redrives() -> None:
    # A re-drive that re-asserts the current status must not trip the guard, even
    # for a terminal state (a terminal run re-observed is a no-op).
    assert assert_transition_run(RunStatus.RUNNING, RunStatus.RUNNING) == RunStatus.RUNNING
    assert assert_transition_run(RunStatus.FAILED, RunStatus.FAILED) == RunStatus.FAILED
    assert assert_transition_step(StepStatus.SUCCESS, StepStatus.SUCCESS) == StepStatus.SUCCESS


@pytest.mark.parametrize(
    "current,new",
    [
        (RunStatus.PENDING, RunStatus.COMPLETED),  # must pass through RUNNING
        (RunStatus.COMPLETED, RunStatus.RUNNING),  # terminal is final
        (RunStatus.FAILED, RunStatus.RUNNING),
        (RunStatus.WAITING_APPROVAL, RunStatus.COMPLETED),  # must resume to RUNNING first
    ],
)
def test_illegal_run_edges_raise(current: RunStatus, new: RunStatus) -> None:
    with pytest.raises(IllegalTransitionError):
        assert_transition_run(current, new)


@pytest.mark.parametrize(
    "current,new",
    [
        (StepStatus.PENDING, StepStatus.SUCCESS),  # cannot skip RUNNING
        (StepStatus.SUCCESS, StepStatus.RUNNING),
        (StepStatus.FAILED, StepStatus.RUNNING),
        (StepStatus.WAITING_APPROVAL, StepStatus.SUCCESS),
    ],
)
def test_illegal_step_edges_raise(current: StepStatus, new: StepStatus) -> None:
    with pytest.raises(IllegalTransitionError):
        assert_transition_step(current, new)
