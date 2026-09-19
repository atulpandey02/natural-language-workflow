"""Pure next-step selection and terminal detection."""

from nlw.domain.workflow import (
    StepStatus,
    WorkflowPlan,
    all_succeeded,
    any_failed,
    select_next_step,
)

PLAN = WorkflowPlan.model_validate(
    {
        "steps": [
            {"id": "a", "tool": "fake.echo"},
            {"id": "b", "tool": "fake.echo", "depends_on": ["a"]},
            {"id": "c", "tool": "fake.echo", "depends_on": ["b"]},
        ]
    }
)


def test_first_step_when_nothing_done() -> None:
    assert select_next_step(PLAN, {}) is not None
    assert select_next_step(PLAN, {}).id == "a"  # type: ignore[union-attr]


def test_dependency_gating() -> None:
    # b is not runnable until a is SUCCESS
    assert select_next_step(PLAN, {"a": StepStatus.RUNNING}) is None
    nxt = select_next_step(PLAN, {"a": StepStatus.SUCCESS})
    assert nxt is not None and nxt.id == "b"


def test_none_when_all_done() -> None:
    states = {"a": StepStatus.SUCCESS, "b": StepStatus.SUCCESS, "c": StepStatus.SUCCESS}
    assert select_next_step(PLAN, states) is None
    assert all_succeeded(PLAN, states)


def test_any_failed() -> None:
    assert any_failed({"a": StepStatus.FAILED})
    assert not any_failed({"a": StepStatus.SUCCESS})
