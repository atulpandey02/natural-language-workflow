"""M6 hardening of the executable plan model must not break M3/M5 shapes."""

import pytest
from pydantic import ValidationError

from nlw.domain.workflow import WorkflowPlan, WorkflowStep


def test_existing_plan_shape_still_valid() -> None:
    plan = WorkflowPlan.model_validate(
        {
            "steps": [
                {
                    "id": "a",
                    "tool": "postgres.query",
                    "args": {"sql": "SELECT 1"},
                    "connector": "pg",
                },
                {"id": "b", "tool": "fake.echo", "depends_on": ["a"]},
            ]
        }
    )
    assert len(plan.steps) == 2


def test_roundtrip_model_dump() -> None:
    step = WorkflowStep(id="a", tool="fake.echo")
    assert WorkflowStep.model_validate(step.model_dump()) == step


def test_extra_field_on_step_rejected() -> None:
    with pytest.raises(ValidationError):
        WorkflowStep.model_validate({"id": "a", "tool": "t", "sneaky": 1})


def test_extra_field_on_plan_rejected() -> None:
    with pytest.raises(ValidationError):
        WorkflowPlan.model_validate({"steps": [], "extra": 1})


@pytest.mark.parametrize("bad", ["", "has space", "has!bang", "x" * 65])
def test_bad_step_id_rejected(bad: str) -> None:
    with pytest.raises(ValidationError):
        WorkflowStep.model_validate({"id": bad, "tool": "t"})


def test_empty_tool_rejected() -> None:
    with pytest.raises(ValidationError):
        WorkflowStep.model_validate({"id": "a", "tool": ""})
