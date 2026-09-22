"""The planner's LLM-boundary contract (M6).

``PlannerOutput`` is the ONLY shape the model may return. It is strict
(``extra='forbid'``) and is parsed, schema-validated, then handed to the
deterministic feasibility engine, which owns the final verdict. The model's
``clarification_needed`` is an advisory *request*, never the final status.
"""

from pydantic import BaseModel, ConfigDict, Field

from nlw.domain.workflow import STEP_ID_PATTERN, WorkflowPlan, WorkflowStep

# Version of the planner contract = the strict output schema (this module) + the
# system prompt / prompt-construction contract (planner/prompt.py,
# docs/security/planner-prompt-contract.md). Bump it whenever either changes so
# stored provenance records which contract produced a plan. Not a wire version.
PLANNER_CONTRACT_VERSION = "planner-1"

# Bounds on the model's proposed plan (defense against pathological output).
MAX_PROPOSED_STEPS = 100
MAX_CLARIFICATION_QUESTIONS = 10
WORKFLOW_NAME_MIN = 1
WORKFLOW_NAME_MAX = 120


class PlannerStep(BaseModel):
    """Mirror of :class:`WorkflowStep` at the model boundary (strict)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=STEP_ID_PATTERN)
    tool: str = Field(min_length=1)
    args: dict[str, object] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)
    connector: str | None = None


class PlannerOutput(BaseModel):
    """Structured model output. Strict, bounded, and never self-authorizing."""

    model_config = ConfigDict(extra="forbid")

    workflow_name: str = Field(min_length=WORKFLOW_NAME_MIN, max_length=WORKFLOW_NAME_MAX)
    clarification_needed: bool = False
    clarification_questions: list[str] = Field(
        default_factory=list, max_length=MAX_CLARIFICATION_QUESTIONS
    )
    steps: list[PlannerStep] = Field(default_factory=list, max_length=MAX_PROPOSED_STEPS)

    def to_workflow_plan(self) -> WorkflowPlan:
        """Convert the proposed steps into the executable domain plan shape."""
        return WorkflowPlan(
            steps=[
                WorkflowStep(
                    id=s.id,
                    tool=s.tool,
                    args=dict(s.args),
                    depends_on=list(s.depends_on),
                    connector=s.connector,
                )
                for s in self.steps
            ]
        )
