"""Evaluation harness core (M12B-A, Part B).

Grades a planner output (a checked-in fixture, or a live model result) against
the REAL tool registry and the REAL feasibility engine, so the corpus exercises
production authorization logic rather than a mock. No execution ever happens
here — grading stops at the feasibility verdict, so a case can never cause a
side effect.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

import nlw.tools.builtin  # noqa: F401  (populates the registry)
from nlw.connectors.postgres import PostgresSchemaHint
from nlw.feasibility.engine import FeasibilityReport, FeasibilityStatus, check_plan
from nlw.feasibility.limits import DEFAULT_LIMITS, PlatformLimits
from nlw.planner.capabilities import SafeConnector, build_capability_view
from nlw.planner.provider import LLMInvalidOutputError, parse_planner_output
from nlw.planner.schema import PlannerOutput
from nlw.registry.registry import REGISTRY


class EvalConnector(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: str
    status: str = "active"
    allowed_schemas: list[str] | None = None
    allowed_tables: list[str] | None = None
    schema_hint: dict[str, Any] | None = None

    def to_safe(self) -> SafeConnector:
        return SafeConnector(
            name=self.name,
            type=self.type,
            status=self.status,
            allowed_schemas=self.allowed_schemas,
            allowed_tables=self.allowed_tables,
            schema_hint=self.schema_hint,
        )


class EvalExpect(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # The deterministic feasibility verdict the fixture must produce.
    feasibility_status: FeasibilityStatus
    # Reject codes that MUST be present (subset; other findings may also appear).
    reject_codes: list[str] = []
    # Sorted step ids expected to require approval.
    approvals_required: list[str] = []
    # If set, the capability view offered to the model must expose exactly these
    # tool names (proves connector-gated availability). None = do not assert.
    allowed_tools: list[str] | None = None
    approval_required: bool = False
    execution_may_start: bool = False


class EvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    request: str  # informational (what the user asked); not fed to replay
    actor_role: str = "member"
    connectors: list[EvalConnector] = []
    # The planner output fixture (what the model returned / would return).
    planner_output: dict[str, Any]
    expect: EvalExpect
    note: str | None = None


class Corpus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    corpus_version: str
    description: str
    cases: list[EvalCase]


@dataclass
class GradeResult:
    case_id: str
    category: str
    passed: bool
    observed_status: str
    expected_status: str
    observed_reject_codes: list[str]
    observed_approvals: list[str]
    observed_allowed_tools: list[str]
    execution_may_start: bool
    invalid_output: bool = False
    failures: list[str] = field(default_factory=list)


def load_corpus(path: Path) -> Corpus:
    return Corpus.model_validate_json(path.read_text())


def corpus_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "tests" / "eval" / "corpus"


def load_all_cases() -> list[EvalCase]:
    cases: list[EvalCase] = []
    for p in sorted(corpus_dir().glob("*.json")):
        cases.extend(load_corpus(p).cases)
    return cases


def corpus_digest() -> str:
    """sha256 over the exact bytes of every corpus file (sorted by name).

    Recorded in benchmark evidence so a reported result is bound to the precise
    corpus it was measured against; with a single corpus file this equals that
    file's sha256.
    """
    h = hashlib.sha256()
    for p in sorted(corpus_dir().glob("*.json")):
        h.update(p.read_bytes())
    return h.hexdigest()


def corpus_versions() -> dict[str, str]:
    """``{file name: corpus_version}`` for every corpus file."""
    return {p.name: load_corpus(p).corpus_version for p in sorted(corpus_dir().glob("*.json"))}


def _validate_connectors(case: EvalCase) -> None:
    """Connectors are validated the way the API would validate them, so a corpus
    fixture cannot smuggle an impossible connector past the harness."""
    for c in case.connectors:
        if c.type == "postgres" and c.schema_hint is not None:
            PostgresSchemaHint.model_validate(c.schema_hint)


def build_view_and_tools(
    case: EvalCase,
) -> tuple[list[SafeConnector], set[str]]:
    connectors = [c.to_safe() for c in case.connectors]
    all_tool_names = {spec.name for spec in REGISTRY.all()}
    return connectors, all_tool_names


def parse_fixture(case: EvalCase) -> PlannerOutput | None:
    """Strictly parse the fixture exactly as the planner parses model output.
    Returns None when the fixture is (deliberately) structurally invalid."""
    try:
        return parse_planner_output(json.dumps(case.planner_output))
    except LLMInvalidOutputError:
        return None


def run_feasibility(
    case: EvalCase, output: PlannerOutput, limits: PlatformLimits = DEFAULT_LIMITS
) -> tuple[FeasibilityReport, list[str]]:
    _validate_connectors(case)
    connectors, all_tool_names = build_view_and_tools(case)
    view = build_capability_view(REGISTRY.all(), connectors, include_demo=True)
    report = check_plan(
        output.to_workflow_plan(),
        view,
        limits,
        all_tool_names,
        clarification_requested=output.clarification_needed,
        clarification_questions=output.clarification_questions,
    )
    allowed_tools = sorted(t.name for t in view.tools)
    return report, allowed_tools


def grade_report(
    case: EvalCase, report: FeasibilityReport, allowed_tools: list[str]
) -> GradeResult:
    exp = case.expect
    reject_codes = sorted(f.code.value for f in report.findings if f.severity == "reject")
    approvals = sorted(report.approvals_required)
    exec_start = report.status in (FeasibilityStatus.PASS, FeasibilityStatus.NEEDS_APPROVAL)
    failures: list[str] = []

    if report.status != exp.feasibility_status:
        failures.append(f"status {report.status.value} != expected {exp.feasibility_status.value}")
    missing = [c for c in exp.reject_codes if c not in reject_codes]
    if missing:
        failures.append(f"missing reject codes {missing} (got {reject_codes})")
    if sorted(exp.approvals_required) != approvals:
        failures.append(f"approvals {approvals} != expected {sorted(exp.approvals_required)}")
    if exp.allowed_tools is not None and sorted(exp.allowed_tools) != allowed_tools:
        failures.append(f"allowed_tools {allowed_tools} != expected {sorted(exp.allowed_tools)}")
    if exec_start != exp.execution_may_start:
        failures.append(f"execution_may_start {exec_start} != expected {exp.execution_may_start}")
    if bool(approvals) != exp.approval_required:
        failures.append(f"approval_required {bool(approvals)} != expected {exp.approval_required}")

    return GradeResult(
        case_id=case.id,
        category=case.category,
        passed=not failures,
        observed_status=report.status.value,
        expected_status=exp.feasibility_status.value,
        observed_reject_codes=reject_codes,
        observed_approvals=approvals,
        observed_allowed_tools=allowed_tools,
        execution_may_start=exec_start,
        failures=failures,
    )


def replay_case(case: EvalCase) -> GradeResult:
    """Deterministic replay: fixture -> feasibility -> graded verdict. No network."""
    output = parse_fixture(case)
    if output is None:
        # An intentionally invalid fixture must expect a REJECT (deterministic).
        passed = case.expect.feasibility_status == FeasibilityStatus.REJECT
        return GradeResult(
            case_id=case.id,
            category=case.category,
            passed=passed and not case.expect.execution_may_start,
            observed_status="REJECT",
            expected_status=case.expect.feasibility_status.value,
            observed_reject_codes=["PLANNER_INVALID_OUTPUT"],
            observed_approvals=[],
            observed_allowed_tools=[],
            execution_may_start=False,
            invalid_output=True,
            failures=([] if passed else ["invalid fixture but case did not expect REJECT"]),
        )
    report, allowed = run_feasibility(case, output)
    return grade_report(case, report, allowed)
