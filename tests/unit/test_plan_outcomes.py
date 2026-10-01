"""B02: deterministic, redacted plan-outcome classification."""

import dataclasses
import uuid

import pytest

from nlw.feasibility.engine import (
    FeasibilityCode,
    FeasibilityFinding,
    FeasibilityReport,
    FeasibilityStatus,
    Severity,
)
from nlw.observability import plan_outcomes as po


def _report(
    status: FeasibilityStatus, *codes: FeasibilityCode, questions: int = 0
) -> FeasibilityReport:
    return FeasibilityReport(
        status=status,
        findings=[
            FeasibilityFinding(
                code=c, severity=Severity.REJECT, message=f"{c.value} names tool 'secret_tbl'"
            )
            for c in codes
        ],
        clarification_questions=[f"q{i}" for i in range(questions)],
    )


def _event(report: FeasibilityReport, request: str = "show sales") -> po.OutcomeEvent:
    return po.from_report(
        report,
        request=request,
        step_count=2,
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        contract_version="planner-1",
        latency_ms=120,
        tokens_in=10,
        tokens_out=5,
        proposal_id=uuid.uuid4(),
    )


def test_every_feasibility_code_is_classified() -> None:
    assert set(po.CATEGORY_BY_CODE) == set(FeasibilityCode)
    allowed = set(po.CATEGORY_PRECEDENCE) | {""}
    assert set(po.CATEGORY_BY_CODE.values()) <= allowed


def test_pass_and_approval_have_no_failure_category() -> None:
    assert _event(_report(FeasibilityStatus.PASS)).category is None
    e = _event(_report(FeasibilityStatus.NEEDS_APPROVAL))
    assert (e.outcome, e.category) == ("APPROVAL", None)


def test_precedence_picks_the_most_significant_category() -> None:
    e = _event(
        _report(
            FeasibilityStatus.REJECT,
            FeasibilityCode.CYCLE_DETECTED,
            FeasibilityCode.UNKNOWN_TOOL,
            FeasibilityCode.SQL_REJECTED,
        )
    )
    assert e.category == "POLICY_REJECTION"
    assert e.finding_codes == ["CYCLE_DETECTED", "SQL_REJECTED", "UNKNOWN_TOOL"]
    e2 = _event(
        _report(
            FeasibilityStatus.REJECT, FeasibilityCode.TOO_MANY_STEPS, FeasibilityCode.CYCLE_DETECTED
        )
    )
    assert e2.category == "PLATFORM_LIMIT"


def test_invalid_output_and_clarification() -> None:
    e = _event(_report(FeasibilityStatus.REJECT, FeasibilityCode.PLANNER_INVALID_OUTPUT))
    assert (e.outcome, e.category) == ("INVALID_OUTPUT", "INVALID_OUTPUT")
    c = _event(_report(FeasibilityStatus.NEEDS_CLARIFICATION, questions=2))
    assert (c.outcome, c.category, c.clarification_count) == (
        "CLARIFY",
        "UNDERSPECIFIED_REQUEST",
        2,
    )


def test_infra_failure_event() -> None:
    e = po.infra_failure(
        request="x" * 60,
        provider="anthropic",
        model="m-1",
        contract_version="planner-1",
        latency_ms=5,
    )
    assert (e.outcome, e.category, e.proposal_id, e.request_len_bucket) == (
        "INFRA_FAIL",
        "INFRA_FAILURE",
        None,
        "50_199",
    )


@pytest.mark.parametrize(
    ("n", "bucket"),
    [(0, "lt50"), (49, "lt50"), (50, "50_199"), (999, "200_999"), (1000, "gte1000")],
)
def test_length_buckets(n: int, bucket: str) -> None:
    assert po.length_bucket(n) == bucket


@pytest.mark.parametrize(
    ("text", "tags"),
    [
        ("Top 5 facilities by open shifts last month", ["has_time_window", "has_top_n"]),
        ("Why did fill rate drop versus Q2?", ["asks_why", "has_comparison", "has_time_window"]),
        ("export all rows to csv", ["asks_export"]),
        ("send the summary to slack", ["asks_action"]),
        ("hello", []),
    ],
)
def test_request_shape_tags(text: str, tags: list[str]) -> None:
    assert po.request_shape(text) == sorted(tags)


def test_event_never_carries_request_text_or_finding_messages() -> None:
    secret = "Dr. Jane Roe at Mercy West patient 12345"
    e = _event(_report(FeasibilityStatus.REJECT, FeasibilityCode.UNKNOWN_TOOL), request=secret)
    blob = repr(dataclasses.asdict(e))
    for fragment in ("Jane", "Mercy", "12345", "secret_tbl"):
        assert fragment not in blob


def test_identifiers_outside_the_closed_shape_are_replaced() -> None:
    e = po.from_report(
        _report(FeasibilityStatus.PASS),
        request="x",
        step_count=0,
        provider="Anthropic Inc",
        model="model with spaces; DROP",
        contract_version="Planner 1",
        latency_ms=None,
        tokens_in=None,
        tokens_out=None,
        proposal_id=uuid.uuid4(),
    )
    assert (e.provider, e.model, e.contract_version) == ("unknown", "unknown", None)
