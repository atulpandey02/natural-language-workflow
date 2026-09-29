"""Redacted plan outcome events (Phase 2 B02, migration 0023).

Deterministic, code-owned classification of every planning attempt into a
closed vocabulary, so pilot failures can be measured without reading anyone's
request text. Nothing here stores or logs free text:

- ``outcome`` comes from the feasibility status (or the provider failure);
- ``category`` is derived from finding CODES with a fixed precedence;
- ``request_shape`` is a set of boolean tags from fixed English patterns;
- the request itself is reduced to a length bucket.

The model's own claims are never used for classification.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.feasibility.engine import FeasibilityCode, FeasibilityReport, FeasibilityStatus

OUTCOME_BY_STATUS = {
    FeasibilityStatus.PASS: "PASS",
    FeasibilityStatus.REJECT: "REJECT",
    FeasibilityStatus.NEEDS_CLARIFICATION: "CLARIFY",
    FeasibilityStatus.NEEDS_APPROVAL: "APPROVAL",
}

# Every feasibility code has exactly one category (a unit test enforces that a
# new code cannot be added without classifying it).
CATEGORY_BY_CODE: dict[FeasibilityCode, str] = {
    FeasibilityCode.EMPTY_PLAN: "MODEL_MISUNDERSTANDING",
    FeasibilityCode.DUPLICATE_STEP_ID: "MODEL_MISUNDERSTANDING",
    FeasibilityCode.ARG_VALIDATION_FAILED: "MODEL_MISUNDERSTANDING",
    FeasibilityCode.UNKNOWN_DEPENDENCY: "MODEL_MISUNDERSTANDING",
    FeasibilityCode.SELF_DEPENDENCY: "MODEL_MISUNDERSTANDING",
    FeasibilityCode.CYCLE_DETECTED: "MODEL_MISUNDERSTANDING",
    FeasibilityCode.CONNECTOR_ON_CONNECTORLESS_TOOL: "MODEL_MISUNDERSTANDING",
    FeasibilityCode.CONNECTOR_TYPE_MISMATCH: "MODEL_MISUNDERSTANDING",
    FeasibilityCode.UNKNOWN_TOOL: "MISSING_CAPABILITY",
    FeasibilityCode.TOOL_NOT_AVAILABLE: "MISSING_CAPABILITY",
    FeasibilityCode.CONNECTOR_REQUIRED: "MISSING_CAPABILITY",
    FeasibilityCode.CONNECTOR_NOT_FOUND: "MISSING_CAPABILITY",
    FeasibilityCode.CONNECTOR_UNUSABLE: "MISSING_CAPABILITY",
    FeasibilityCode.CONNECTOR_CONFIG_CHANGED: "MISSING_CAPABILITY",
    FeasibilityCode.CONNECTOR_HEALTH_UNVERIFIED: "MISSING_CAPABILITY",
    FeasibilityCode.SQL_REJECTED: "POLICY_REJECTION",
    FeasibilityCode.TOO_MANY_STEPS: "PLATFORM_LIMIT",
    FeasibilityCode.PLAN_TOO_LARGE: "PLATFORM_LIMIT",
    FeasibilityCode.ARGS_TOO_LARGE: "PLATFORM_LIMIT",
    FeasibilityCode.TOO_MANY_DEPENDENCIES: "PLATFORM_LIMIT",
    FeasibilityCode.STEP_TIMEOUT_EXCEEDED: "PLATFORM_LIMIT",
    FeasibilityCode.TOTAL_TIMEOUT_EXCEEDED: "PLATFORM_LIMIT",
    FeasibilityCode.CLARIFICATION_REQUIRED: "UNDERSPECIFIED_REQUEST",
    FeasibilityCode.PLANNER_INVALID_OUTPUT: "INVALID_OUTPUT",
    # Not a failure: an approval-gated plan is a valid plan.
    FeasibilityCode.APPROVAL_REQUIRED: "",
}

# When several reject findings disagree, the most operationally significant wins.
CATEGORY_PRECEDENCE = (
    "POLICY_REJECTION",
    "INVALID_OUTPUT",
    "MISSING_CAPABILITY",
    "PLATFORM_LIMIT",
    "MODEL_MISUNDERSTANDING",
    "UNDERSPECIFIED_REQUEST",
)

LENGTH_BUCKETS = ((50, "lt50"), (200, "50_199"), (1000, "200_999"))

# Fixed English patterns -> tags. Tags are booleans; the matched text is never
# kept. A missed tag is a measurement gap, never a safety decision.
_SHAPE_PATTERNS: dict[str, re.Pattern[str]] = {
    "has_time_window": re.compile(
        r"\b(last|past|previous|this|next)\s+(\d+\s+)?(day|week|month|quarter|year)s?\b"
        r"|\b(yesterday|today|ytd|mtd|qtd|q[1-4]|since|between)\b"
        r"|\b(19|20)\d{2}\b",
        re.I,
    ),
    "has_comparison": re.compile(
        r"\b(compare|compared|comparison|versus|vs\.?|against|difference|change|growth|trend)\b",
        re.I,
    ),
    "has_top_n": re.compile(r"\b(top|bottom|highest|lowest|best|worst|largest|smallest)\b", re.I),
    "asks_why": re.compile(r"\b(why|cause|caused|reason|because)\b", re.I),
    "asks_export": re.compile(
        r"\b(export|download|csv|spreadsheet|excel|dump|list all|all rows|raw data)\b", re.I
    ),
    "asks_action": re.compile(
        r"\b(send|post|email|notify|slack|message|delete|update|create|schedule|share)\b", re.I
    ),
}


_PROVIDER_OK = re.compile(r"^[a-z0-9_-]{1,32}$")
_MODEL_OK = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")
_CONTRACT_OK = re.compile(r"^[a-z0-9._-]{1,40}$")


def _ident(value: str | None, pattern: re.Pattern[str], fallback: str | None) -> str | None:
    """Identifiers are stored only if they match the column's closed shape."""
    return value if value is not None and pattern.match(value) else fallback


def length_bucket(n: int) -> str:
    for limit, name in LENGTH_BUCKETS:
        if n < limit:
            return name
    return "gte1000"


def request_shape(request: str) -> list[str]:
    return sorted(tag for tag, pattern in _SHAPE_PATTERNS.items() if pattern.search(request))


def category_for(outcome: str, codes: Iterable[FeasibilityCode]) -> str | None:
    """The single category for an outcome, from finding codes only."""
    if outcome in ("PASS", "APPROVAL"):
        return None
    if outcome == "INFRA_FAIL":
        return "INFRA_FAILURE"
    found = {CATEGORY_BY_CODE[c] for c in codes} - {""}
    for category in CATEGORY_PRECEDENCE:
        if category in found:
            return category
    return "UNDERSPECIFIED_REQUEST" if outcome == "CLARIFY" else None


@dataclass(frozen=True)
class OutcomeEvent:
    outcome: str
    category: str | None
    finding_codes: list[str]
    clarification_count: int
    step_count: int
    request_len_bucket: str
    request_shape: list[str]
    provider: str
    model: str
    contract_version: str | None
    latency_ms: int | None
    tokens_in: int | None
    tokens_out: int | None
    proposal_id: uuid.UUID | None = None
    id: uuid.UUID = field(default_factory=uuid.uuid4)


def from_report(
    report: FeasibilityReport,
    *,
    request: str,
    step_count: int,
    provider: str,
    model: str,
    contract_version: str | None,
    latency_ms: int | None,
    tokens_in: int | None,
    tokens_out: int | None,
    proposal_id: uuid.UUID,
) -> OutcomeEvent:
    codes = [f.code for f in report.findings if f.severity == "reject"]
    if report.status == FeasibilityStatus.NEEDS_CLARIFICATION:
        codes = codes or [f.code for f in report.findings]
    outcome = OUTCOME_BY_STATUS[report.status]
    if FeasibilityCode.PLANNER_INVALID_OUTPUT in codes:
        outcome = "INVALID_OUTPUT"
    return OutcomeEvent(
        outcome=outcome,
        category=category_for(outcome, codes),
        finding_codes=sorted({c.value for c in codes}),
        clarification_count=len(report.clarification_questions),
        step_count=step_count,
        request_len_bucket=length_bucket(len(request)),
        request_shape=request_shape(request),
        provider=_ident(provider, _PROVIDER_OK, "unknown") or "unknown",
        model=_ident(model, _MODEL_OK, "unknown") or "unknown",
        contract_version=_ident(contract_version, _CONTRACT_OK, None),
        latency_ms=latency_ms,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        proposal_id=proposal_id,
    )


def infra_failure(
    *, request: str, provider: str, model: str, contract_version: str | None, latency_ms: int
) -> OutcomeEvent:
    return OutcomeEvent(
        outcome="INFRA_FAIL",
        category="INFRA_FAILURE",
        finding_codes=[],
        clarification_count=0,
        step_count=0,
        request_len_bucket=length_bucket(len(request)),
        request_shape=request_shape(request),
        provider=_ident(provider, _PROVIDER_OK, "unknown") or "unknown",
        model=_ident(model, _MODEL_OK, "unknown") or "unknown",
        contract_version=_ident(contract_version, _CONTRACT_OK, None),
        latency_ms=latency_ms,
        tokens_in=None,
        tokens_out=None,
    )


async def insert_event(session: AsyncSession, tenant_id: uuid.UUID, event: OutcomeEvent) -> None:
    """Insert under the CALLER's signed request context (RLS: member of tenant)."""
    await session.execute(
        text(
            "INSERT INTO plan_outcome_events (id, tenant_id, proposal_id, outcome, category, "
            "finding_codes, clarification_count, step_count, request_len_bucket, "
            "request_shape, provider, model, contract_version, latency_ms, tokens_in, "
            "tokens_out) VALUES (:id, :tenant_id, :proposal_id, :outcome, :category, "
            ":finding_codes, :clarification_count, :step_count, :request_len_bucket, "
            ":request_shape, :provider, :model, :contract_version, :latency_ms, :tokens_in, "
            ":tokens_out)"
        ),
        {
            "id": event.id,
            "tenant_id": tenant_id,
            "proposal_id": event.proposal_id,
            "outcome": event.outcome,
            "category": event.category,
            "finding_codes": event.finding_codes,
            "clarification_count": event.clarification_count,
            "step_count": event.step_count,
            "request_len_bucket": event.request_len_bucket,
            "request_shape": event.request_shape,
            "provider": event.provider,
            "model": event.model,
            "contract_version": event.contract_version,
            "latency_ms": event.latency_ms,
            "tokens_in": event.tokens_in,
            "tokens_out": event.tokens_out,
        },
    )
