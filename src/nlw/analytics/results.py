"""Read-only analytics projection over the existing grounded run summary.

Only allowlisted analytical tools contribute. All text is code-owned; checkpoint
text, unknown fields, other tools and unsuccessful steps never enter charts.
"""

import hashlib
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from nlw.analytics.analysis import AnalysisArgs, AnalysisOutput
from nlw.analytics.datasets import CATEGORIES, ISSUES, MONTHS, REGIONS, TEAMS
from nlw.analytics.schema import (
    AnalyticsResult,
    Finding,
    Freshness,
    Metric,
    Series,
    Table,
    Unit,
    Visualization,
)
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.summary import RunSummary, StepOutcome

TOOLS = {"pilot.sales_analysis": "sales-v1", "pilot.support_analysis": "support-v1"}


@dataclass(frozen=True)
class Checkpoint:
    step_id: str
    tool: str
    output: dict[str, Any] | None
    finished: bool


def _series(
    labels: list[str], units: list[Unit], rows: list[list[int | float | None]]
) -> list[Series]:
    return [
        Series(label=label, unit=unit, values=[r[i] for r in rows])
        for i, (label, unit) in enumerate(zip(labels, units, strict=True))
    ]


def _fragment(data: AnalysisOutput, source: str) -> dict[str, Any]:
    sales = data.dataset == "sales-v1"
    names = (
        ["Revenue", "Orders", "Average order value", "Units"]
        if sales
        else ["SLA compliance", "Open backlog", "Resolution time", "Satisfaction"]
    )
    units: list[Unit] = (
        ["USD", "count", "USD", "count"] if sales else ["percent", "count", "hours", "score"]
    )
    sources = [source]
    metrics = [
        Metric(label=n, value=v, unit=u, source_step_ids=sources)
        for n, v, u in zip(names, data.totals, units, strict=True)
    ]
    monthly = _series(names, units, data.trend)
    group_labels = list(CATEGORIES if sales else ISSUES)
    category_names = (
        ["Revenue", "Orders", "Revenue change", "Units"]
        if sales
        else ["Tickets", "Reopened", "Resolution time", "Unused"]
    )
    category_units: list[Unit] = (
        ["USD", "count", "percent", "count"] if sales else ["count", "count", "hours", "count"]
    )
    category_series = _series(category_names, category_units, data.categories)
    comparison_labels = list(REGIONS if sales else TEAMS)
    comparison = _series(names, units, data.comparison)
    charts = [
        Visualization(
            kind="line",
            title="Monthly revenue" if sales else "SLA compliance trend",
            labels=list(MONTHS[-data.months :]),
            series=[monthly[0]],
            source_step_ids=sources,
        ),
        Visualization(
            kind="line",
            title="Order trend" if sales else "Resolution time trend",
            labels=list(MONTHS[-data.months :]),
            series=[monthly[1 if sales else 2]],
            source_step_ids=sources,
        ),
        Visualization(
            kind="bar",
            title="Category performance" if sales else "Recurring issue categories",
            labels=group_labels,
            series=[category_series[0]],
            source_step_ids=sources,
        ),
        Visualization(
            kind="bar",
            title="Regional revenue" if sales else "Team SLA compliance",
            labels=comparison_labels,
            series=[comparison[0]],
            source_step_ids=sources,
        ),
    ]
    tables = [
        Table(
            title="Monthly supporting data",
            dimension="Month",
            labels=list(MONTHS[-data.months :]),
            series=monthly,
            source_step_ids=sources,
        ),
        Table(
            title="Categories" if sales else "Issue categories",
            dimension="Category",
            labels=group_labels,
            series=category_series if sales else category_series[:3],
            source_step_ids=sources,
        ),
        Table(
            title="Regional performance" if sales else "Team comparison",
            dimension="Region" if sales else "Team",
            labels=comparison_labels,
            series=comparison,
            source_step_ids=sources,
        ),
    ]
    findings: list[Finding] = []
    if sales:
        ranked = sorted(range(4), key=lambda i: float(data.categories[i][0] or 0), reverse=True)
        findings.append(
            Finding(
                text=f"{CATEGORIES[ranked[0]]} has the highest revenue; "
                f"{CATEGORIES[ranked[-1]]} has the lowest in this period.",
                source_step_ids=sources,
            )
        )
        for i, row in enumerate(data.categories):
            if row[2] is not None and row[2] <= -15:
                findings.append(
                    Finding(
                        text=f"{CATEGORIES[i]} revenue declined {abs(row[2]):.1f}% "
                        "between the first and last month. "
                        "This is a comparison, not a causal explanation.",
                        source_step_ids=sources,
                    )
                )
        tables.append(
            Table(
                title="Product performance",
                dimension="Product",
                labels=[
                    f"{tier} {category}"
                    for category in CATEGORIES
                    for tier in ("Everyday", "Premium")
                ],
                series=_series(names, units, data.products),
                source_step_ids=sources,
            )
        )
    else:
        worst = min(range(3), key=lambda i: float(data.comparison[i][0] or 0))
        recurring = max(range(4), key=lambda i: float(data.categories[i][0] or 0))
        findings.extend(
            [
                Finding(
                    text=f"{TEAMS[worst]} has the lowest resolved-ticket SLA compliance "
                    f"at {data.comparison[worst][0]}%. Review workload and issue mix "
                    "before attributing a cause.",
                    source_step_ids=sources,
                ),
                Finding(
                    text=f"{ISSUES[recurring]} is the most frequent issue category. "
                    f"Open backlog is {data.totals[1]} tickets from the selected creation period "
                    "at the fixed snapshot date.",
                    source_step_ids=sources,
                ),
            ]
        )
        charts.append(
            Visualization(
                kind="line",
                title="Satisfaction trend",
                labels=list(MONTHS[-data.months :]),
                series=[monthly[3]],
                source_step_ids=sources,
            )
        )
    return dict(
        metrics=metrics,
        visualizations=charts,
        tables=tables,
        findings=findings,
        freshness=Freshness(dataset=data.dataset, period_start=f"{MONTHS[-data.months]}-01"),
    )


def result_digest(result: AnalyticsResult) -> str:
    # Stable JSON includes exact ordered values, sources, outcome and freshness.
    return hashlib.sha256(result.model_dump_json(exclude={"summary_digest"}).encode()).hexdigest()


def project_analytics(
    plan: WorkflowPlan, summary: RunSummary, checkpoints: list[Checkpoint]
) -> AnalyticsResult:
    outcome = summary.outcome.value
    base: dict[str, Any] = {"run_outcome": outcome}
    outcomes = {s.step_id: s.outcome for s in summary.steps}
    by_id = {s.step_id: s for s in checkpoints}
    items: dict[str, list[Any]] = {
        k: []
        for k in ("metrics", "visualizations", "tables", "findings", "freshness", "source_step_ids")
    }
    analytical = [s for s in plan.steps if s.tool in TOOLS]
    try:
        for step in analytical:
            if outcomes.get(step.id) != StepOutcome.SUCCESS:
                continue
            checkpoint = by_id.get(step.id)
            if checkpoint is None or checkpoint.tool != step.tool or not checkpoint.finished:
                raise ValueError("missing completed checkpoint")
            args = AnalysisArgs.model_validate(step.args)
            data = AnalysisOutput.model_validate(checkpoint.output)
            if data.dataset != TOOLS[step.tool] or data.months != args.months:
                raise ValueError("output identity mismatch")
            fragment = _fragment(data, step.id)
            for key in ("metrics", "visualizations", "tables", "findings"):
                items[key].extend(fragment[key])
            items["freshness"].append(fragment["freshness"])
            items["source_step_ids"].append(step.id)
        if items["source_step_ids"]:
            status = "READY" if outcome == "COMPLETED" else "PARTIAL"
        else:
            status = (
                "PENDING"
                if analytical and outcome in ("PENDING", "IN_PROGRESS", "WAITING_APPROVAL")
                else "EMPTY"
            )
        result = AnalyticsResult.model_validate({**base, **items, "status": status})
    except (ValidationError, ValueError, TypeError):
        # No partial chart survives malformed data or cardinality overflow.
        result = AnalyticsResult.model_validate({**base, "status": "INVALID"})
    return result.model_copy(update={"summary_digest": result_digest(result)})


def slack_summary(result: AnalyticsResult) -> str:
    """Exact, bounded message from validated successful analytical evidence only."""
    if result.status != "READY" or result.run_outcome != "COMPLETED":
        raise ValueError("a completed, valid analysis is required")
    lines = ["Synthetic pilot analysis", "Snapshot: 2026-09-01 (historical demonstration data)."]
    lines.extend(
        f"{m.label}: {m.value if m.value is not None else 'unavailable'} {m.unit} "
        f"[step {', '.join(m.source_step_ids)}]"
        for m in result.metrics
    )
    lines.extend(f"{f.text} [step {', '.join(f.source_step_ids)}]" for f in result.findings)
    message = "\n".join(lines)
    if len(message) > 4000:
        raise ValueError("summary exceeds reviewable Slack message size")
    return message
