"""Bounded aggregation of synthetic records. Internal output is numeric only."""

from collections.abc import Sequence
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from nlw.analytics.datasets import (
    CATEGORIES,
    ISSUES,
    MONTHS,
    REGIONS,
    TEAMS,
    Sale,
    Ticket,
    load_sales_v1,
    load_support_v1,
)
from nlw.analytics.schema import Number, StrictModel

Row = Annotated[list[Number | None], Field(min_length=4, max_length=4)]


class AnalysisArgs(StrictModel):
    # Explicit version means a future seed never changes an old workflow.
    dataset_version: Literal["v1"] = "v1"
    months: int = Field(default=6, strict=True, ge=1, le=8)


class AnalysisOutput(StrictModel):
    version: Literal["pilot-numeric-1"] = "pilot-numeric-1"
    dataset: Literal["sales-v1", "support-v1"]
    months: int = Field(strict=True, ge=1, le=8)
    totals: Row
    trend: list[Row] = Field(min_length=1, max_length=8)
    categories: list[Row] = Field(min_length=4, max_length=4)
    comparison: list[Row] = Field(min_length=3, max_length=4)
    products: list[Row] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def shape(self) -> Self:
        if len(self.trend) != self.months:
            raise ValueError("incomplete trend")
        if len(self.comparison) != (4 if self.dataset == "sales-v1" else 3):
            raise ValueError("incomplete comparison")
        if len(self.products) != (8 if self.dataset == "sales-v1" else 0):
            raise ValueError("incomplete products")
        return self


def _average(values: Sequence[float | int]) -> float | None:
    return round(sum(values) / len(values), 2) if values else None


def _sales_row(rows: Sequence[Sale]) -> list[float | int | None]:
    revenue = sum(r.revenue_cents for r in rows) / 100
    return [
        round(revenue, 2),
        len(rows),
        round(revenue / len(rows), 2) if rows else None,
        sum(r.units for r in rows),
    ]


def analyze_sales(args: AnalysisArgs) -> AnalysisOutput:
    months = MONTHS[-args.months :]
    rows = [r for r in load_sales_v1() if r.order_date.isoformat()[:7] in months]
    categories: list[list[float | int | None]] = []
    for category in CATEGORIES:
        group = [r for r in rows if r.category == category]
        first = sum(
            r.revenue_cents for r in group if r.order_date.isoformat().startswith(months[0])
        )
        last = sum(
            r.revenue_cents for r in group if r.order_date.isoformat().startswith(months[-1])
        )
        change = round((last / first - 1) * 100, 2) if first and args.months > 1 else None
        categories.append(
            [
                sum(r.revenue_cents for r in group) / 100,
                len(group),
                change,
                sum(r.units for r in group),
            ]
        )
    return AnalysisOutput(
        dataset="sales-v1",
        months=args.months,
        totals=_sales_row(rows),
        trend=[
            _sales_row([r for r in rows if r.order_date.isoformat().startswith(m)]) for m in months
        ],
        categories=categories,
        comparison=[_sales_row([r for r in rows if r.region == region]) for region in REGIONS],
        products=[
            _sales_row([r for r in rows if r.product == f"{tier} {category}"])
            for category in CATEGORIES
            for tier in ("Everyday", "Premium")
        ],
    )


def _support_row(rows: Sequence[Ticket]) -> list[float | int | None]:
    resolved = [r for r in rows if r.resolution_hours is not None]
    compliance = (
        round(
            100
            * sum(
                r.resolution_hours <= r.sla_target_hours
                for r in resolved
                if r.resolution_hours is not None
            )
            / len(resolved),
            2,
        )
        if resolved
        else None
    )
    return [
        compliance,
        sum(r.status == "Open" for r in rows),
        _average([r.resolution_hours for r in resolved if r.resolution_hours is not None]),
        _average([r.csat for r in rows if r.csat is not None]),
    ]


def analyze_support(args: AnalysisArgs) -> AnalysisOutput:
    months = MONTHS[-args.months :]
    rows = [r for r in load_support_v1() if r.created_at.isoformat()[:7] in months]
    return AnalysisOutput(
        dataset="support-v1",
        months=args.months,
        totals=_support_row(rows),
        trend=[
            _support_row([r for r in rows if r.created_at.isoformat().startswith(m)])
            for m in months
        ],
        categories=[
            [len(group), sum(r.reopened for r in group), _support_row(group)[2], None]
            for category in ISSUES
            if (group := [r for r in rows if r.issue_category == category])
        ],
        comparison=[_support_row([r for r in rows if r.team == team]) for team in TEAMS],
    )
