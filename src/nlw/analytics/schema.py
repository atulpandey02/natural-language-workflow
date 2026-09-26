"""analytics-1: fixed, bounded presentation data, never executable config."""

import re
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    model_validator,
)


def safe_text(value: str) -> str:
    if re.search(
        r"[<>\x00-\x1f]|https?://|www\.|javascript:|[0-9a-f]{8}-[0-9a-f-]{27,}", value, re.I
    ):
        raise ValueError("unsafe analytical text")
    return value


Label = Annotated[str, Field(strict=True, min_length=1, max_length=80), AfterValidator(safe_text)]
Text = Annotated[str, Field(strict=True, min_length=1, max_length=240), AfterValidator(safe_text)]
Number = Annotated[StrictInt | StrictFloat, Field(allow_inf_nan=False, ge=-1e12, le=1e12)]
Source = Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9_-]{1,64}$")]
Sources = Annotated[list[Source], Field(min_length=1, max_length=8)]
Unit = Literal["USD", "count", "percent", "hours", "score"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Metric(StrictModel):
    label: Label
    value: Number | None
    unit: Unit
    source_step_ids: Sources


class Series(StrictModel):
    label: Label
    unit: Unit
    values: list[Number | None] = Field(min_length=1, max_length=24)


class Visualization(StrictModel):
    kind: Literal["line", "bar"]
    title: Label
    labels: list[Label] = Field(min_length=1, max_length=24)
    series: list[Series] = Field(min_length=1, max_length=3)
    source_step_ids: Sources

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if any(len(s.values) != len(self.labels) for s in self.series):
            raise ValueError("series length mismatch")
        if len(set(self.labels)) != len(self.labels):
            raise ValueError("duplicate categories")
        if len({s.unit for s in self.series}) != 1:
            raise ValueError("mixed units on one axis")
        return self


class Table(StrictModel):
    title: Label
    dimension: Label
    labels: list[Label] = Field(min_length=1, max_length=24)
    series: list[Series] = Field(min_length=1, max_length=4)
    source_step_ids: Sources

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if any(len(s.values) != len(self.labels) for s in self.series):
            raise ValueError("table length mismatch")
        return self


class Finding(StrictModel):
    text: Text
    source_step_ids: Sources


class Freshness(StrictModel):
    dataset: Literal["sales-v1", "support-v1"]
    as_of: Literal["2026-09-01"] = "2026-09-01"
    period_start: str = Field(pattern=r"^2026-0[1-8]-01$")
    period_end: Literal["2026-08-31"] = "2026-08-31"
    synthetic: Literal[True] = True


class AnalyticsResult(StrictModel):
    contract_version: Literal["analytics-1"] = "analytics-1"
    title: Label = "Analysis results"
    status: Literal["READY", "PARTIAL", "PENDING", "EMPTY", "INVALID"]
    run_outcome: Literal[
        "COMPLETED", "FAILED", "FAILED_WITH_UNKNOWN", "WAITING_APPROVAL", "IN_PROGRESS", "PENDING"
    ]
    metrics: list[Metric] = Field(default_factory=list, max_length=8)
    visualizations: list[Visualization] = Field(default_factory=list, max_length=6)
    tables: list[Table] = Field(default_factory=list, max_length=6)
    findings: list[Finding] = Field(default_factory=list, max_length=8)
    freshness: list[Freshness] = Field(default_factory=list, max_length=2)
    source_step_ids: list[Source] = Field(default_factory=list, max_length=8)
    summary_digest: str = Field(default="", pattern=r"^([0-9a-f]{64})?$")

    @model_validator(mode="after")
    def grounded(self) -> Self:
        sources = set(self.source_step_ids)
        if len(sources) != len(self.source_step_ids):
            raise ValueError("duplicate sources")
        items: list[Metric | Visualization | Table | Finding] = [
            *self.metrics,
            *self.visualizations,
            *self.tables,
            *self.findings,
        ]
        if any(not set(i.source_step_ids) <= sources for i in items):
            raise ValueError("ungrounded result")
        if self.status in ("INVALID", "PENDING", "EMPTY") and (items or sources):
            raise ValueError("unavailable result cannot contain conclusions")
        if self.status == "READY" and (self.run_outcome != "COMPLETED" or not sources):
            raise ValueError("ready requires completed source work")
        return self
