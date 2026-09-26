"""Pilot read-only tools. Ordinary registry, runtime validation and checkpoints."""

from typing import Any

from pydantic import BaseModel

from nlw.analytics.analysis import AnalysisArgs, analyze_sales, analyze_support
from nlw.connectors.base import ConnectorContext
from nlw.registry.registry import REGISTRY, ToolCategory, ToolSpec


def _sales(args: BaseModel, ctx: ConnectorContext | None) -> dict[str, Any]:
    return analyze_sales(AnalysisArgs.model_validate(args.model_dump())).model_dump(mode="json")


def _support(args: BaseModel, ctx: ConnectorContext | None) -> dict[str, Any]:
    return analyze_support(AnalysisArgs.model_validate(args.model_dump())).model_dump(mode="json")


for name, description, execute in (
    (
        "pilot.sales_analysis",
        (
            "Analyze sales-v1 synthetic orders: revenue, orders, AOV, monthly "
            "trends, category decline, regions and products. Fixed as-of "
            "2026-09-01; last six months means March-August 2026. No real "
            "customer data."
        ),
        _sales,
    ),
    (
        "pilot.support_analysis",
        (
            "Analyze support-v1 synthetic tickets: resolved-ticket SLA "
            "compliance, open backlog as of 2026-09-01, issue categories, "
            "resolution and satisfaction trends, teams. Last six months means "
            "March-August 2026. No real customer data."
        ),
        _support,
    ),
):
    REGISTRY.register(
        ToolSpec(
            name=name,
            description=description,
            category=ToolCategory.DATA,
            connector_type=None,
            input_model=AnalysisArgs,
            read_only=True,
            requires_approval=False,
            timeout_seconds=5,
            execute=execute,
            demo=True,
        )
    )
