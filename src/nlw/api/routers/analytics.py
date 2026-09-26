"""Synthetic dataset catalog, grounded analytics, and explicit Slack proposals."""

import time
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.analytics.datasets import load_sales_v1, load_support_v1
from nlw.analytics.results import slack_summary
from nlw.analytics.schema import AnalyticsResult
from nlw.analytics.service import SlackRequest, load_analytics, load_slack, source_binding
from nlw.api.capability import build_tenant_view
from nlw.api.deps import get_app_settings, get_session, get_tenant_context, rate_limit
from nlw.api.schemas import PlanProposalDetailOut
from nlw.connectors.slack import SlackConnectorConfig
from nlw.core.config import Settings
from nlw.db.repositories import PlanProposalRepository
from nlw.domain.workflow import WorkflowPlan
from nlw.feasibility.engine import check_plan
from nlw.feasibility.limits import DEFAULT_LIMITS
from nlw.observability import metrics
from nlw.planner.provenance import compute_request_digest
from nlw.registry.registry import ToolExecutionError
from nlw.tenancy.context import TenantContext

router = APIRouter()


@router.get("/analytics/datasets")
async def datasets(
    ctx: TenantContext = Depends(get_tenant_context), settings: Settings = Depends(get_app_settings)
) -> list[dict[str, object]]:
    if not settings.demo_tools_visible:
        return []
    return [
        {
            "id": "sales-v1",
            "name": "Sales operations",
            "grain": "One synthetic order with one product per row",
            "rows": len(load_sales_v1()),
            "as_of": "2026-09-01",
            "synthetic": True,
            "tool": "pilot.sales_analysis",
            "prompt": (
                "Analyze the last six months of sales using sales-v1. Show revenue "
                "and order trends, best and worst categories, regional performance "
                "and meaningful decline."
            ),
        },
        {
            "id": "support-v1",
            "name": "Support operations",
            "grain": "One synthetic support ticket per row",
            "rows": len(load_support_v1()),
            "as_of": "2026-09-01",
            "synthetic": True,
            "tool": "pilot.support_analysis",
            "prompt": (
                "Analyze support-v1 performance for the last six months. Show SLA "
                "compliance, backlog, recurring issue categories, resolution and "
                "satisfaction trends, and teams that need attention."
            ),
        },
    ]


@router.get("/runs/{run_id}/analytics", response_model=AnalyticsResult)
async def analytics_result(
    run_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> AnalyticsResult:
    started = time.perf_counter()
    result = await load_analytics(run_id, ctx, session)
    metrics.record_analytics_result(
        result.status, len(result.visualizations), time.perf_counter() - started
    )
    return result


@router.post(
    "/runs/{run_id}/slack-proposal",
    response_model=PlanProposalDetailOut,
    status_code=201,
    dependencies=[Depends(rate_limit("plans", "plans"))],
)
async def slack_proposal(
    run_id: uuid.UUID,
    body: SlackRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_app_settings),
) -> PlanProposalDetailOut:
    result = await load_analytics(run_id, ctx, session)
    try:
        message = slack_summary(result)
    except ValueError as exc:
        raise HTTPException(409, "A completed, validated analysis is required.") from exc
    connector = await load_slack(body.connector_id, ctx, session)
    try:
        config = SlackConnectorConfig.model_validate(connector.config)
        channel = config.resolve_channel(body.channel)
    except (ValueError, ToolExecutionError) as exc:
        raise HTTPException(422, "Select a channel allowed by this Slack connector.") from exc
    plan = WorkflowPlan.model_validate(
        {
            "steps": [
                {
                    "id": "send_summary",
                    "tool": "slack.send_message",
                    "args": {"text": message, "channel": channel},
                    "connector": connector.name,
                }
            ]
        }
    )
    view, names = await build_tenant_view(session, ctx.tenant_id, settings, purpose="planning")
    report = check_plan(plan, view, DEFAULT_LIMITS, names)
    binding = source_binding(run_id, result, message, connector, channel)
    request = "Send the reviewed grounded synthetic analysis summary to the selected Slack channel."
    proposal = await PlanProposalRepository(session).create(
        tenant_id=ctx.tenant_id,
        created_by=ctx.user_id,
        prompt_len=len(request),
        provider="deterministic",
        model="analytics-handoff-1",
        workflow_name="Share analysis summary to Slack",
        status=report.status.value,
        proposed_plan=plan.model_dump(),
        normalized_plan=report.normalized_plan.model_dump() if report.normalized_plan else None,
        feasibility=report.model_dump(mode="json", exclude={"normalized_plan"}),
        clarification_questions=report.clarification_questions,
        request_text=request,
        request_sha256=compute_request_digest(request),
        planner_contract_version="analytics-handoff-1",
        analytics_source=binding.model_dump(mode="json"),
    )
    return PlanProposalDetailOut.model_validate(proposal)
