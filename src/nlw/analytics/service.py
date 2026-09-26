"""Authorized read composition and immutable handoff validation. No execution."""

import hashlib
import uuid
from typing import Literal

from fastapi import HTTPException
from pydantic import Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.analytics.results import Checkpoint, project_analytics, slack_summary
from nlw.analytics.schema import AnalyticsResult, StrictModel
from nlw.api.routers.runs import get_run_summary
from nlw.connectors.slack import SlackConnectorConfig
from nlw.db.models import Connector, PlanProposal, WorkflowVersion
from nlw.db.repositories import RunRepository
from nlw.domain.workflow import WorkflowPlan
from nlw.feasibility.connector_binding import CurrentConnector, build_binding, verify_binding
from nlw.registry.registry import ToolExecutionError
from nlw.tenancy.context import TenantContext


class SlackRequest(StrictModel):
    connector_id: uuid.UUID
    channel: str | None = Field(
        default=None, min_length=3, max_length=80, pattern=r"^[CGD][A-Z0-9]+$"
    )


class SourceBinding(StrictModel):
    source_run_id: uuid.UUID
    contract_version: Literal["analytics-1"]
    result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    message_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    connector_id: uuid.UUID
    connector_type: Literal["slack"] = "slack"
    config_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    channel: str = Field(min_length=3, max_length=80, pattern=r"^[CGD][A-Z0-9]+$")


def digest_message(message: str) -> str:
    return hashlib.sha256(message.encode()).hexdigest()


def stale_source() -> HTTPException:
    return HTTPException(
        409,
        detail={
            "code": "STALE_ANALYTICS_SOURCE",
            "message": "The analysis or destination changed or cannot be verified. "
            "Create a new Slack proposal.",
        },
    )


async def load_analytics(
    run_id: uuid.UUID, ctx: TenantContext, session: AsyncSession
) -> AnalyticsResult:
    repo = RunRepository(session)
    run = await repo.get(run_id, ctx.tenant_id)
    if run is None:
        raise HTTPException(404, "run not found")
    version = await session.get(WorkflowVersion, run.workflow_version_id)
    if version is None:
        raise HTTPException(404, "run version not found")
    summary = await get_run_summary(run_id, ctx, session)
    steps = await repo.steps(run_id, ctx.tenant_id)
    return project_analytics(
        WorkflowPlan.model_validate(version.plan),
        summary,
        [Checkpoint(s.step_id, s.tool, s.output, s.finished_at is not None) for s in steps],
    )


async def load_slack(
    connector_id: uuid.UUID, ctx: TenantContext, session: AsyncSession
) -> Connector:
    connector = (
        await session.execute(
            select(Connector).where(
                Connector.id == connector_id,
                Connector.tenant_id == ctx.tenant_id,
                Connector.type == "slack",
            )
        )
    ).scalar_one_or_none()
    if connector is None:
        raise HTTPException(404, "connector not found")
    if connector.status == "disabled":
        raise stale_source()
    return connector


async def validate_handoff(
    proposal: PlanProposal, ctx: TenantContext, session: AsyncSession
) -> None:
    """Called before materialization, including idempotent re-reads. Fail closed."""
    try:
        binding = SourceBinding.model_validate(proposal.analytics_source)
        result = await load_analytics(binding.source_run_id, ctx, session)
        message = slack_summary(result)
        if (
            result.contract_version != binding.contract_version
            or result.summary_digest != binding.result_digest
            or digest_message(message) != binding.message_digest
        ):
            raise stale_source()
        connector = await load_slack(binding.connector_id, ctx, session)
        expected = {
            "connector_id": str(binding.connector_id),
            "connector_type": "slack",
            "config_fingerprint": binding.config_fingerprint,
        }
        current = CurrentConnector(
            str(connector.id), connector.type, connector.config, connector.status
        )
        if verify_binding(expected, current) is not None:
            raise stale_source()
        config = SlackConnectorConfig.model_validate(connector.config)
        config.resolve_channel(binding.channel)
        expected_plan = {
            "steps": [
                {
                    "id": "send_summary",
                    "tool": "slack.send_message",
                    "args": {"text": message, "channel": binding.channel},
                    "depends_on": [],
                    "connector": connector.name,
                }
            ]
        }
        if proposal.proposed_plan != expected_plan or proposal.normalized_plan != expected_plan:
            raise stale_source()
    except (ValidationError, ValueError, ToolExecutionError, HTTPException) as exc:
        # Preserve non-disclosing resource errors on the ordinary read endpoints;
        # this binding recheck reveals only that a fresh proposal is required.
        raise stale_source() from exc


def source_binding(
    run_id: uuid.UUID, result: AnalyticsResult, message: str, connector: Connector, channel: str
) -> SourceBinding:
    binding = build_binding(str(connector.id), connector.type, connector.config)
    return SourceBinding(
        source_run_id=run_id,
        contract_version=result.contract_version,
        result_digest=result.summary_digest,
        message_digest=digest_message(message),
        connector_id=connector.id,
        config_fingerprint=binding["config_fingerprint"],
        channel=channel,
    )
