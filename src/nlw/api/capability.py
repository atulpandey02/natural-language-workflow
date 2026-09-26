"""Shared tenant capability-view construction (M12B-A addendum, Part 2).

One place that projects a tenant's connectors to the secret-free capability view
+ registry tool-name set, used by the planner endpoint, materialization and the
run-creation STALE_PLAN gate so they reason over an identical, authoritative
surface — with ONE explicit difference, the demo-tool visibility policy:

- ``purpose="planning"`` (POST /plans, materialize, GET /tools): demo tools
  (``ToolSpec.demo``) are offered only when the operator setting
  ``DEMO_TOOLS_ENABLED`` is explicitly true. Unset = hidden (fail closed). A
  tenant request can never widen this.
- ``purpose="execution_compat"`` (manual run of an ALREADY-materialized version):
  registry compatibility — every registered tool, demo included — so historical
  workflow versions that reference demo tools remain executable where
  operationally required instead of becoming STALE merely because new planning
  no longer sees the tool. The worker/scheduler never consult the view.
"""

from __future__ import annotations

import uuid
from typing import Literal

from sqlalchemy.ext.asyncio import AsyncSession

from nlw.connectors.postgres import PostgresConnectorConfig
from nlw.core.config import Settings
from nlw.db.models import Connector
from nlw.db.repositories import ConnectorRepository
from nlw.planner.capabilities import CapabilityView, SafeConnector, build_capability_view
from nlw.registry.registry import REGISTRY

ViewPurpose = Literal["planning", "execution_compat"]


def safe_connectors(connectors: list[Connector]) -> list[SafeConnector]:
    """Project connector rows to a secret-free view for the planner + feasibility."""
    result: list[SafeConnector] = []
    for c in connectors:
        if c.type == "postgres":
            cfg = PostgresConnectorConfig.model_validate(c.config)
            hint = cfg.schema_hint.model_dump(by_alias=True) if cfg.schema_hint else None
            result.append(
                SafeConnector(
                    name=c.name,
                    type=c.type,
                    status=c.status,
                    allowed_schemas=cfg.allowed_schemas,
                    allowed_tables=cfg.allowed_tables,
                    schema_hint=hint,
                )
            )
        else:
            result.append(SafeConnector(name=c.name, type=c.type, status=c.status))
    return result


def demo_tools_included(settings: Settings, purpose: ViewPurpose) -> bool:
    """The demo-tool visibility decision for a view purpose (pure; testable)."""
    if purpose == "execution_compat":
        return True
    return settings.demo_tools_visible


async def build_tenant_view(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    settings: Settings,
    *,
    purpose: ViewPurpose,
) -> tuple[CapabilityView, set[str]]:
    """The current capability view + all registry tool names for a tenant."""
    connectors = await ConnectorRepository(session).list_for_tenant(tenant_id)
    view = build_capability_view(
        REGISTRY.all(),
        safe_connectors(connectors),
        include_demo=demo_tools_included(settings, purpose),
    )
    return view, {spec.name for spec in REGISTRY.all()}
