"""Shared tenant capability-view construction (M12B-A addendum, Part 2).

One place that projects a tenant's connectors to the secret-free capability view
+ registry tool-name set, used by both the planner endpoint and the run-creation
STALE_PLAN gate so they reason over an identical, authoritative surface.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from nlw.connectors.postgres import PostgresConnectorConfig
from nlw.db.models import Connector
from nlw.db.repositories import ConnectorRepository
from nlw.planner.capabilities import CapabilityView, SafeConnector, build_capability_view
from nlw.registry.registry import REGISTRY


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


async def build_tenant_view(
    session: AsyncSession, tenant_id: uuid.UUID
) -> tuple[CapabilityView, set[str]]:
    """The current capability view + all registry tool names for a tenant."""
    connectors = await ConnectorRepository(session).list_for_tenant(tenant_id)
    view = build_capability_view(REGISTRY.all(), safe_connectors(connectors))
    return view, {spec.name for spec in REGISTRY.all()}
