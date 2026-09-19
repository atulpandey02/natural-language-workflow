"""Connector and tool endpoints.

- ``POST /connectors``  create a tenant connector (secret_ref only; never a secret)
- ``GET  /connectors``  list the tenant's connectors (no secret, no secret_ref)
- ``GET  /tools``       tools available to the tenant (registry + owned connectors)

The API never resolves secrets and has no ``NLW_SECRET_*`` environment.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

import nlw.tools.builtin  # noqa: F401  (populates registries)
from nlw.api.deps import get_session, get_tenant_context
from nlw.api.schemas import ConnectorCreate, ConnectorOut, ToolOut
from nlw.connectors.base import (
    ConnectorConfigError,
    UnknownConnectorTypeError,
    get_connector_type,
    validate_connector_config,
)
from nlw.db.repositories import ConnectorRepository
from nlw.registry.registry import REGISTRY
from nlw.secrets.store import InvalidSecretRefError, validate_secret_ref
from nlw.tenancy.context import TenantContext

router = APIRouter()


def _to_out(connector: object) -> ConnectorOut:
    c = connector
    return ConnectorOut(
        id=c.id,  # type: ignore[attr-defined]
        type=c.type,  # type: ignore[attr-defined]
        name=c.name,  # type: ignore[attr-defined]
        config=c.config,  # type: ignore[attr-defined]
        status=c.status,  # type: ignore[attr-defined]
        has_secret=c.secret_ref is not None,  # type: ignore[attr-defined]
    )


@router.post("/connectors", response_model=ConnectorOut, status_code=status.HTTP_201_CREATED)
async def create_connector(
    body: ConnectorCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> ConnectorOut:
    try:
        connector_type = get_connector_type(body.type)
        config = validate_connector_config(body.type, body.config)
    except (UnknownConnectorTypeError, ConnectorConfigError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    if body.secret_ref is not None:
        try:
            validate_secret_ref(body.secret_ref)
        except InvalidSecretRefError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if connector_type.secret_required and not body.secret_ref:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"connector type '{body.type}' requires a secret_ref",
        )

    connector = await ConnectorRepository(session).create(
        ctx.tenant_id, body.type, body.name, config, body.secret_ref
    )
    return _to_out(connector)


@router.get("/connectors", response_model=list[ConnectorOut])
async def list_connectors(
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> list[ConnectorOut]:
    connectors = await ConnectorRepository(session).list_for_tenant(ctx.tenant_id)
    return [_to_out(c) for c in connectors]


@router.get("/tools", response_model=list[ToolOut])
async def list_tools(
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> list[ToolOut]:
    owned = await ConnectorRepository(session).owned_types(ctx.tenant_id)
    return [
        ToolOut(
            name=spec.name,
            description=spec.description,
            category=spec.category.value,
            connector_type=spec.connector_type,
            read_only=spec.read_only,
            requires_approval=spec.requires_approval,
            timeout_seconds=spec.timeout_seconds,
        )
        for spec in REGISTRY.available_for(owned)
    ]
