"""Request/response models for the API."""

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str


class WorkspaceCreate(BaseModel):
    name: str


class WorkspaceOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    role: str


class TenantContextOut(BaseModel):
    tenant_id: uuid.UUID
    role: str


class ConnectorCreate(BaseModel):
    type: str
    name: str
    config: dict[str, Any] = {}
    secret_ref: str | None = None


class ConnectorOut(BaseModel):
    # Note: secret_ref is intentionally NOT exposed; only has_secret.
    id: uuid.UUID
    type: str
    name: str
    config: dict[str, Any]
    status: str
    has_secret: bool


class ToolOut(BaseModel):
    name: str
    description: str
    category: str
    connector_type: str | None
    read_only: bool
    requires_approval: bool
    timeout_seconds: int
