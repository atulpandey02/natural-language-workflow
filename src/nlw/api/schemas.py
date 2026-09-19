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


class PlanRequest(BaseModel):
    # The raw prompt is used to plan and then discarded; it is never persisted.
    prompt: str


class PlanProposalOut(BaseModel):
    # protected_namespaces=() so the ``model`` field name is allowed.
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: uuid.UUID
    status: str
    workflow_name: str
    provider: str
    model: str
    proposed_plan: dict[str, Any] | None
    normalized_plan: dict[str, Any] | None
    feasibility: dict[str, Any]
    clarification_questions: list[str] | None
    workflow_version_id: uuid.UUID | None


class MaterializeOut(BaseModel):
    workflow_id: uuid.UUID
    workflow_version_id: uuid.UUID
    idempotent_hit: bool


class ApprovalOut(BaseModel):
    id: uuid.UUID
    run_id: uuid.UUID
    step_id: str
    tool: str
    connector_name: str
    status: str
    requested_at: str | None
    decided_at: str | None
    # Bounded, secret-free preview derived from the immutable plan step so a human
    # can approve knowingly. Contains only workflow/user content, never secrets.
    preview: dict[str, Any]


class ApprovalDecisionOut(BaseModel):
    id: uuid.UUID
    status: str
    resumed: bool
