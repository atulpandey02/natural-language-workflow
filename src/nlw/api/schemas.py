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


class ScheduleCreate(BaseModel):
    workflow_id: uuid.UUID
    timezone: str
    frequency: str  # hourly | daily | weekly
    minute: int
    hour: int | None = None
    day_of_week: int | None = None


class ScheduleUpdate(BaseModel):
    # Recurrence fields are optional; any provided ones are re-validated and
    # next_run_at is recomputed. `enabled` toggles the schedule.
    timezone: str | None = None
    frequency: str | None = None
    minute: int | None = None
    hour: int | None = None
    day_of_week: int | None = None
    enabled: bool | None = None


class ScheduleOut(BaseModel):
    id: uuid.UUID
    workflow_id: uuid.UUID
    workflow_version_id: uuid.UUID
    timezone: str
    frequency: str
    minute: int
    hour: int | None
    day_of_week: int | None
    enabled: bool
    next_run_at: str
    last_scheduled_for: str | None


# --- M10 read models (workflows / versions / runs) ---


class WorkflowOut(BaseModel):
    id: uuid.UUID
    name: str
    current_version_id: uuid.UUID | None
    created_at: str


class WorkflowVersionOut(BaseModel):
    id: uuid.UUID
    workflow_id: uuid.UUID
    version: int
    # The normalized, immutable plan (steps/tools/connectors/dependencies). This
    # is workflow definition content only — it never contains secrets.
    plan: dict[str, Any]


class WorkflowDetailOut(BaseModel):
    id: uuid.UUID
    name: str
    current_version_id: uuid.UUID | None
    created_at: str
    current_version: WorkflowVersionOut | None


class RunOut(BaseModel):
    id: uuid.UUID
    workflow_id: uuid.UUID
    workflow_version_id: uuid.UUID
    status: str
    trigger: str
    schedule_id: uuid.UUID | None
    scheduled_for: str | None
    error: str | None
    started_at: str | None
    finished_at: str | None
    created_at: str


class StepRunOut(BaseModel):
    step_id: str
    tool: str
    status: str
    attempt: int
    error: str | None
    started_at: str | None
    finished_at: str | None
    # Bounded, size-capped preview of the step output (tenant business data,
    # never secrets). Raw/unrestricted output is never returned (M10 D3).
    output_preview: dict[str, Any] | None
    output_truncated: bool


class ExternalActionOut(BaseModel):
    # Secret-free by construction: destination_summary is a host/channel only;
    # raw request/response bodies, auth headers, and secrets are never stored here.
    step_id: str
    tool: str
    destination_summary: str | None
    status: str
    attempts: int
    error_class: str | None
    http_status: int | None
    last_attempt_at: str | None
    next_attempt_at: str | None


class RunCreateOut(BaseModel):
    run_id: uuid.UUID
    status: str
    idempotent_hit: bool
