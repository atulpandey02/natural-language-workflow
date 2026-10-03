"""Request/response models for the API."""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


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
    # The request is bounded (llm_max_prompt_chars) and then durably bound to the
    # proposal it produces (M12B-A). It is never logged, metered, or listed.
    prompt: str


class PlanProposalOut(BaseModel):
    # LIST/summary view: deliberately WITHOUT the request text (never listed).
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


class PlanProposalDetailOut(PlanProposalOut):
    """Single-proposal DETAIL view: additionally carries the original request and
    its provenance. Returned only by the create + get-one endpoints (never lists),
    and only to an authorized workspace member (tenant RLS)."""

    request_text: str | None = None
    request_sha256: str | None = None
    planner_contract_version: str | None = None
    analytics_source: dict[str, Any] | None = None


class WorkflowProvenanceOut(BaseModel):
    """What caused a workflow version to exist: the originating request + planner
    identity + the feasibility decision that allowed it. Read-only, tenant-scoped."""

    workflow_version_id: uuid.UUID
    request_text: str | None
    request_sha256: str | None
    provider: str
    model: str
    planner_contract_version: str | None
    status: str
    created_at: str
    analytics_source: dict[str, Any] | None = None


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
    # P3A: the immutable requester (opaque user id) and whether the CURRENT viewer
    # is eligible to decide (an admin/owner who is not the requester). The frontend
    # uses eligibility to disable self-approval; the backend remains authoritative.
    requested_by_user_id: uuid.UUID | None = None
    viewer_can_decide: bool = False
    # The effective, non-secret destination the side effect will reach (webhook
    # host / Slack channel), derived from the APPROVED connector. None if it
    # cannot be safely resolved.
    destination: str | None = None
    # True when the payload exceeds the safe review size and therefore is NOT
    # shown; the action must NOT be approved in that state (P1C).
    payload_review_blocked: bool = False
    # Bounded, secret-free preview derived from the immutable plan step so a human
    # can approve knowingly. Contains only workflow/user content, never secrets.
    # ``args`` is None when payload_review_blocked is True.
    preview: dict[str, Any]


class ApprovalDecisionOut(BaseModel):
    id: uuid.UUID
    status: str
    resumed: bool


# --- Membership & invitations (M11.5 P3A) ---


class MemberOut(BaseModel):
    user_id: uuid.UUID
    role: str
    # When the membership row was created: a non-sensitive way for the UI to tell
    # co-members apart (their emails are not readable under users RLS).
    joined_at: str | None = None


class RoleUpdate(BaseModel):
    role: str  # 'owner' | 'admin' | 'member' (validated server-side)


class InvitationCreate(BaseModel):
    email: str
    role: str  # 'admin' | 'member'


class InvitationOut(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    status: str
    expires_at: str | None
    created_at: str | None


class InvitationCreatedOut(InvitationOut):
    # The raw token is returned ONCE, only at creation, for manual sharing. It is
    # never stored, logged, or returned again.
    token: str


class InvitationAccept(BaseModel):
    token: str


class InvitationAcceptedOut(BaseModel):
    workspace_id: uuid.UUID
    role: str


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
    # Fail-closed authorization (M12B, Part 4): a stable reason when occurrence
    # creation is blocked (creator lost membership/role); null when authorized.
    blocked_reason: str | None = None
    blocked_at: str | None = None


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


# --- Datasets (Phase 2A, ADR-029): metadata only -----------------------------
# Raw input bounds are generous upper limits; the service applies the exact
# normalized contract (nlw.datasets.lifecycle) and refuses with a stable code.
# extra="forbid": tenant, actor, status, version numbers and the active-version
# pointer are always derived server-side and can never be supplied.


class DatasetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=1000)


class DatasetOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    status: Literal["ACTIVE", "DELETING"]
    active_version_id: uuid.UUID | None
    version_count: int
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
    deletion_requested_at: datetime | None


class DatasetVersionOut(BaseModel):
    """No storage key, URL or path is ever returned."""

    id: uuid.UUID
    dataset_id: uuid.UUID
    version_number: int
    status: Literal[
        "QUARANTINED", "PROFILING", "PROFILED", "ACTIVE", "SUPERSEDED", "REJECTED", "DELETING"
    ]
    original_filename: str
    media_type: str
    declared_size_bytes: int
    content_sha256: str | None
    rejection_code: str | None
    created_by: uuid.UUID
    created_at: datetime
    activated_at: datetime | None
    superseded_at: datetime | None
    rejected_at: datetime | None
    deletion_requested_at: datetime | None
