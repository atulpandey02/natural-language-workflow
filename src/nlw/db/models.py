"""ORM models for identity and tenancy (M2a).

- ``User``      global identity (V1: email-authenticated users only).
- ``Workspace`` a tenant; its ``id`` is the ``tenant_id`` used elsewhere.
- ``Membership`` links a user to a workspace with a role.

Row-Level Security policies and the restricted runtime role are added in M2b.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from nlw.db.base import Base


def _now() -> datetime:
    return datetime.now(UTC)


class TimestampMixin:
    # Python-side defaults so ORM inserts carry the values and do NOT emit
    # RETURNING. Under RLS, INSERT ... RETURNING would re-check the row against
    # the SELECT policy, which a just-created (not-yet-member-visible) workspace
    # would fail. server_default remains as a fallback for non-ORM inserts.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_now,
        server_default=func.now(),
        onupdate=_now,
        nullable=False,
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # Supabase subject (sub). UNIQUE makes first-sight provisioning race-safe and
    # already creates the lookup index (no separate index needed).
    auth_provider_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False)


class Workspace(TimestampMixin, Base):
    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String, nullable=False)
    slug: Mapped[str] = mapped_column(String, unique=True, nullable=False)


class Membership(TimestampMixin, Base):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "workspace_id", name="uq_membership_user_workspace"),
        CheckConstraint("role in ('owner','admin','member')", name="ck_membership_role"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # user_id needs no standalone index: the UNIQUE(user_id, workspace_id)
    # composite index already serves user_id-prefix lookups.
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # workspace_id is not the leading column of the composite, so it keeps its own
    # index (workspace-scoped queries + FK cascade on workspace delete).
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String, nullable=False)


# --- Durable workflow execution (M3) ---
# Every table carries tenant_id for RLS. workflow_versions is immutable.


class Workflow(TimestampMixin, Base):
    __tablename__ = "workflows"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)


class WorkflowVersion(TimestampMixin, Base):
    __tablename__ = "workflow_versions"
    __table_args__ = (
        UniqueConstraint("workflow_id", "version", name="uq_version_workflow_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    workflow_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    plan: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)


class WorkflowRun(TimestampMixin, Base):
    __tablename__ = "workflow_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_run_tenant_idempotency"),
        # Exactly-once per schedule occurrence. NULLs are distinct, so manual runs
        # (schedule_id NULL) never collide (M8).
        UniqueConstraint("schedule_id", "scheduled_for", name="uq_run_schedule_occurrence"),
        CheckConstraint(
            "status in ('PENDING','RUNNING','WAITING_APPROVAL','COMPLETED','FAILED')",
            name="ck_run_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    workflow_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workflow_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("workflow_versions.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String, nullable=False, default="PENDING")
    trigger: Mapped[str] = mapped_column(String, nullable=False, default="manual")
    idempotency_key: Mapped[str | None] = mapped_column(String, nullable=True)
    # M8: scheduled runs pin the schedule + occurrence (exactly-once per occurrence).
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class StepRun(TimestampMixin, Base):
    __tablename__ = "step_runs"
    __table_args__ = (
        UniqueConstraint("run_id", "step_id", name="uq_step_run_run_step"),
        CheckConstraint(
            "status in ('PENDING','RUNNING','WAITING_APPROVAL','SUCCESS','FAILED')",
            name="ck_step_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("workflow_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_id: Mapped[str] = mapped_column(String, nullable=False)
    tool: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="PENDING")
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    input: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    output: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# --- Connectors (M4) ---
# Tenant-owned integration instances. config is NON-secret; secret_ref is a
# pointer into the SecretStore (never a secret value).


class Connector(TimestampMixin, Base):
    __tablename__ = "connectors"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_connector_tenant_name"),
        CheckConstraint(
            "status in ('unchecked','active','error','disabled')", name="ck_connector_status"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    type: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    secret_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="unchecked")


# --- Approvals + external actions (M7) ---
# An action step with requires_approval=True parks the run at WAITING_APPROVAL and
# creates one Approval. External side effects are audited (secret-free) in
# ExternalAction, which also carries the durable idempotency key + lease.


class Approval(TimestampMixin, Base):
    __tablename__ = "approvals"
    __table_args__ = (
        UniqueConstraint("run_id", "step_id", name="uq_approval_run_step"),
        CheckConstraint("status in ('pending','approved','rejected')", name="ck_approval_status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    step_id: Mapped[str] = mapped_column(String, nullable=False)
    connector_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    connector_name: Mapped[str] = mapped_column(String, nullable=False)
    tool: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)


class ExternalAction(TimestampMixin, Base):
    __tablename__ = "external_actions"
    __table_args__ = (
        UniqueConstraint("run_id", "step_id", name="uq_external_action_run_step"),
        CheckConstraint(
            "status in ('pending','success','failed','unknown')",
            name="ck_external_action_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    step_id: Mapped[str] = mapped_column(String, nullable=False)
    connector_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    tool: Mapped[str] = mapped_column(String, nullable=False)
    # Stable idempotency key: generated once, reused on every retry/resume.
    external_action_key: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    # Non-secret summary only (webhook host / slack channel id).
    destination_summary: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_class: Mapped[str | None] = mapped_column(String, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    provider_request_id: Mapped[str | None] = mapped_column(String, nullable=True)
    lease_token: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String, nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


# --- Planner proposals (M6) ---
# Immutable audit snapshot of a planning request + its deterministic verdict.
# The raw user prompt and raw provider response are NEVER stored: only a length,
# the parsed/validated proposed plan, the normalized plan, and the feasibility
# report. The only post-insert mutation is linking a materialized version.


class PlanProposal(TimestampMixin, Base):
    __tablename__ = "plan_proposals"
    __table_args__ = (
        CheckConstraint(
            "status in ('PASS','REJECT','NEEDS_CLARIFICATION','NEEDS_APPROVAL')",
            name="ck_plan_proposal_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    # No raw prompt: only its length (bounded by the platform cap).
    prompt_len: Mapped[int] = mapped_column(Integer, nullable=False)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    model: Mapped[str] = mapped_column(String, nullable=False)
    workflow_name: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    # Parsed + schema-validated + feasibility-checked plan (not raw provider bytes).
    proposed_plan: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Canonical plan (e.g. re-rendered SQL); present only when status != REJECT.
    normalized_plan: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    feasibility: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    clarification_questions: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    workflow_version_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)


# --- Schedules (M8) ---
# Durable, structured recurrence pinned to an IMMUTABLE workflow_version. The
# scheduler creates one run per due occurrence; execution stays with the worker.


class Schedule(TimestampMixin, Base):
    __tablename__ = "schedules"
    __table_args__ = (
        CheckConstraint("frequency in ('hourly','daily','weekly')", name="ck_schedule_frequency"),
        CheckConstraint("minute >= 0 and minute <= 59", name="ck_schedule_minute"),
        CheckConstraint("hour is null or (hour >= 0 and hour <= 23)", name="ck_schedule_hour"),
        CheckConstraint(
            "day_of_week is null or (day_of_week >= 0 and day_of_week <= 6)",
            name="ck_schedule_dow",
        ),
        CheckConstraint("frequency = 'hourly' or hour is not null", name="ck_schedule_hour_req"),
        CheckConstraint(
            "frequency <> 'weekly' or day_of_week is not null", name="ck_schedule_dow_req"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    workflow_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False
    )
    # Pinned immutable version: scheduled runs always execute this exact plan.
    workflow_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("workflow_versions.id", ondelete="CASCADE"), nullable=False
    )
    timezone: Mapped[str] = mapped_column(String, nullable=False)
    frequency: Mapped[str] = mapped_column(String, nullable=False)
    minute: Mapped[int] = mapped_column(Integer, nullable=False)
    hour: Mapped[int | None] = mapped_column(Integer, nullable=True)
    day_of_week: Mapped[int | None] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_scheduled_for: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Server-owned: the authenticated admin/owner who created the schedule.
    created_by: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
