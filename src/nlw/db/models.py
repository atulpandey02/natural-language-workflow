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


class WorkspaceInvitation(TimestampMixin, Base):
    """A single-use invitation to join a workspace (M11.5 P3A).

    Only the sha256 hash of the high-entropy token is stored; the raw token is
    returned once at creation for manual sharing and never persisted/logged.
    """

    __tablename__ = "workspace_invitations"
    __table_args__ = (
        CheckConstraint("role in ('admin','member')", name="ck_invitation_role"),
        CheckConstraint(
            "status in ('pending','accepted','revoked','expired')", name="ck_invitation_status"
        ),
        UniqueConstraint("token_hash", name="uq_invitation_token_hash"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False)
    invited_by: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthzAuditEvent(Base):
    """Append-only authorization audit (M11.5 P3A). No tokens/secrets/payloads."""

    __tablename__ = "authz_audit_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    subject_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    detail: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


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
    # M12B final: authoritative connector identity binding per connector-backed
    # step -> {connector_id, connector_type, config_fingerprint}. Computed at
    # materialization; execution loads by the bound id and fails closed (STALE_PLAN)
    # on identity/type/config change. NULL only for pre-binding historical versions.
    connector_bindings: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)


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
    # M11.5 P3A: the authenticated user who created a MANUAL run (approval-requester
    # provenance). NULL for scheduled runs — schedules.created_by is authoritative.
    initiated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    idempotency_key: Mapped[str | None] = mapped_column(String, nullable=True)
    # M8: scheduled runs pin the schedule + occurrence (exactly-once per occurrence).
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # M11.5 P1D: last MEANINGFUL execution-state advancement (server time). Updated
    # ONLY on genuine state-machine progress (run/step/action transitions, retry
    # scheduling, approval resolution) — NEVER on a reconciler scan, a read, or an
    # unrelated metadata write. The reconciler uses this (not the mutable
    # ``updated_at``) to tell a genuinely stuck run from one still progressing.
    last_progress_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


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
    # M11.5 P3A: immutable identity of the human whose action requires approval
    # (derived from run provenance by the worker, NEVER from request JSON). A NULL
    # requester (legacy/unknown) fails closed for decision (four-eyes RLS).
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
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
    # Durable ambiguity boundary (ADR-013 crash window). Committed immediately
    # BEFORE the out-of-lock network transmission and cleared only when a provably
    # pre-transmission (or contractually-throttled) failure schedules a retry. If
    # this is set and the attempt never finalized (worker death), the transmission
    # MAY have started: lease recovery transitions the action to terminal UNKNOWN
    # rather than resending it (unless the tool has an enforced idempotency
    # contract). NULL = no attempt has crossed the boundary yet.
    transmission_started_at: Mapped[datetime | None] = mapped_column(
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
    # Length of the request (bounded by the platform cap); kept for back-compat.
    prompt_len: Mapped[int] = mapped_column(Integer, nullable=False)
    # M12B-A: durable request->plan provenance. The original NL request text
    # (bounded before persistence), its sha256 digest (mutation detection), and
    # the planner contract version. Immutable after INSERT (nlw_app has no UPDATE
    # grant on these columns); never logged/metered; RLS/tenant-scoped.
    request_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_sha256: Mapped[str | None] = mapped_column(String, nullable=True)
    planner_contract_version: Mapped[str | None] = mapped_column(String, nullable=True)
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


# --- Disaster recovery (M11.5 P2) ---
# Append-only, PLATFORM-level audit of post-restore quiescence. NOT tenant-scoped
# and outside RLS; no runtime role is granted access (only the owner/restore
# connection writes it), so a restore event cannot be forged by a tenant.


class DrRestoreEvent(Base):
    __tablename__ = "dr_restore_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    restored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    cutoff_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    manifest_format: Mapped[str | None] = mapped_column(String, nullable=True)
    snapshot_id: Mapped[str | None] = mapped_column(String, nullable=True)
    alembic_revision: Mapped[str | None] = mapped_column(String, nullable=True)
    app_version: Mapped[str | None] = mapped_column(String, nullable=True)
    pg_version: Mapped[str | None] = mapped_column(String, nullable=True)
    runs_quiesced: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    steps_quiesced: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actions_unknowned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    schedules_recomputed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Authoritative recovery-lock state (addendum): a restored generation is
    # runtime-LOCKED until validated (by the restore) AND explicitly enabled (by the
    # operator enable command). Runtime roles have column-scoped SELECT only.
    target_project: Mapped[str | None] = mapped_column(String, nullable=True)
    validation_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    runtime_enabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    runtime_enabled_by: Mapped[str | None] = mapped_column(String, nullable=True)
