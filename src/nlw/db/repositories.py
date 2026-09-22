"""Data-access repositories for identity and tenancy.

Repositories are the only place queries are built. In M2b they gain tenant
scoping via ``SET LOCAL app.tenant_id`` and RLS becomes the backstop; for M2a
authorization is membership-based at the application layer.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.db.models import (
    Approval,
    AuthzAuditEvent,
    Connector,
    ExternalAction,
    Membership,
    PlanProposal,
    Schedule,
    StepRun,
    User,
    Workflow,
    WorkflowRun,
    WorkflowVersion,
    Workspace,
    WorkspaceInvitation,
)
from nlw.tenancy.session import set_current_user

DecisionOutcome = Literal[
    "transitioned", "idempotent", "conflict", "not_found", "self_approval", "requester_unknown"
]


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_or_create(self, auth_provider_id: str, email: str) -> User:
        """Idempotent, race-safe first-sight identity resolution/provisioning.

        Three narrow steps (M11.5 P1A), so no single primitive can read or mutate
        another user's identity:

        1. Resolve the internal id via the minimal ``resolve_or_create_user``
           SECURITY DEFINER bootstrap. It inserts a missing identity (race-safe via
           ``UNIQUE(auth_provider_id)``, ``ON CONFLICT DO NOTHING``) and returns
           ONLY the ``uuid`` — never a row, email, or ``auth_provider_id`` — and
           does nothing to an existing row. This is required because at first login
           the row does not exist yet and ``app.user_id`` is not established.
        2. Establish ``app.user_id`` so the self-scoped RLS read/update apply.
        3. Read the caller's own row and, only if the *verified provider* email
           changed, synchronize it through a self-scoped UPDATE (RLS restricts to
           the own row; the column grant restricts to ``email``/``updated_at`` — the
           stable ``auth_provider_id`` can never be written). The email value comes
           exclusively from the verified token, never from request JSON.

        No commit here: the caller's request transaction owns commit/rollback.
        """
        user_id = (
            await self.session.execute(
                text("SELECT resolve_or_create_user(:sub, :email)"),
                {"sub": auth_provider_id, "email": email},
            )
        ).scalar_one()

        # Establish self-context, then read/sync self-scoped (deps also sets this
        # after us; a repeated SET LOCAL of the same value is a harmless no-op).
        await set_current_user(self.session, user_id)
        row = (
            await self.session.execute(
                text("SELECT id, auth_provider_id, email FROM users WHERE id = :id"),
                {"id": user_id},
            )
        ).one()
        if row.email != email:
            await self.session.execute(
                text("UPDATE users SET email = :email, updated_at = now() WHERE id = :id"),
                {"email": email, "id": user_id},
            )
            return User(id=row.id, auth_provider_id=row.auth_provider_id, email=email)
        return User(id=row.id, auth_provider_id=row.auth_provider_id, email=row.email)


class WorkspaceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_for_user(self, user_id: uuid.UUID) -> list[tuple[Workspace, str]]:
        rows = await self.session.execute(
            select(Workspace, Membership.role)
            .join(Membership, Membership.workspace_id == Workspace.id)
            .where(Membership.user_id == user_id)
            .order_by(Workspace.created_at)
        )
        return [(ws, role) for ws, role in rows.all()]


class MembershipRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, user_id: uuid.UUID, workspace_id: uuid.UUID) -> Membership | None:
        return (
            await self.session.execute(
                select(Membership).where(
                    Membership.user_id == user_id,
                    Membership.workspace_id == workspace_id,
                )
            )
        ).scalar_one_or_none()

    async def list_for_workspace(self, workspace_id: uuid.UUID) -> list[Membership]:
        """The workspace roster (RLS: co-members see it; admin/owner manage)."""
        rows = await self.session.execute(
            select(Membership)
            .where(Membership.workspace_id == workspace_id)
            .order_by(Membership.created_at.asc())
        )
        return list(rows.scalars().all())

    async def set_role(
        self, user_id: uuid.UUID, workspace_id: uuid.UUID, role: str
    ) -> Membership | None:
        """Change a member's role. RLS gates admin/owner + owner-only owner rows;
        the owner-preservation trigger blocks demoting the final owner. Returns the
        updated row, or None if no writable row matched (RLS/absent)."""
        await self.session.execute(
            update(Membership)
            .where(Membership.user_id == user_id, Membership.workspace_id == workspace_id)
            .values(role=role, updated_at=func.now())
        )
        return await self.get(user_id, workspace_id)

    async def remove(self, user_id: uuid.UUID, workspace_id: uuid.UUID) -> int:
        """Remove a member. RLS gates admin/owner + owner-only owner rows; the
        owner-preservation trigger blocks removing the final owner. Returns rowcount."""
        result = await self.session.execute(
            delete(Membership).where(
                Membership.user_id == user_id, Membership.workspace_id == workspace_id
            )
        )
        return int(result.rowcount)  # type: ignore[attr-defined]


class AuditRepository:
    """Append-only authorization audit. No tokens/secrets/payloads are recorded."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def emit(
        self,
        *,
        tenant_id: uuid.UUID | None,
        event_type: str,
        actor_user_id: uuid.UUID | None,
        subject_id: uuid.UUID | None = None,
        detail: str | None = None,
    ) -> None:
        self.session.add(
            AuthzAuditEvent(
                tenant_id=tenant_id,
                event_type=event_type,
                actor_user_id=actor_user_id,
                subject_id=subject_id,
                detail=detail,
            )
        )


class InvitationRepository:
    """Workspace invitations (nlw_app; RLS admin/owner-gated create/list/revoke).

    Only the token hash is stored. Acceptance is the SECURITY DEFINER
    ``accept_workspace_invitation`` function (the accepter is not yet a member).
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def count_pending(self, tenant_id: uuid.UUID) -> int:
        return int(
            (
                await self.session.execute(
                    select(func.count())
                    .select_from(WorkspaceInvitation)
                    .where(
                        WorkspaceInvitation.tenant_id == tenant_id,
                        WorkspaceInvitation.status == "pending",
                    )
                )
            ).scalar_one()
        )

    async def create(
        self,
        *,
        tenant_id: uuid.UUID,
        email: str,
        role: str,
        invited_by: uuid.UUID,
        token_hash: str,
        expiry_hours: int,
    ) -> WorkspaceInvitation | None:
        """Create a pending invitation. Returns the row, or None on a duplicate
        pending invite for the same (workspace, email) — conflict-safe."""
        inv = WorkspaceInvitation(
            tenant_id=tenant_id,
            email=email,
            role=role,
            invited_by=invited_by,
            token_hash=token_hash,
            status="pending",
            expires_at=datetime.now(UTC) + timedelta(hours=expiry_hours),
        )
        self.session.add(inv)
        try:
            await self.session.flush()
        except Exception:
            return None
        return inv

    async def list_pending(self, tenant_id: uuid.UUID) -> list[WorkspaceInvitation]:
        rows = await self.session.execute(
            select(WorkspaceInvitation)
            .where(
                WorkspaceInvitation.tenant_id == tenant_id,
                WorkspaceInvitation.status == "pending",
            )
            .order_by(WorkspaceInvitation.created_at.desc())
        )
        return list(rows.scalars().all())

    async def revoke(self, invitation_id: uuid.UUID, tenant_id: uuid.UUID) -> bool:
        """Revoke a pending invitation. Returns True if one was revoked."""
        result = await self.session.execute(
            update(WorkspaceInvitation)
            .where(
                WorkspaceInvitation.id == invitation_id,
                WorkspaceInvitation.tenant_id == tenant_id,
                WorkspaceInvitation.status == "pending",
            )
            .values(status="revoked", updated_at=func.now())
        )
        return int(result.rowcount) == 1  # type: ignore[attr-defined]

    async def accept(self, token_hash: str) -> uuid.UUID:
        """Atomic single-use acceptance via the SECURITY DEFINER function. Raises on
        any invalid/expired/used/wrong-email invitation (uniform, non-enumerating)."""
        raw = (
            await self.session.execute(
                text("SELECT accept_workspace_invitation(:h)"), {"h": token_hash}
            )
        ).scalar_one()
        return raw if isinstance(raw, uuid.UUID) else uuid.UUID(str(raw))


class ConnectorRepository:
    """Tenant-scoped connector access for the API (nlw_app: SELECT + INSERT)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        tenant_id: uuid.UUID,
        type_: str,
        name: str,
        config: dict[str, Any],
        secret_ref: str | None,
    ) -> Connector:
        connector = Connector(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            type=type_,
            name=name,
            config=config,
            secret_ref=secret_ref,
            status="unchecked",
        )
        self.session.add(connector)
        await self.session.flush()
        return connector

    async def list_for_tenant(self, tenant_id: uuid.UUID) -> list[Connector]:
        rows = await self.session.execute(
            select(Connector).where(Connector.tenant_id == tenant_id).order_by(Connector.created_at)
        )
        return list(rows.scalars().all())

    async def owned_types(self, tenant_id: uuid.UUID) -> set[str]:
        rows = await self.session.execute(
            select(Connector.type).where(Connector.tenant_id == tenant_id).distinct()
        )
        return set(rows.scalars().all())


class PlanProposalRepository:
    """Tenant-scoped planner-proposal access (nlw_app: SELECT/INSERT + narrow UPDATE)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        *,
        tenant_id: uuid.UUID,
        created_by: uuid.UUID,
        prompt_len: int,
        provider: str,
        model: str,
        workflow_name: str,
        status: str,
        proposed_plan: dict[str, Any] | None,
        normalized_plan: dict[str, Any] | None,
        feasibility: dict[str, Any],
        clarification_questions: list[str] | None,
    ) -> PlanProposal:
        proposal = PlanProposal(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            created_by=created_by,
            prompt_len=prompt_len,
            provider=provider,
            model=model,
            workflow_name=workflow_name,
            status=status,
            proposed_plan=proposed_plan,
            normalized_plan=normalized_plan,
            feasibility=feasibility,
            clarification_questions=clarification_questions,
        )
        self.session.add(proposal)
        await self.session.flush()
        return proposal

    async def get(self, proposal_id: uuid.UUID, tenant_id: uuid.UUID) -> PlanProposal | None:
        return (
            await self.session.execute(
                select(PlanProposal).where(
                    PlanProposal.id == proposal_id, PlanProposal.tenant_id == tenant_id
                )
            )
        ).scalar_one_or_none()

    async def get_for_update(
        self, proposal_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> PlanProposal | None:
        """Row-locked read for concurrency-safe, idempotent materialization."""
        return (
            await self.session.execute(
                select(PlanProposal)
                .where(PlanProposal.id == proposal_id, PlanProposal.tenant_id == tenant_id)
                .with_for_update()
            )
        ).scalar_one_or_none()

    async def list_for_tenant(self, tenant_id: uuid.UUID) -> list[PlanProposal]:
        rows = await self.session.execute(
            select(PlanProposal)
            .where(PlanProposal.tenant_id == tenant_id)
            .order_by(PlanProposal.created_at.desc())
        )
        return list(rows.scalars().all())


class ApprovalRepository:
    """Tenant-scoped approval access. Decisions are compare-and-set; RLS also
    enforces admin/owner + decided_by = app.user_id on the UPDATE."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_for_tenant(
        self, tenant_id: uuid.UUID, *, pending_only: bool = True
    ) -> list[Approval]:
        stmt = select(Approval).where(Approval.tenant_id == tenant_id)
        if pending_only:
            stmt = stmt.where(Approval.status == "pending")
        stmt = stmt.order_by(Approval.requested_at.desc())
        return list((await self.session.execute(stmt)).scalars().all())

    async def get(self, approval_id: uuid.UUID, tenant_id: uuid.UUID) -> Approval | None:
        return (
            await self.session.execute(
                select(Approval).where(Approval.id == approval_id, Approval.tenant_id == tenant_id)
            )
        ).scalar_one_or_none()

    async def decide(
        self,
        approval_id: uuid.UUID,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        target: Literal["approved", "rejected"],
    ) -> tuple[DecisionOutcome, uuid.UUID | None]:
        """Recovery-safe CAS. Returns (outcome, run_id). Repeating the same
        decision is idempotent (so a lost enqueue can be re-driven); the opposite
        decision on an already-decided approval conflicts."""
        appr = await self.get(approval_id, tenant_id)
        if appr is None:
            return "not_found", None
        # Separation of duties (also enforced by the RLS WITH CHECK as the backstop
        # against direct SQL): the decider must not be the requester, and a legacy
        # approval whose requester is unknown cannot be decided (fail closed).
        if appr.requested_by_user_id is None:
            return "requester_unknown", appr.run_id
        if appr.requested_by_user_id == user_id:
            return "self_approval", appr.run_id
        if appr.status == target:
            return "idempotent", appr.run_id
        if appr.status != "pending":
            return "conflict", appr.run_id
        result = await self.session.execute(
            update(Approval)
            .where(
                Approval.id == approval_id,
                Approval.tenant_id == tenant_id,
                Approval.status == "pending",
                # Belt-and-suspenders: never attempt a self / unknown-requester
                # decision (the RLS WITH CHECK would reject it anyway).
                Approval.requested_by_user_id.isnot(None),
                Approval.requested_by_user_id != user_id,
            )
            .values(status=target, decided_by=user_id, decided_at=func.now())
        )
        if result.rowcount == 1:  # type: ignore[attr-defined]
            return "transitioned", appr.run_id
        # Lost a race: re-read to classify.
        fresh = await self.get(approval_id, tenant_id)
        if fresh is not None and fresh.status == target:
            return "idempotent", fresh.run_id
        return "conflict", appr.run_id


class WorkflowRepository:
    """Tenant-scoped read access to workflows + versions (nlw_app; RLS-scoped)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_for_tenant(
        self, tenant_id: uuid.UUID, *, limit: int, offset: int
    ) -> list[Workflow]:
        rows = await self.session.execute(
            select(Workflow)
            .where(Workflow.tenant_id == tenant_id)
            .order_by(Workflow.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(rows.scalars().all())

    async def get(self, workflow_id: uuid.UUID, tenant_id: uuid.UUID) -> Workflow | None:
        return (
            await self.session.execute(
                select(Workflow).where(Workflow.id == workflow_id, Workflow.tenant_id == tenant_id)
            )
        ).scalar_one_or_none()

    async def get_version(
        self, version_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> WorkflowVersion | None:
        return (
            await self.session.execute(
                select(WorkflowVersion).where(
                    WorkflowVersion.id == version_id, WorkflowVersion.tenant_id == tenant_id
                )
            )
        ).scalar_one_or_none()


class RunRepository:
    """Tenant-scoped run/step/action read access + idempotent manual run creation."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_for_tenant(
        self,
        tenant_id: uuid.UUID,
        *,
        limit: int,
        offset: int,
        workflow_id: uuid.UUID | None = None,
        status: str | None = None,
    ) -> list[WorkflowRun]:
        stmt = select(WorkflowRun).where(WorkflowRun.tenant_id == tenant_id)
        if workflow_id is not None:
            stmt = stmt.where(WorkflowRun.workflow_id == workflow_id)
        if status is not None:
            stmt = stmt.where(WorkflowRun.status == status)
        stmt = stmt.order_by(WorkflowRun.created_at.desc()).limit(limit).offset(offset)
        return list((await self.session.execute(stmt)).scalars().all())

    async def get(self, run_id: uuid.UUID, tenant_id: uuid.UUID) -> WorkflowRun | None:
        return (
            await self.session.execute(
                select(WorkflowRun).where(
                    WorkflowRun.id == run_id, WorkflowRun.tenant_id == tenant_id
                )
            )
        ).scalar_one_or_none()

    async def steps(self, run_id: uuid.UUID, tenant_id: uuid.UUID) -> list[StepRun]:
        rows = await self.session.execute(
            select(StepRun)
            .where(StepRun.run_id == run_id, StepRun.tenant_id == tenant_id)
            .order_by(StepRun.started_at.asc().nulls_last(), StepRun.step_id.asc())
        )
        return list(rows.scalars().all())

    async def actions(self, run_id: uuid.UUID, tenant_id: uuid.UUID) -> list[ExternalAction]:
        rows = await self.session.execute(
            select(ExternalAction)
            .where(ExternalAction.run_id == run_id, ExternalAction.tenant_id == tenant_id)
            .order_by(ExternalAction.step_id.asc())
        )
        return list(rows.scalars().all())

    async def create_manual(
        self,
        *,
        tenant_id: uuid.UUID,
        workflow_id: uuid.UUID,
        workflow_version_id: uuid.UUID,
        idempotency_key: str,
        initiated_by_user_id: uuid.UUID,
    ) -> tuple[WorkflowRun, bool]:
        """Idempotent PENDING manual run. Returns (run, created).

        A repeat with the same (tenant_id, idempotency_key) returns the existing
        run without creating a duplicate — this is what makes retries/double-clicks
        safe. Race-safe via ``INSERT ... ON CONFLICT DO NOTHING``. ``initiated_by``
        records the authenticated creator (approval-requester provenance, P3A).
        """
        run_id = uuid.uuid4()
        stmt = (
            pg_insert(WorkflowRun)
            .values(
                id=run_id,
                tenant_id=tenant_id,
                workflow_id=workflow_id,
                workflow_version_id=workflow_version_id,
                status="PENDING",
                trigger="manual",
                idempotency_key=idempotency_key,
                initiated_by_user_id=initiated_by_user_id,
            )
            .on_conflict_do_nothing(constraint="uq_run_tenant_idempotency")
            .returning(WorkflowRun.id)
        )
        inserted_id = (await self.session.execute(stmt)).scalar_one_or_none()
        created = inserted_id is not None
        run = (
            await self.session.execute(
                select(WorkflowRun).where(
                    WorkflowRun.tenant_id == tenant_id,
                    WorkflowRun.idempotency_key == idempotency_key,
                )
            )
        ).scalar_one()
        return run, created


class ScheduleRepository:
    """Tenant-scoped schedule access for the API (nlw_app; RLS admin-gated writes)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, schedule: "Schedule") -> "Schedule":
        self.session.add(schedule)
        await self.session.flush()
        return schedule

    async def get(self, schedule_id: uuid.UUID, tenant_id: uuid.UUID) -> "Schedule | None":
        return (
            await self.session.execute(
                select(Schedule).where(Schedule.id == schedule_id, Schedule.tenant_id == tenant_id)
            )
        ).scalar_one_or_none()

    async def list_for_tenant(self, tenant_id: uuid.UUID) -> "list[Schedule]":
        rows = await self.session.execute(
            select(Schedule)
            .where(Schedule.tenant_id == tenant_id)
            .order_by(Schedule.created_at.desc())
        )
        return list(rows.scalars().all())
