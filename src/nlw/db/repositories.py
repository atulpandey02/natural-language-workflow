"""Data-access repositories for identity and tenancy.

Repositories are the only place queries are built. In M2b they gain tenant
scoping via ``SET LOCAL app.tenant_id`` and RLS becomes the backstop; for M2a
authorization is membership-based at the application layer.
"""

import uuid
from typing import Any, Literal

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.db.models import (
    Approval,
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
)

DecisionOutcome = Literal["transitioned", "idempotent", "conflict", "not_found"]


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_or_create(self, auth_provider_id: str, email: str) -> User:
        """Idempotent, race-safe first-sight identity resolution/provisioning.

        Delegates to the ``resolve_or_create_user`` SECURITY DEFINER bootstrap
        function (M11.5 P1A). This is required because at first login the row does
        not exist yet and ``app.user_id`` is not established, so a self-scoped RLS
        policy cannot admit the write; ``nlw_app`` holds no direct INSERT/UPDATE on
        ``users``. The function:

        - returns the existing row unchanged when the verified identity is
          established and its email has not changed (no write, no row lock);
        - inserts exactly one row on first login, converging concurrent races via
          ``UNIQUE(auth_provider_id)``;
        - syncs ``email`` only when the verified provider email actually changed;
        - never reassigns the stable ``auth_provider_id``.

        No commit here: the caller's request transaction owns commit/rollback.
        """
        row = (
            await self.session.execute(
                text(
                    "SELECT id, auth_provider_id, email FROM resolve_or_create_user(:sub, :email)"
                ),
                {"sub": auth_provider_id, "email": email},
            )
        ).one()
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
    ) -> tuple[WorkflowRun, bool]:
        """Idempotent PENDING manual run. Returns (run, created).

        A repeat with the same (tenant_id, idempotency_key) returns the existing
        run without creating a duplicate — this is what makes retries/double-clicks
        safe. Race-safe via ``INSERT ... ON CONFLICT DO NOTHING``.
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
