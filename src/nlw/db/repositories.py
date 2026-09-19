"""Data-access repositories for identity and tenancy.

Repositories are the only place queries are built. In M2b they gain tenant
scoping via ``SET LOCAL app.tenant_id`` and RLS becomes the backstop; for M2a
authorization is membership-based at the application layer.
"""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.db.models import Connector, Membership, PlanProposal, User, Workspace


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_or_create(self, auth_provider_id: str, email: str) -> User:
        """Idempotent, race-safe first-sight provisioning.

        Relies on ``UNIQUE(auth_provider_id)``: concurrent callers converge on a
        single row via ``INSERT ... ON CONFLICT``.
        """
        stmt = (
            pg_insert(User)
            .values(id=uuid.uuid4(), auth_provider_id=auth_provider_id, email=email)
            .on_conflict_do_update(index_elements=["auth_provider_id"], set_={"email": email})
        )
        # No commit here: the caller's request transaction owns commit/rollback.
        # The row is visible to later statements in the same transaction, and
        # ON CONFLICT keeps it race-safe regardless of commit timing.
        await self.session.execute(stmt)
        user = (
            await self.session.execute(
                select(User).where(User.auth_provider_id == auth_provider_id)
            )
        ).scalar_one()
        return user


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
