"""Data-access repositories for identity and tenancy.

Repositories are the only place queries are built. In M2b they gain tenant
scoping via ``SET LOCAL app.tenant_id`` and RLS becomes the backstop; for M2a
authorization is membership-based at the application layer.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.db.models import Membership, User, Workspace


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
