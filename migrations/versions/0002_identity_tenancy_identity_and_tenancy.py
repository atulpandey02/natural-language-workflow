"""identity and tenancy

Creates users, workspaces, memberships (M2a). No roles or RLS here — role
provisioning is a bootstrap concern and RLS policies arrive in M2b.

Revision ID: 0002_identity_tenancy
Revises: 0001_baseline
Create Date: 2026-09-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_identity_tenancy"
down_revision: str | Sequence[str] | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("auth_provider_id", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("auth_provider_id", name="uq_users_auth_provider_id"),
    )
    # No separate index on auth_provider_id: the UNIQUE constraint already indexes it.

    op.create_table(
        "workspaces",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("slug", name="uq_workspaces_slug"),
    )

    op.create_table(
        "memberships",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("user_id", "workspace_id", name="uq_membership_user_workspace"),
        sa.CheckConstraint("role in ('owner','admin','member')", name="ck_membership_role"),
    )
    # user_id is covered by the UNIQUE(user_id, workspace_id) composite index;
    # workspace_id (not the leading column) keeps its own index.
    op.create_index("ix_memberships_workspace_id", "memberships", ["workspace_id"])


def downgrade() -> None:
    op.drop_index("ix_memberships_workspace_id", table_name="memberships")
    op.drop_table("memberships")
    op.drop_table("workspaces")
    op.drop_table("users")
