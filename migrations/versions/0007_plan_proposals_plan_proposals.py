"""plan_proposals

Immutable planner audit snapshots (M6). Stores no raw prompt (only prompt_len)
and no raw provider response — only the parsed/validated proposed plan, the
normalized plan, and the deterministic feasibility report. Role-specific RLS
(no PUBLIC), reusing is_current_user_member (0004):
- nlw_app: SELECT, INSERT (membership-bound), and column-level
           UPDATE(workflow_version_id, updated_at) only, for one-time
           materialization linkage. No general UPDATE/DELETE.
- nlw_worker: no access in M6 (planning is API-side).

Revision ID: 0007_plan_proposals
Revises: 0006_connectors
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_plan_proposals"
down_revision: str | Sequence[str] | None = "0006_connectors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_GUC = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_APP = f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_member(tenant_id))"


def upgrade() -> None:
    op.create_table(
        "plan_proposals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("prompt_len", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("model", sa.String(), nullable=False),
        sa.Column("workflow_name", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("proposed_plan", postgresql.JSONB(), nullable=True),
        sa.Column("normalized_plan", postgresql.JSONB(), nullable=True),
        sa.Column("feasibility", postgresql.JSONB(), nullable=False),
        sa.Column("clarification_questions", postgresql.JSONB(), nullable=True),
        sa.Column("workflow_version_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status in ('PASS','REJECT','NEEDS_CLARIFICATION','NEEDS_APPROVAL')",
            name="ck_plan_proposal_status",
        ),
    )
    op.create_index("ix_plan_proposals_tenant_id", "plan_proposals", ["tenant_id"])

    # Grants (least privilege): immutable snapshot + one-time materialization link.
    op.execute("GRANT SELECT, INSERT ON plan_proposals TO nlw_app")
    op.execute("GRANT UPDATE (workflow_version_id, updated_at) ON plan_proposals TO nlw_app")

    # RLS: enable + FORCE; role-specific policies (no PUBLIC).
    op.execute("ALTER TABLE plan_proposals ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE plan_proposals FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY plan_proposals_app_select ON plan_proposals "
        f"FOR SELECT TO nlw_app USING {_APP}"
    )
    op.execute(
        f"CREATE POLICY plan_proposals_app_insert ON plan_proposals "
        f"FOR INSERT TO nlw_app WITH CHECK {_APP}"
    )
    op.execute(
        f"CREATE POLICY plan_proposals_app_update ON plan_proposals "
        f"FOR UPDATE TO nlw_app USING {_APP} WITH CHECK {_APP}"
    )


def downgrade() -> None:
    for policy in (
        "plan_proposals_app_update",
        "plan_proposals_app_insert",
        "plan_proposals_app_select",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON plan_proposals")
    op.execute("ALTER TABLE plan_proposals NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE plan_proposals DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_plan_proposals_tenant_id", table_name="plan_proposals")
    op.drop_table("plan_proposals")
