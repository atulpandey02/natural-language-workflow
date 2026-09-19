"""action connectors: approvals + external_actions + WAITING_APPROVAL

M7. Adds:
- is_current_user_admin_or_owner(tenant) SECURITY DEFINER helper (mirrors
  is_current_user_member); read-only, owned by nlw_rls_bypass.
- approvals: nlw_app SELECT (member) + narrow UPDATE(status, decided_at,
  decided_by, updated_at) gated on admin/owner AND decided_by = app.user_id;
  nlw_worker SELECT + INSERT (tenant-only). No general UPDATE/DELETE for nlw_app.
- external_actions: nlw_worker SELECT/INSERT/UPDATE (tenant-only) for the
  two-phase action lifecycle + lease; nlw_app SELECT (member) for audit.
- WAITING_APPROVAL added to the run/step status CHECK constraints.

Revision ID: 0008_action_connectors
Revises: 0007_plan_proposals
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_action_connectors"
down_revision: str | Sequence[str] | None = "0007_plan_proposals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_GUC = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_USER_GUC = "NULLIF(current_setting('app.user_id', true), '')::uuid"
_MEMBER = f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_member(tenant_id))"
_ADMIN = f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_admin_or_owner(tenant_id))"
_ADMIN_SELF = f"({_ADMIN} AND decided_by = {_USER_GUC})"
_WRK = f"(tenant_id = {_TENANT_GUC})"


def upgrade() -> None:
    # --- admin/owner authorization helper (read-only SECURITY DEFINER) ---
    op.execute("GRANT SELECT (role) ON memberships TO nlw_rls_bypass")
    op.execute(
        """
        CREATE FUNCTION is_current_user_admin_or_owner(p_tenant_id uuid) RETURNS boolean
            LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
            AS $$
                SELECT EXISTS (
                    SELECT 1 FROM public.memberships m
                    WHERE m.user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                      AND m.workspace_id = p_tenant_id
                      AND m.role IN ('owner', 'admin')
                )
            $$
        """
    )
    op.execute("ALTER FUNCTION is_current_user_admin_or_owner(uuid) OWNER TO nlw_rls_bypass")
    op.execute("REVOKE ALL ON FUNCTION is_current_user_admin_or_owner(uuid) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION is_current_user_admin_or_owner(uuid) TO nlw_app")

    # --- approvals ---
    op.create_table(
        "approvals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("step_id", sa.String(), nullable=False),
        sa.Column("connector_id", sa.Uuid(), nullable=False),
        sa.Column("connector_name", sa.String(), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("requested_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("run_id", "step_id", name="uq_approval_run_step"),
        sa.CheckConstraint(
            "status in ('pending','approved','rejected')", name="ck_approval_status"
        ),
    )
    op.create_index("ix_approvals_tenant_id", "approvals", ["tenant_id"])
    op.create_index("ix_approvals_run_id", "approvals", ["run_id"])

    op.execute("GRANT SELECT ON approvals TO nlw_app")
    op.execute("GRANT UPDATE (status, decided_at, decided_by, updated_at) ON approvals TO nlw_app")
    op.execute("GRANT SELECT, INSERT ON approvals TO nlw_worker")
    op.execute("ALTER TABLE approvals ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE approvals FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY approvals_app_select ON approvals FOR SELECT TO nlw_app USING {_MEMBER}"
    )
    op.execute(
        f"CREATE POLICY approvals_app_update ON approvals FOR UPDATE TO nlw_app "
        f"USING {_ADMIN} WITH CHECK {_ADMIN_SELF}"
    )
    op.execute(
        f"CREATE POLICY approvals_worker_select ON approvals FOR SELECT TO nlw_worker USING {_WRK}"
    )
    op.execute(
        f"CREATE POLICY approvals_worker_insert ON approvals FOR INSERT "
        f"TO nlw_worker WITH CHECK {_WRK}"
    )

    # --- external_actions ---
    op.create_table(
        "external_actions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("step_id", sa.String(), nullable=False),
        sa.Column("connector_id", sa.Uuid(), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("external_action_key", sa.Uuid(), nullable=False),
        sa.Column("destination_summary", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_class", sa.String(), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("provider_request_id", sa.String(), nullable=True),
        sa.Column("lease_token", sa.Uuid(), nullable=True),
        sa.Column("lease_owner", sa.String(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("run_id", "step_id", name="uq_external_action_run_step"),
        sa.CheckConstraint(
            "status in ('pending','success','failed')", name="ck_external_action_status"
        ),
    )
    op.create_index("ix_external_actions_tenant_id", "external_actions", ["tenant_id"])
    op.create_index("ix_external_actions_run_id", "external_actions", ["run_id"])

    op.execute("GRANT SELECT ON external_actions TO nlw_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON external_actions TO nlw_worker")
    op.execute("ALTER TABLE external_actions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE external_actions FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY ext_actions_app_select ON external_actions FOR SELECT "
        f"TO nlw_app USING {_MEMBER}"
    )
    op.execute(
        f"CREATE POLICY ext_actions_worker_select ON external_actions FOR SELECT "
        f"TO nlw_worker USING {_WRK}"
    )
    op.execute(
        f"CREATE POLICY ext_actions_worker_insert ON external_actions FOR INSERT "
        f"TO nlw_worker WITH CHECK {_WRK}"
    )
    op.execute(
        f"CREATE POLICY ext_actions_worker_update ON external_actions FOR UPDATE "
        f"TO nlw_worker USING {_WRK} WITH CHECK {_WRK}"
    )

    # --- WAITING_APPROVAL in run/step status checks ---
    op.execute("ALTER TABLE workflow_runs DROP CONSTRAINT ck_run_status")
    op.execute(
        "ALTER TABLE workflow_runs ADD CONSTRAINT ck_run_status "
        "CHECK (status in ('PENDING','RUNNING','WAITING_APPROVAL','COMPLETED','FAILED'))"
    )
    op.execute("ALTER TABLE step_runs DROP CONSTRAINT ck_step_status")
    op.execute(
        "ALTER TABLE step_runs ADD CONSTRAINT ck_step_status "
        "CHECK (status in ('PENDING','RUNNING','WAITING_APPROVAL','SUCCESS','FAILED'))"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE step_runs DROP CONSTRAINT ck_step_status")
    op.execute(
        "ALTER TABLE step_runs ADD CONSTRAINT ck_step_status "
        "CHECK (status in ('PENDING','RUNNING','SUCCESS','FAILED'))"
    )
    op.execute("ALTER TABLE workflow_runs DROP CONSTRAINT ck_run_status")
    op.execute(
        "ALTER TABLE workflow_runs ADD CONSTRAINT ck_run_status "
        "CHECK (status in ('PENDING','RUNNING','COMPLETED','FAILED'))"
    )

    for policy in (
        "ext_actions_worker_update",
        "ext_actions_worker_insert",
        "ext_actions_worker_select",
        "ext_actions_app_select",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON external_actions")
    op.execute("ALTER TABLE external_actions NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE external_actions DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_external_actions_run_id", table_name="external_actions")
    op.drop_index("ix_external_actions_tenant_id", table_name="external_actions")
    op.drop_table("external_actions")

    for policy in (
        "approvals_worker_insert",
        "approvals_worker_select",
        "approvals_app_update",
        "approvals_app_select",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON approvals")
    op.execute("ALTER TABLE approvals NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE approvals DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_approvals_run_id", table_name="approvals")
    op.drop_index("ix_approvals_tenant_id", table_name="approvals")
    op.drop_table("approvals")

    op.execute("DROP FUNCTION IF EXISTS is_current_user_admin_or_owner(uuid)")
    op.execute("REVOKE SELECT (role) ON memberships FROM nlw_rls_bypass")
