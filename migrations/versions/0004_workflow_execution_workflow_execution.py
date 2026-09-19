"""workflow execution

Durable workflow model (workflows, immutable workflow_versions) and execution
model (workflow_runs, step_runs). Least-privilege grants for nlw_app (create/
read) and nlw_worker (execution only). Worker tenant bootstrap uses a hardened,
worker-only SECURITY DEFINER resolver (run_id -> tenant_id) owned by the
non-login BYPASSRLS role; workflow_runs itself keeps only tenant-scoped RLS (no
GUC-settable self-policy). FORCE RLS is preserved on every table.

Roles (nlw_app, nlw_worker, nlw_rls_bypass) are created by bootstrap, not here.

Revision ID: 0004_workflow_execution
Revises: 0003_rls_isolation
Create Date: 2026-09-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_workflow_execution"
down_revision: str | Sequence[str] | None = "0003_rls_isolation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TS = dict(server_default=sa.func.now(), nullable=False)
_TENANT_GUC = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.create_table(
        "workflows",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("current_version_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **_TS),
        sa.Column("updated_at", sa.DateTime(timezone=True), **_TS),
    )
    op.create_index("ix_workflows_tenant_id", "workflows", ["tenant_id"])

    op.create_table(
        "workflow_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("workflow_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("plan", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), **_TS),
        sa.Column("updated_at", sa.DateTime(timezone=True), **_TS),
        sa.ForeignKeyConstraint(["workflow_id"], ["workflows.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("workflow_id", "version", name="uq_version_workflow_version"),
    )
    op.create_index("ix_workflow_versions_tenant_id", "workflow_versions", ["tenant_id"])

    op.create_table(
        "workflow_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("workflow_id", sa.Uuid(), nullable=False),
        sa.Column("workflow_version_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("trigger", sa.String(), nullable=False, server_default="manual"),
        sa.Column("idempotency_key", sa.String(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **_TS),
        sa.Column("updated_at", sa.DateTime(timezone=True), **_TS),
        sa.ForeignKeyConstraint(["workflow_id"], ["workflows.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["workflow_version_id"], ["workflow_versions.id"], ondelete="CASCADE"
        ),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_run_tenant_idempotency"),
        sa.CheckConstraint(
            "status in ('PENDING','RUNNING','COMPLETED','FAILED')", name="ck_run_status"
        ),
    )
    op.create_index("ix_workflow_runs_tenant_id", "workflow_runs", ["tenant_id"])
    op.create_index("ix_workflow_runs_workflow_id", "workflow_runs", ["workflow_id"])

    op.create_table(
        "step_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("step_id", sa.String(), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("input", postgresql.JSONB(), nullable=True),
        sa.Column("output", postgresql.JSONB(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **_TS),
        sa.Column("updated_at", sa.DateTime(timezone=True), **_TS),
        sa.ForeignKeyConstraint(["run_id"], ["workflow_runs.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("run_id", "step_id", name="uq_step_run_run_step"),
        sa.CheckConstraint(
            "status in ('PENDING','RUNNING','SUCCESS','FAILED')", name="ck_step_status"
        ),
    )
    op.create_index("ix_step_runs_tenant_id", "step_runs", ["tenant_id"])
    op.create_index("ix_step_runs_run_id", "step_runs", ["run_id"])

    # --- Least-privilege grants ---
    # nlw_app: create/read definitions & runs (no step writes).
    op.execute("GRANT SELECT, INSERT, UPDATE ON workflows TO nlw_app")
    op.execute("GRANT SELECT, INSERT ON workflow_versions TO nlw_app")
    op.execute("GRANT SELECT, INSERT ON workflow_runs TO nlw_app")
    op.execute("GRANT SELECT ON step_runs TO nlw_app")
    # nlw_worker: execution only (read plan; lock+update runs; write step_runs).
    op.execute("GRANT SELECT ON workflow_versions TO nlw_worker")
    op.execute("GRANT SELECT, UPDATE ON workflow_runs TO nlw_worker")
    op.execute("GRANT SELECT, INSERT, UPDATE ON step_runs TO nlw_worker")

    # --- Worker-only tenant resolver (hardened SECURITY DEFINER) ---
    # Minimal search_path, schema-qualified table reference. Owned by the
    # non-login BYPASSRLS role; nlw_rls_bypass gets only column-level SELECT.
    op.execute("GRANT SELECT (id, tenant_id) ON workflow_runs TO nlw_rls_bypass")
    op.execute(
        """
        CREATE FUNCTION resolve_run_tenant(p_run_id uuid) RETURNS uuid
            LANGUAGE sql
            STABLE
            SECURITY DEFINER
            SET search_path = pg_catalog
            AS $$ SELECT tenant_id FROM public.workflow_runs WHERE id = p_run_id $$
        """
    )
    op.execute("ALTER FUNCTION resolve_run_tenant(uuid) OWNER TO nlw_rls_bypass")
    op.execute("REVOKE ALL ON FUNCTION resolve_run_tenant(uuid) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION resolve_run_tenant(uuid) TO nlw_worker")

    # --- App membership-check helper (read-only SECURITY DEFINER) ---
    # Derives app.user_id internally; returns boolean only. Owned by the
    # read-only non-login BYPASSRLS role (column-level SELECT on memberships).
    op.execute("GRANT SELECT (user_id, workspace_id) ON memberships TO nlw_rls_bypass")
    op.execute(
        """
        CREATE FUNCTION is_current_user_member(p_tenant_id uuid) RETURNS boolean
            LANGUAGE sql
            STABLE
            SECURITY DEFINER
            SET search_path = pg_catalog
            AS $$
                SELECT EXISTS (
                    SELECT 1 FROM public.memberships m
                    WHERE m.user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                      AND m.workspace_id = p_tenant_id
                )
            $$
        """
    )
    op.execute("ALTER FUNCTION is_current_user_member(uuid) OWNER TO nlw_rls_bypass")
    op.execute("REVOKE ALL ON FUNCTION is_current_user_member(uuid) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION is_current_user_member(uuid) TO nlw_app")

    # --- RLS: enable + FORCE on all four; role-specific policies (no PUBLIC) ---
    # nlw_app: bound to active tenant AND the caller's membership in it.
    # nlw_worker: tenant-only (tenant obtained via resolve_run_tenant bootstrap).
    app = f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_member(tenant_id))"
    wrk = f"(tenant_id = {_TENANT_GUC})"
    for table in ("workflows", "workflow_versions", "workflow_runs", "step_runs"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    # nlw_app policies (per granted command)
    op.execute(f"CREATE POLICY workflows_app_select ON workflows FOR SELECT TO nlw_app USING {app}")
    op.execute(
        f"CREATE POLICY workflows_app_insert ON workflows FOR INSERT TO nlw_app WITH CHECK {app}"
    )
    op.execute(
        f"CREATE POLICY workflows_app_update ON workflows FOR UPDATE TO nlw_app "
        f"USING {app} WITH CHECK {app}"
    )
    op.execute(
        f"CREATE POLICY workflow_versions_app_select ON workflow_versions FOR SELECT "
        f"TO nlw_app USING {app}"
    )
    op.execute(
        f"CREATE POLICY workflow_versions_app_insert ON workflow_versions FOR INSERT "
        f"TO nlw_app WITH CHECK {app}"
    )
    op.execute(
        f"CREATE POLICY workflow_runs_app_select ON workflow_runs FOR SELECT TO nlw_app USING {app}"
    )
    op.execute(
        f"CREATE POLICY workflow_runs_app_insert ON workflow_runs FOR INSERT "
        f"TO nlw_app WITH CHECK {app}"
    )
    op.execute(f"CREATE POLICY step_runs_app_select ON step_runs FOR SELECT TO nlw_app USING {app}")

    # nlw_worker policies (tenant-only, per granted command)
    op.execute(
        f"CREATE POLICY workflow_versions_worker_select ON workflow_versions FOR SELECT "
        f"TO nlw_worker USING {wrk}"
    )
    op.execute(
        f"CREATE POLICY workflow_runs_worker_select ON workflow_runs FOR SELECT "
        f"TO nlw_worker USING {wrk}"
    )
    op.execute(
        f"CREATE POLICY workflow_runs_worker_update ON workflow_runs FOR UPDATE "
        f"TO nlw_worker USING {wrk} WITH CHECK {wrk}"
    )
    op.execute(
        f"CREATE POLICY step_runs_worker_select ON step_runs FOR SELECT TO nlw_worker USING {wrk}"
    )
    op.execute(
        f"CREATE POLICY step_runs_worker_insert ON step_runs FOR INSERT "
        f"TO nlw_worker WITH CHECK {wrk}"
    )
    op.execute(
        f"CREATE POLICY step_runs_worker_update ON step_runs FOR UPDATE "
        f"TO nlw_worker USING {wrk} WITH CHECK {wrk}"
    )


_APP_POLICIES = (
    "workflows_app_select",
    "workflows_app_insert",
    "workflows_app_update",
    "workflow_versions_app_select",
    "workflow_versions_app_insert",
    "workflow_runs_app_select",
    "workflow_runs_app_insert",
    "step_runs_app_select",
)
_WORKER_POLICIES = (
    "workflow_versions_worker_select",
    "workflow_runs_worker_select",
    "workflow_runs_worker_update",
    "step_runs_worker_select",
    "step_runs_worker_insert",
    "step_runs_worker_update",
)
_POLICY_TABLE = {
    "workflows": "workflows",
    "workflow_versions": "workflow_versions",
    "workflow_runs": "workflow_runs",
    "step_runs": "step_runs",
}


def _table_of(policy: str) -> str:
    for table in ("workflow_versions", "workflow_runs", "step_runs", "workflows"):
        if policy.startswith(table + "_"):
            return table
    raise ValueError(policy)


def downgrade() -> None:
    for policy in (*_APP_POLICIES, *_WORKER_POLICIES):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON {_table_of(policy)}")
    for table in ("step_runs", "workflow_runs", "workflow_versions", "workflows"):
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP FUNCTION IF EXISTS is_current_user_member(uuid)")
    op.execute("DROP FUNCTION IF EXISTS resolve_run_tenant(uuid)")
    op.drop_table("step_runs")
    op.drop_table("workflow_runs")
    op.drop_table("workflow_versions")
    op.drop_table("workflows")
