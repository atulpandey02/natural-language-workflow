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

    # --- RLS: enable + FORCE on all four; tenant-scoped policies only ---
    for table in ("workflows", "workflow_versions", "workflow_runs", "step_runs"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {table}_tenant_select ON {table} FOR SELECT "
            f"USING (tenant_id = {_TENANT_GUC})"
        )
        op.execute(
            f"CREATE POLICY {table}_tenant_insert ON {table} FOR INSERT "
            f"WITH CHECK (tenant_id = {_TENANT_GUC})"
        )
        op.execute(
            f"CREATE POLICY {table}_tenant_update ON {table} FOR UPDATE "
            f"USING (tenant_id = {_TENANT_GUC}) WITH CHECK (tenant_id = {_TENANT_GUC})"
        )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS resolve_run_tenant(uuid)")
    for table in ("step_runs", "workflow_runs", "workflow_versions", "workflows"):
        for cmd in ("update", "insert", "select"):
            op.execute(f"DROP POLICY IF EXISTS {table}_tenant_{cmd} ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.drop_table("step_runs")
    op.drop_table("workflow_runs")
    op.drop_table("workflow_versions")
    op.drop_table("workflows")
