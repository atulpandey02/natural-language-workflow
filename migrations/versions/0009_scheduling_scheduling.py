"""scheduling: schedules + scheduled-run columns + nlw_scheduler policies

M8. Adds:
- schedules: durable structured recurrence pinned to an immutable
  workflow_version. nlw_app CRUD is membership-bound; INSERT/UPDATE/DELETE also
  require admin/owner (is_current_user_admin_or_owner). nlw_scheduler gets
  role-specific cross-tenant SELECT + narrow UPDATE(next_run_at,
  last_scheduled_for, updated_at).
- workflow_runs: schedule_id, scheduled_for + UNIQUE(schedule_id, scheduled_for)
  (NULLs distinct -> manual runs never collide). nlw_scheduler role-specific
  SELECT + INSERT (cross-tenant) for run creation + reconciliation.
- external_actions/approvals: nlw_scheduler role-specific SELECT (reconcile only).

nlw_scheduler is LOGIN NOSUPERUSER NOBYPASSRLS (created by bootstrap). It has NO
grant on connectors, secrets, or step_runs I/O.

Revision ID: 0009_scheduling
Revises: 0008_action_connectors
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_scheduling"
down_revision: str | Sequence[str] | None = "0008_action_connectors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_GUC = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_MEMBER = f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_member(tenant_id))"
_ADMIN = f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_admin_or_owner(tenant_id))"


def upgrade() -> None:
    op.create_table(
        "schedules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("workflow_id", sa.Uuid(), nullable=False),
        sa.Column("workflow_version_id", sa.Uuid(), nullable=False),
        sa.Column("timezone", sa.String(), nullable=False),
        sa.Column("frequency", sa.String(), nullable=False),
        sa.Column("minute", sa.Integer(), nullable=False),
        sa.Column("hour", sa.Integer(), nullable=True),
        sa.Column("day_of_week", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_scheduled_for", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["workflow_id"], ["workflows.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["workflow_version_id"], ["workflow_versions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "frequency in ('hourly','daily','weekly')", name="ck_schedule_frequency"
        ),
        sa.CheckConstraint("minute >= 0 and minute <= 59", name="ck_schedule_minute"),
        sa.CheckConstraint("hour is null or (hour >= 0 and hour <= 23)", name="ck_schedule_hour"),
        sa.CheckConstraint(
            "day_of_week is null or (day_of_week >= 0 and day_of_week <= 6)", name="ck_schedule_dow"
        ),
        sa.CheckConstraint("frequency = 'hourly' or hour is not null", name="ck_schedule_hour_req"),
        sa.CheckConstraint(
            "frequency <> 'weekly' or day_of_week is not null", name="ck_schedule_dow_req"
        ),
    )
    op.create_index("ix_schedules_tenant_id", "schedules", ["tenant_id"])
    op.create_index("ix_schedules_next_run_at", "schedules", ["next_run_at"])

    # workflow_runs: scheduled-occurrence columns + exactly-once constraint.
    op.add_column("workflow_runs", sa.Column("schedule_id", sa.Uuid(), nullable=True))
    op.add_column(
        "workflow_runs", sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_foreign_key(
        "fk_run_schedule",
        "workflow_runs",
        "schedules",
        ["schedule_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_unique_constraint(
        "uq_run_schedule_occurrence", "workflow_runs", ["schedule_id", "scheduled_for"]
    )

    # --- Grants (least privilege) ---
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON schedules TO nlw_app")
    op.execute("GRANT SELECT ON schedules TO nlw_scheduler")
    op.execute(
        "GRANT UPDATE (next_run_at, last_scheduled_for, updated_at) ON schedules TO nlw_scheduler"
    )
    op.execute("GRANT SELECT, INSERT ON workflow_runs TO nlw_scheduler")
    op.execute("GRANT SELECT ON external_actions TO nlw_scheduler")
    op.execute("GRANT SELECT ON approvals TO nlw_scheduler")

    # --- schedules RLS ---
    op.execute("ALTER TABLE schedules ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE schedules FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY schedules_app_select ON schedules FOR SELECT TO nlw_app USING {_MEMBER}"
    )
    op.execute(
        f"CREATE POLICY schedules_app_insert ON schedules FOR INSERT TO nlw_app WITH CHECK {_ADMIN}"
    )
    op.execute(
        f"CREATE POLICY schedules_app_update ON schedules FOR UPDATE TO nlw_app "
        f"USING {_ADMIN} WITH CHECK {_ADMIN}"
    )
    op.execute(
        f"CREATE POLICY schedules_app_delete ON schedules FOR DELETE TO nlw_app USING {_ADMIN}"
    )
    # Scheduler: cross-tenant read + narrow next_run_at advancement.
    op.execute(
        "CREATE POLICY schedules_sched_select ON schedules FOR SELECT TO nlw_scheduler USING (true)"
    )
    op.execute(
        "CREATE POLICY schedules_sched_update ON schedules FOR UPDATE TO nlw_scheduler "
        "USING (true) WITH CHECK (true)"
    )

    # --- workflow_runs: scheduler cross-tenant SELECT + INSERT ---
    op.execute(
        "CREATE POLICY workflow_runs_sched_select ON workflow_runs FOR SELECT "
        "TO nlw_scheduler USING (true)"
    )
    op.execute(
        "CREATE POLICY workflow_runs_sched_insert ON workflow_runs FOR INSERT "
        "TO nlw_scheduler WITH CHECK (true)"
    )

    # --- external_actions / approvals: scheduler cross-tenant SELECT (reconcile) ---
    op.execute(
        "CREATE POLICY ext_actions_sched_select ON external_actions FOR SELECT "
        "TO nlw_scheduler USING (true)"
    )
    op.execute(
        "CREATE POLICY approvals_sched_select ON approvals FOR SELECT TO nlw_scheduler USING (true)"
    )


def downgrade() -> None:
    for policy in ("ext_actions_sched_select",):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON external_actions")
    op.execute("DROP POLICY IF EXISTS approvals_sched_select ON approvals")
    for policy in ("workflow_runs_sched_insert", "workflow_runs_sched_select"):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON workflow_runs")

    op.execute("REVOKE ALL ON external_actions FROM nlw_scheduler")
    op.execute("REVOKE ALL ON approvals FROM nlw_scheduler")
    op.execute("REVOKE ALL ON workflow_runs FROM nlw_scheduler")

    op.drop_constraint("uq_run_schedule_occurrence", "workflow_runs", type_="unique")
    op.drop_constraint("fk_run_schedule", "workflow_runs", type_="foreignkey")
    op.drop_column("workflow_runs", "scheduled_for")
    op.drop_column("workflow_runs", "schedule_id")

    for policy in (
        "schedules_sched_update",
        "schedules_sched_select",
        "schedules_app_delete",
        "schedules_app_update",
        "schedules_app_insert",
        "schedules_app_select",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON schedules")
    op.execute("REVOKE ALL ON schedules FROM nlw_scheduler")
    op.execute("REVOKE ALL ON schedules FROM nlw_app")
    op.drop_index("ix_schedules_next_run_at", table_name="schedules")
    op.drop_index("ix_schedules_tenant_id", table_name="schedules")
    op.drop_table("schedules")
