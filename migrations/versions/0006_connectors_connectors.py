"""connectors

Tenant-owned connectors (M4). config is non-secret; secret_ref is a pointer into
the SecretStore, never a secret value. Role-specific RLS (no PUBLIC), reusing
is_current_user_member (0004):
- nlw_app:    SELECT, INSERT (membership-bound). No UPDATE/DELETE in M4.
- nlw_worker: SELECT + UPDATE(status, updated_at) only (tenant-only), for
              worker-side health status transitions.

Revision ID: 0006_connectors
Revises: 0005_harden_m2_policies
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_connectors"
down_revision: str | Sequence[str] | None = "0005_harden_m2_policies"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_GUC = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_APP = f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_member(tenant_id))"
_WRK = f"(tenant_id = {_TENANT_GUC})"


def upgrade() -> None:
    op.create_table(
        "connectors",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("secret_ref", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="unchecked"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("tenant_id", "name", name="uq_connector_tenant_name"),
        sa.CheckConstraint(
            "status in ('unchecked','active','error','disabled')", name="ck_connector_status"
        ),
    )
    op.create_index("ix_connectors_tenant_id", "connectors", ["tenant_id"])

    # Grants (least privilege).
    op.execute("GRANT SELECT, INSERT ON connectors TO nlw_app")
    op.execute("GRANT SELECT ON connectors TO nlw_worker")
    op.execute("GRANT UPDATE (status, updated_at) ON connectors TO nlw_worker")

    # RLS: enable + FORCE; role-specific policies (no PUBLIC).
    op.execute("ALTER TABLE connectors ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE connectors FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY connectors_app_select ON connectors FOR SELECT TO nlw_app USING {_APP}"
    )
    op.execute(
        f"CREATE POLICY connectors_app_insert ON connectors FOR INSERT TO nlw_app WITH CHECK {_APP}"
    )
    op.execute(
        f"CREATE POLICY connectors_worker_select ON connectors FOR SELECT "
        f"TO nlw_worker USING {_WRK}"
    )
    op.execute(
        f"CREATE POLICY connectors_worker_update ON connectors FOR UPDATE "
        f"TO nlw_worker USING {_WRK} WITH CHECK {_WRK}"
    )


def downgrade() -> None:
    for policy in (
        "connectors_worker_update",
        "connectors_worker_select",
        "connectors_app_insert",
        "connectors_app_select",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON connectors")
    op.execute("ALTER TABLE connectors NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE connectors DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_connectors_tenant_id", table_name="connectors")
    op.drop_table("connectors")
