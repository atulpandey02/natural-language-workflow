"""rls isolation

Grant the restricted runtime role (nlw_app) DML privileges, then enable + FORCE
Row-Level Security on the tenant tables with policies keyed off two
transaction-local GUCs:

- app.user_id   set right after authentication (identity)
- app.tenant_id set only after membership is confirmed (active tenant)

Policies (permissive, OR'd):
- memberships: SELECT own (user_id = app.user_id) OR tenant (workspace_id = app.tenant_id);
               INSERT own (user_id = app.user_id).
- workspaces:  SELECT if a member (via memberships) OR tenant (id = app.tenant_id);
               INSERT allowed for any authenticated user (tenant bootstrap).
- users:       global identity, no RLS.

When a GUC is unset, current_setting(..., true) is NULL and every comparison is
false, so access is denied by default.

The role itself is created by bootstrap (docker init / CI step), never here.

Revision ID: 0003_rls_isolation
Revises: 0002_identity_tenancy
Create Date: 2026-09-18
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003_rls_isolation"
down_revision: str | Sequence[str] | None = "0002_identity_tenancy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_APP_ROLE = "nlw_app"


def upgrade() -> None:
    # DML privileges for the restricted runtime role.
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON users TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON workspaces TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON memberships TO {_APP_ROLE}")

    # Enable + FORCE RLS on tenant tables (FORCE subjects the owner too).
    for table in ("workspaces", "memberships"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    # current_setting is wrapped in NULLIF(..., '') because a connection that
    # previously ran SET LOCAL leaves the GUC's reset value as '' (not NULL);
    # on a reused pooled connection ''::uuid would raise. Empty -> NULL -> deny.
    user_guc = "NULLIF(current_setting('app.user_id', true), '')::uuid"
    tenant_guc = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"

    # memberships policies
    op.execute(
        f"CREATE POLICY memberships_self_select ON memberships FOR SELECT "
        f"USING (user_id = {user_guc})"
    )
    op.execute(
        f"CREATE POLICY memberships_tenant_select ON memberships FOR SELECT "
        f"USING (workspace_id = {tenant_guc})"
    )
    op.execute(
        f"CREATE POLICY memberships_self_insert ON memberships FOR INSERT "
        f"WITH CHECK (user_id = {user_guc})"
    )

    # workspaces policies
    op.execute(
        f"CREATE POLICY workspaces_member_select ON workspaces FOR SELECT "
        f"USING (id IN (SELECT m.workspace_id FROM memberships m WHERE m.user_id = {user_guc}))"
    )
    op.execute(
        f"CREATE POLICY workspaces_tenant_select ON workspaces FOR SELECT USING (id = {tenant_guc})"
    )
    op.execute("CREATE POLICY workspaces_insert ON workspaces FOR INSERT WITH CHECK (true)")


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS workspaces_insert ON workspaces")
    op.execute("DROP POLICY IF EXISTS workspaces_tenant_select ON workspaces")
    op.execute("DROP POLICY IF EXISTS workspaces_member_select ON workspaces")
    op.execute("DROP POLICY IF EXISTS memberships_self_insert ON memberships")
    op.execute("DROP POLICY IF EXISTS memberships_tenant_select ON memberships")
    op.execute("DROP POLICY IF EXISTS memberships_self_select ON memberships")

    for table in ("workspaces", "memberships"):
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.execute(f"REVOKE ALL ON memberships FROM {_APP_ROLE}")
    op.execute(f"REVOKE ALL ON workspaces FROM {_APP_ROLE}")
    op.execute(f"REVOKE ALL ON users FROM {_APP_ROLE}")
