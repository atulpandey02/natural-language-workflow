"""harden m2 workspace membership policies

Close the cross-tenant / self-escalation gaps in the M2b (0003) policies:
- drop the forgeable tenant-only SELECT policies on workspaces/memberships;
- remove ALL direct workspaces/memberships writes from nlw_app (SELECT only);
- create a workspace + its sole owner membership only via a narrow, atomic
  SECURITY DEFINER bootstrap function owned by the write-only non-login role
  nlw_workspace_bootstrap (which cannot add a caller to an existing workspace);
- app SELECT is membership-bound (via is_current_user_member from 0004).

0003 is left untouched; downgrade restores its exact policies and grants.

Revision ID: 0005_harden_m2_policies
Revises: 0004_workflow_execution
Create Date: 2026-09-19
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005_harden_m2_policies"
down_revision: str | Sequence[str] | None = "0004_workflow_execution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_USER_GUC = "NULLIF(current_setting('app.user_id', true), '')::uuid"
_TENANT_GUC = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"

_OLD_POLICIES = (
    ("memberships", "memberships_self_select"),
    ("memberships", "memberships_tenant_select"),
    ("memberships", "memberships_self_insert"),
    ("workspaces", "workspaces_member_select"),
    ("workspaces", "workspaces_tenant_select"),
    ("workspaces", "workspaces_insert"),
)


def upgrade() -> None:
    # 1. Drop the 0003 PUBLIC policies (incl. the forgeable tenant-only ones).
    for table, policy in _OLD_POLICIES:
        op.execute(f"DROP POLICY IF EXISTS {policy} ON {table}")

    # 2. nlw_app becomes SELECT-only on both tables (no direct membership writes).
    op.execute("REVOKE INSERT, UPDATE, DELETE ON workspaces FROM nlw_app")
    op.execute("REVOKE INSERT, UPDATE, DELETE ON memberships FROM nlw_app")

    # 3. Write-only bootstrap role gets INSERT; the function (owned by it) is the
    #    ONLY membership-write path.
    op.execute("GRANT INSERT ON workspaces TO nlw_workspace_bootstrap")
    op.execute("GRANT INSERT ON memberships TO nlw_workspace_bootstrap")
    op.execute(
        """
        CREATE FUNCTION create_workspace_for_current_user(p_name text, p_slug text)
            RETURNS uuid
            LANGUAGE plpgsql
            VOLATILE
            SECURITY DEFINER
            SET search_path = pg_catalog
            AS $$
            DECLARE
                v_user uuid := NULLIF(current_setting('app.user_id', true), '')::uuid;
                v_id   uuid := pg_catalog.gen_random_uuid();
            BEGIN
                IF v_user IS NULL THEN
                    RAISE EXCEPTION 'no authenticated user in context';
                END IF;
                INSERT INTO public.workspaces (id, name, slug, created_at, updated_at)
                    VALUES (v_id, p_name, p_slug, pg_catalog.now(), pg_catalog.now());
                INSERT INTO public.memberships
                        (id, user_id, workspace_id, role, created_at, updated_at)
                    VALUES (pg_catalog.gen_random_uuid(), v_user, v_id, 'owner',
                            pg_catalog.now(), pg_catalog.now());
                RETURN v_id;
            END;
            $$
        """
    )
    op.execute(
        "ALTER FUNCTION create_workspace_for_current_user(text, text) "
        "OWNER TO nlw_workspace_bootstrap"
    )
    op.execute("REVOKE ALL ON FUNCTION create_workspace_for_current_user(text, text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION create_workspace_for_current_user(text, text) TO nlw_app")

    # 4. Membership-bound, role-specific SELECT policies for nlw_app.
    op.execute(
        "CREATE POLICY workspaces_app_select ON workspaces FOR SELECT TO nlw_app "
        "USING (public.is_current_user_member(id))"
    )
    op.execute(
        f"CREATE POLICY memberships_app_select ON memberships FOR SELECT TO nlw_app "
        f"USING (user_id = {_USER_GUC})"
    )


def downgrade() -> None:
    # Reverse in mirror order, restoring the exact 0003 state.
    op.execute("DROP POLICY IF EXISTS memberships_app_select ON memberships")
    op.execute("DROP POLICY IF EXISTS workspaces_app_select ON workspaces")

    op.execute("DROP FUNCTION IF EXISTS create_workspace_for_current_user(text, text)")
    op.execute("REVOKE INSERT ON memberships FROM nlw_workspace_bootstrap")
    op.execute("REVOKE INSERT ON workspaces FROM nlw_workspace_bootstrap")

    # Restore 0003 grants for nlw_app.
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON workspaces TO nlw_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON memberships TO nlw_app")

    # Recreate the exact 0003 policies.
    op.execute(
        f"CREATE POLICY memberships_self_select ON memberships FOR SELECT "
        f"USING (user_id = {_USER_GUC})"
    )
    op.execute(
        f"CREATE POLICY memberships_tenant_select ON memberships FOR SELECT "
        f"USING (workspace_id = {_TENANT_GUC})"
    )
    op.execute(
        f"CREATE POLICY memberships_self_insert ON memberships FOR INSERT "
        f"WITH CHECK (user_id = {_USER_GUC})"
    )
    op.execute(
        f"CREATE POLICY workspaces_member_select ON workspaces FOR SELECT "
        f"USING (id IN (SELECT m.workspace_id FROM memberships m WHERE m.user_id = {_USER_GUC}))"
    )
    op.execute(
        f"CREATE POLICY workspaces_tenant_select ON workspaces FOR SELECT "
        f"USING (id = {_TENANT_GUC})"
    )
    op.execute("CREATE POLICY workspaces_insert ON workspaces FOR INSERT WITH CHECK (true)")
