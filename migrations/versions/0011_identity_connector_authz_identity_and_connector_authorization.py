"""identity and connector authorization boundary (M11.5 P1A)

Close two verified authorization defects:

Part A — protect ``users`` (identity table had NO RLS; ``nlw_app`` held broad
SELECT/INSERT/UPDATE, so the runtime role could enumerate identities and rewrite
unrelated identity mappings including the stable ``auth_provider_id``):
- enable + FORCE RLS on ``users``;
- remove the broad direct grant; ``nlw_app`` keeps only self-scoped SELECT (RLS);
- first-login resolution/provisioning moves into a narrow SECURITY DEFINER
  bootstrap function ``resolve_or_create_user`` owned by the existing write-only
  non-login role ``nlw_workspace_bootstrap`` (the only user-write path). It never
  reassigns an existing ``auth_provider_id`` and syncs email only when the
  verified provider email actually changed. It is EXECUTE-only for ``nlw_app``
  (never worker/scheduler/PUBLIC). Worker and scheduler get no access to
  ``users`` (no demonstrated runtime requirement).

Part B — connector mutation authority (any member could create a connector and
supply a credential alias): the ``connectors`` INSERT policy for ``nlw_app`` now
requires ``is_current_user_admin_or_owner`` instead of ``is_current_user_member``
(mirrors the ``schedules`` admin-mutate pattern from 0009). Read stays member.

This does NOT provide signed/non-forgeable DB request context (out of scope).

0003/0006 are left untouched; downgrade restores their exact prior grants and
policies on ``users`` and ``connectors``.

Revision ID: 0011_identity_connector_authz
Revises: 0010_readiness_schema_grant
Create Date: 2026-09-20
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0011_identity_connector_authz"
down_revision: str | Sequence[str] | None = "0010_readiness_schema_grant"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_USER_GUC = "NULLIF(current_setting('app.user_id', true), '')::uuid"
_TENANT_GUC = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"

# connectors predicates (mirror 0006/0009 macros)
_CONN_MEMBER = f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_member(tenant_id))"
_CONN_ADMIN = f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_admin_or_owner(tenant_id))"


def upgrade() -> None:
    # ---------------------------------------------------------------- Part A --
    # 1. The write-only, BYPASSRLS, non-login role owns the sole user-write path.
    #    It already exists (created in docker/postgres/initdb/00-roles.sh and the
    #    test bootstrap) and owns create_workspace_for_current_user (0005). Grant
    #    it the table privileges the definer function needs (BYPASSRLS bypasses
    #    RLS policies, not GRANTs).
    op.execute("GRANT SELECT, INSERT, UPDATE ON users TO nlw_workspace_bootstrap")

    # 2. Narrow first-login bootstrap. Read-first so an established, unchanged
    #    identity does NOT incur a write or a row lock; ON CONFLICT converges
    #    concurrent first-login races onto exactly one row. auth_provider_id is
    #    the conflict key and is NEVER in a SET clause -> immutable via this
    #    function; direct UPDATE is revoked, so it is immutable to nlw_app.
    op.execute(
        """
        CREATE FUNCTION resolve_or_create_user(p_auth_provider_id text, p_email text)
            RETURNS SETOF public.users
            LANGUAGE plpgsql
            VOLATILE
            SECURITY DEFINER
            SET search_path = pg_catalog
            AS $fn$
            DECLARE
                v_email text;
            BEGIN
                IF p_auth_provider_id IS NULL OR p_auth_provider_id = '' THEN
                    RAISE EXCEPTION 'auth_provider_id is required';
                END IF;
                IF p_email IS NULL OR p_email = '' THEN
                    RAISE EXCEPTION 'email is required';
                END IF;

                -- Fast path: established identity. Plain read, no write, no lock.
                SELECT u.email INTO v_email
                    FROM public.users u
                    WHERE u.auth_provider_id = p_auth_provider_id;

                IF FOUND THEN
                    -- Narrow email sync: write ONLY when the verified provider
                    -- email actually changed. auth_provider_id is not touched.
                    IF v_email IS DISTINCT FROM p_email THEN
                        UPDATE public.users u
                            SET email = p_email, updated_at = pg_catalog.now()
                            WHERE u.auth_provider_id = p_auth_provider_id;
                    END IF;
                    RETURN QUERY
                        SELECT u.* FROM public.users u
                            WHERE u.auth_provider_id = p_auth_provider_id;
                    RETURN;
                END IF;

                -- First login: create exactly one row. ON CONFLICT makes
                -- concurrent first-login callers converge; the DO UPDATE never
                -- reassigns auth_provider_id and only writes email when changed.
                INSERT INTO public.users (id, auth_provider_id, email, created_at, updated_at)
                    VALUES (pg_catalog.gen_random_uuid(), p_auth_provider_id, p_email,
                            pg_catalog.now(), pg_catalog.now())
                    ON CONFLICT (auth_provider_id) DO UPDATE
                        SET email = excluded.email, updated_at = pg_catalog.now()
                        WHERE public.users.email IS DISTINCT FROM excluded.email;

                RETURN QUERY
                    SELECT u.* FROM public.users u
                        WHERE u.auth_provider_id = p_auth_provider_id;
            END;
            $fn$
        """
    )
    op.execute("ALTER FUNCTION resolve_or_create_user(text, text) OWNER TO nlw_workspace_bootstrap")
    op.execute("REVOKE ALL ON FUNCTION resolve_or_create_user(text, text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION resolve_or_create_user(text, text) TO nlw_app")

    # 3. Remove the broad direct grant; nlw_app keeps only (RLS-scoped) SELECT.
    #    No INSERT/UPDATE/DELETE grant -> all direct writes fail closed; the
    #    definer function is the only write path.
    op.execute("REVOKE ALL ON users FROM nlw_app")
    op.execute("GRANT SELECT ON users TO nlw_app")

    # 4. Enable + FORCE RLS (FORCE subjects the table owner too).
    op.execute("ALTER TABLE users ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE users FORCE ROW LEVEL SECURITY")

    # 5. Self-read only: a caller may read exactly their own row, and only once
    #    app.user_id is established. Absent/empty context -> NULL -> deny.
    op.execute(
        f"CREATE POLICY users_app_self_select ON users FOR SELECT TO nlw_app "
        f"USING (id = {_USER_GUC})"
    )

    # ---------------------------------------------------------------- Part B --
    # Connector creation requires admin/owner (was: any member). Read unchanged.
    op.execute("DROP POLICY IF EXISTS connectors_app_insert ON connectors")
    op.execute(
        f"CREATE POLICY connectors_app_insert ON connectors FOR INSERT TO nlw_app "
        f"WITH CHECK {_CONN_ADMIN}"
    )


def downgrade() -> None:
    # Reverse in mirror order, restoring the exact 0006/0003 state.

    # ---- Part B: restore member-level connector INSERT (0006). ----
    op.execute("DROP POLICY IF EXISTS connectors_app_insert ON connectors")
    op.execute(
        f"CREATE POLICY connectors_app_insert ON connectors FOR INSERT TO nlw_app "
        f"WITH CHECK {_CONN_MEMBER}"
    )

    # ---- Part A: restore the 0003 users posture (no RLS, broad grant). ----
    op.execute("DROP POLICY IF EXISTS users_app_self_select ON users")
    op.execute("ALTER TABLE users NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE users DISABLE ROW LEVEL SECURITY")

    op.execute("DROP FUNCTION IF EXISTS resolve_or_create_user(text, text)")
    op.execute("REVOKE ALL ON users FROM nlw_workspace_bootstrap")

    op.execute("REVOKE ALL ON users FROM nlw_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON users TO nlw_app")
