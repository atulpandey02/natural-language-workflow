"""Workspace-creation grants: founding a tenant requires an operator grant.

Phase 2 plan, section 0.5 (B01). Before this revision
``create_workspace_for_current_user`` checked only that a user was in the signed
context, so any identity the auth provider could mint was able to found an
unlimited number of tenants. The database is now the authority:

- ``workspace_creation_grants`` is a PLATFORM table (not tenant-scoped, no RLS,
  like ``ctx_keys``). No login role holds any privilege on it; only the
  NOLOGIN function owner ``nlw_workspace_bootstrap`` may read and update it, and
  only through the SECURITY DEFINER functions below. Operators add and revoke
  grants with the owner credential (``python -m nlw.ops.grants``).
- ``create_workspace_for_current_user`` is replaced IN PLACE (same signature, so
  no ungated overload survives): it locks one unconsumed, unrevoked, unexpired
  grant for the caller's email FOR UPDATE, raises SQLSTATE 42501 if there is
  none, creates the workspace and owner membership, consumes the grant and
  appends ``workspace.created`` to ``authz_audit_events`` in one transaction.
- ``has_workspace_creation_grant()`` is a read-only pre-check the API uses to
  answer 403 before attempting the bootstrap. It reveals only whether the
  CALLER holds a usable grant.
- ``resolve_or_create_user`` additionally appends ``identity.provisioned`` when
  (and only when) it inserts a new identity. Its lookup/insert behaviour is
  unchanged.

Invitations are unaffected: ``accept_workspace_invitation`` remains the path to
JOIN an existing workspace.

Revision ID: 0022_workspace_creation_grants
Revises: 0021_analytics_handoff
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0022_workspace_creation_grants"
down_revision: str | Sequence[str] | None = "0021_analytics_handoff"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CREATE_TABLE = """
CREATE TABLE workspace_creation_grants (
    id uuid PRIMARY KEY,
    email_normalized text NOT NULL
        CHECK (email_normalized = lower(btrim(email_normalized))
               AND length(email_normalized) BETWEEN 3 AND 320
               AND position('@' IN email_normalized) > 1),
    granted_by text NOT NULL CHECK (length(btrim(granted_by)) BETWEEN 1 AND 200),
    note text CHECK (note IS NULL OR length(note) <= 200),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_by text CHECK (revoked_by IS NULL OR length(btrim(revoked_by)) BETWEEN 1 AND 200),
    consumed_at timestamptz,
    consumed_by_user_id uuid,
    consumed_workspace_id uuid,
    CHECK (expires_at > created_at),
    CHECK ((consumed_at IS NULL) = (consumed_workspace_id IS NULL)),
    CHECK ((consumed_at IS NULL) = (consumed_by_user_id IS NULL)),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    CHECK (NOT (consumed_at IS NOT NULL AND revoked_at IS NOT NULL))
)
"""

# At most one OPEN (unconsumed, unrevoked) grant per email: consumption is
# unambiguous and an operator cannot stack grants by accident.
_OPEN_UNIQUE = (
    "CREATE UNIQUE INDEX uq_workspace_creation_grant_open "
    "ON workspace_creation_grants (email_normalized) "
    "WHERE consumed_at IS NULL AND revoked_at IS NULL"
)

_SQL_CREATE_WORKSPACE_GRANTED = """
CREATE OR REPLACE FUNCTION create_workspace_for_current_user(p_name text, p_slug text)
    RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
    AS $$
    DECLARE
        v_user  uuid := public.ctx_user_id();
        v_id    uuid := pg_catalog.gen_random_uuid();
        v_email text;
        v_grant uuid;
    BEGIN
        IF v_user IS NULL THEN
            RAISE EXCEPTION 'no authenticated user in context';
        END IF;
        SELECT lower(btrim(email)) INTO v_email FROM public.users WHERE id = v_user;
        IF v_email IS NULL THEN
            RAISE EXCEPTION 'workspace creation not granted' USING ERRCODE = '42501';
        END IF;
        SELECT g.id INTO v_grant FROM public.workspace_creation_grants g
            WHERE g.email_normalized = v_email
              AND g.consumed_at IS NULL
              AND g.revoked_at IS NULL
              AND g.expires_at > pg_catalog.now()
            FOR UPDATE;
        IF v_grant IS NULL THEN
            RAISE EXCEPTION 'workspace creation not granted' USING ERRCODE = '42501';
        END IF;
        INSERT INTO public.workspaces (id, name, slug, created_at, updated_at)
            VALUES (v_id, p_name, p_slug, pg_catalog.now(), pg_catalog.now());
        INSERT INTO public.memberships
                (id, user_id, workspace_id, role, created_at, updated_at)
            VALUES (pg_catalog.gen_random_uuid(), v_user, v_id, 'owner',
                    pg_catalog.now(), pg_catalog.now());
        UPDATE public.workspace_creation_grants
            SET consumed_at = pg_catalog.now(),
                consumed_by_user_id = v_user,
                consumed_workspace_id = v_id
            WHERE id = v_grant AND consumed_at IS NULL AND revoked_at IS NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'workspace creation not granted' USING ERRCODE = '42501';
        END IF;
        INSERT INTO public.authz_audit_events
                (id, tenant_id, event_type, actor_user_id, subject_id, detail, created_at)
            VALUES (pg_catalog.gen_random_uuid(), v_id, 'workspace.created', v_user, v_id,
                    v_grant::text, pg_catalog.now());
        RETURN v_id;
    END;
    $$
"""

# The pre-0022 body (0016), restored by downgrade only.
_SQL_CREATE_WORKSPACE_0016 = """
CREATE OR REPLACE FUNCTION create_workspace_for_current_user(p_name text, p_slug text)
    RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
    AS $$
    DECLARE
        v_user uuid := public.ctx_user_id();
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

_SQL_HAS_GRANT = """
CREATE FUNCTION has_workspace_creation_grant() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
    AS $$
        SELECT EXISTS (
            SELECT 1
            FROM public.users u
            JOIN public.workspace_creation_grants g
              ON g.email_normalized = lower(btrim(u.email))
            WHERE u.id = public.ctx_user_id()
              AND g.consumed_at IS NULL
              AND g.revoked_at IS NULL
              AND g.expires_at > pg_catalog.now()
        )
    $$
"""

_RESOLVE_TEMPLATE = """
CREATE OR REPLACE FUNCTION resolve_or_create_user(p_auth_provider_id text, p_email text)
    RETURNS uuid
    LANGUAGE plpgsql
    VOLATILE
    SECURITY DEFINER
    SET search_path = pg_catalog
    AS $fn$
    DECLARE
        v_id uuid;
    BEGIN
        IF p_auth_provider_id IS NULL OR p_auth_provider_id = '' THEN
            RAISE EXCEPTION 'auth_provider_id is required';
        END IF;
        IF p_email IS NULL OR p_email = '' THEN
            RAISE EXCEPTION 'email is required';
        END IF;

        SELECT u.id INTO v_id
            FROM public.users u
            WHERE u.auth_provider_id = p_auth_provider_id;
        IF FOUND THEN
            RETURN v_id;
        END IF;

        INSERT INTO public.users (id, auth_provider_id, email, created_at, updated_at)
            VALUES (pg_catalog.gen_random_uuid(), p_auth_provider_id, p_email,
                    pg_catalog.now(), pg_catalog.now())
            ON CONFLICT (auth_provider_id) DO NOTHING
            RETURNING id INTO v_id;

        IF v_id IS NULL THEN
            SELECT u.id INTO v_id
                FROM public.users u
                WHERE u.auth_provider_id = p_auth_provider_id;
        {AUDIT}END IF;
        RETURN v_id;
    END;
    $fn$
"""
# Only the session whose INSERT won appends the event (the race loser reads the
# existing id). Tenant-less: provisioning belongs to no workspace yet.
_PROVISIONED_AUDIT = """ELSE
            INSERT INTO public.authz_audit_events
                    (id, tenant_id, event_type, actor_user_id, subject_id, created_at)
                VALUES (pg_catalog.gen_random_uuid(), NULL, 'identity.provisioned',
                        v_id, v_id, pg_catalog.now());
        """
_SQL_RESOLVE_AUDITED = _RESOLVE_TEMPLATE.replace("{AUDIT}", _PROVISIONED_AUDIT)
_SQL_RESOLVE_0011 = _RESOLVE_TEMPLATE.replace("{AUDIT}", "")


def upgrade() -> None:
    op.execute(_CREATE_TABLE)
    op.execute(_OPEN_UNIQUE)
    op.execute("REVOKE ALL ON workspace_creation_grants FROM PUBLIC")
    # Function owner only; no login role (nlw_app/worker/scheduler) is granted.
    op.execute("GRANT SELECT, UPDATE ON workspace_creation_grants TO nlw_workspace_bootstrap")

    op.execute(_SQL_CREATE_WORKSPACE_GRANTED)
    op.execute(_SQL_HAS_GRANT)
    op.execute("ALTER FUNCTION has_workspace_creation_grant() OWNER TO nlw_workspace_bootstrap")
    op.execute("REVOKE ALL ON FUNCTION has_workspace_creation_grant() FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION has_workspace_creation_grant() TO nlw_app")

    op.execute(_SQL_RESOLVE_AUDITED)


def downgrade() -> None:
    op.execute(_SQL_RESOLVE_0011)
    op.execute("DROP FUNCTION IF EXISTS has_workspace_creation_grant()")
    op.execute(_SQL_CREATE_WORKSPACE_0016)
    op.execute("DROP TABLE IF EXISTS workspace_creation_grants")
