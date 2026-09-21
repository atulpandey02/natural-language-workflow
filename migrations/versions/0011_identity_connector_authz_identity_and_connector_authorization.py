"""identity and connector authorization boundary (M11.5 P1A)

Close two verified authorization defects:

Part A — protect ``users`` (identity table had NO RLS; ``nlw_app`` held broad
SELECT/INSERT/UPDATE, so the runtime role could enumerate identities and rewrite
unrelated identity mappings including the stable ``auth_provider_id``):
- enable + FORCE RLS on ``users``;
- remove the broad direct grant; ``nlw_app`` keeps only self-scoped SELECT and a
  self-scoped, column-limited UPDATE(email) (RLS + column grant);
- first-login resolution moves into a *minimal* SECURITY DEFINER bootstrap
  ``resolve_or_create_user`` owned by the existing write-only non-login role
  ``nlw_workspace_bootstrap``. It returns ONLY the internal ``uuid`` id — never a
  row, email, or ``auth_provider_id`` — and on an existing identity it does
  NOTHING (``ON CONFLICT DO NOTHING``): it neither discloses nor mutates another
  user's record, so a caller under ``nlw_app`` supplying an arbitrary
  ``auth_provider_id`` learns at most that an id exists and can neither read that
  user's email/provider id nor change it. It is EXECUTE-only for ``nlw_app``
  (never worker/scheduler/PUBLIC). Worker and scheduler get no access to ``users``.
- email synchronization is a SEPARATE self-scoped operation done by the app AFTER
  ``app.user_id`` is established (self-only UPDATE policy + column-level
  UPDATE(email, updated_at) grant), using only the verified provider email.

NOTE (honest boundary): the DIRECT function-call guarantee above holds for any
``nlw_app`` caller. Protection against a caller that can FORGE a complete
authenticated DB context (e.g. arbitrarily set ``app.user_id``) is the deferred
signed/non-forgeable-GUC item (ADR-003) and is explicitly NOT provided here.

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
    # 1. The write-only, BYPASSRLS, non-login role owns the sole first-login
    #    INSERT path. It already exists (docker/postgres/initdb/00-roles.sh + the
    #    test bootstrap) and owns create_workspace_for_current_user (0005). The
    #    bootstrap only ever INSERTs a missing identity, so it needs SELECT+INSERT
    #    (no UPDATE): it must never be able to mutate an existing user.
    op.execute("GRANT SELECT, INSERT ON users TO nlw_workspace_bootstrap")

    # 2. MINIMAL first-login bootstrap. Returns ONLY the internal uuid id — never
    #    a row, email, or auth_provider_id — and on an existing identity does
    #    NOTHING (no read of its fields is returned, no write). So a caller under
    #    nlw_app that supplies an arbitrary auth_provider_id can neither read that
    #    user's email/provider id nor change it; at most it learns an id exists.
    #    Email synchronization is handled separately by the app, self-scoped,
    #    after app.user_id is established (see step 6 + the app repository).
    op.execute(
        """
        CREATE FUNCTION resolve_or_create_user(p_auth_provider_id text, p_email text)
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

                -- Fast path: established identity -> return its id. NO write.
                SELECT u.id INTO v_id
                    FROM public.users u
                    WHERE u.auth_provider_id = p_auth_provider_id;
                IF FOUND THEN
                    RETURN v_id;
                END IF;

                -- First login: insert the missing identity. ON CONFLICT DO
                -- NOTHING converges concurrent first-login races WITHOUT ever
                -- touching an existing row (no email/auth_provider_id change).
                INSERT INTO public.users (id, auth_provider_id, email, created_at, updated_at)
                    VALUES (pg_catalog.gen_random_uuid(), p_auth_provider_id, p_email,
                            pg_catalog.now(), pg_catalog.now())
                    ON CONFLICT (auth_provider_id) DO NOTHING
                    RETURNING id INTO v_id;

                IF v_id IS NULL THEN
                    -- Lost the race: another session inserted first. Read its id.
                    SELECT u.id INTO v_id
                        FROM public.users u
                        WHERE u.auth_provider_id = p_auth_provider_id;
                END IF;
                RETURN v_id;
            END;
            $fn$
        """
    )
    op.execute("ALTER FUNCTION resolve_or_create_user(text, text) OWNER TO nlw_workspace_bootstrap")
    op.execute("REVOKE ALL ON FUNCTION resolve_or_create_user(text, text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION resolve_or_create_user(text, text) TO nlw_app")

    # 3. Remove the broad direct grant. nlw_app keeps only (RLS-scoped) SELECT and
    #    a column-limited UPDATE(email) — never INSERT/DELETE, and never UPDATE of
    #    id/auth_provider_id/created_at (those columns are not granted).
    op.execute("REVOKE ALL ON users FROM nlw_app")
    op.execute("GRANT SELECT ON users TO nlw_app")
    op.execute("GRANT UPDATE (email, updated_at) ON users TO nlw_app")

    # 4. Enable + FORCE RLS (FORCE subjects the table owner too).
    op.execute("ALTER TABLE users ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE users FORCE ROW LEVEL SECURITY")

    # 5. Self-read only: a caller may read exactly their own row, and only once
    #    app.user_id is established. Absent/empty context -> NULL -> deny.
    op.execute(
        f"CREATE POLICY users_app_self_select ON users FOR SELECT TO nlw_app "
        f"USING (id = {_USER_GUC})"
    )

    # 6. Self-update only (email sync). Combined with the column grant above, a
    #    caller can update only their OWN row and only the email/updated_at
    #    columns. Absent/empty context -> NULL -> no row matches -> no-op.
    op.execute(
        f"CREATE POLICY users_app_self_update ON users FOR UPDATE TO nlw_app "
        f"USING (id = {_USER_GUC}) WITH CHECK (id = {_USER_GUC})"
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
    #
    # WARNING: this downgrade RE-OPENS the P1A defects — it restores the broad
    # nlw_app SELECT/INSERT/UPDATE on `users` (no RLS) and, above, the member-level
    # connector-insert policy. Do NOT run it on the live pilot without explicit
    # security review + compensating controls (see docs/runbooks/failed-migration.md
    # and the migration warning in docs).
    op.execute("DROP POLICY IF EXISTS users_app_self_update ON users")
    op.execute("DROP POLICY IF EXISTS users_app_self_select ON users")
    op.execute("ALTER TABLE users NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE users DISABLE ROW LEVEL SECURITY")

    op.execute("DROP FUNCTION IF EXISTS resolve_or_create_user(text, text)")
    op.execute("REVOKE ALL ON users FROM nlw_workspace_bootstrap")

    op.execute("REVOKE ALL ON users FROM nlw_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON users TO nlw_app")
