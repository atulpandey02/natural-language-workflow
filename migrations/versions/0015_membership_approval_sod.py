"""membership invitations + approval separation of duties (M11.5 P3A)

Adds the product + authorization primitives for a second real user and a genuine
human-approval gate:

- ``workspace_invitations`` — hashed single-use invite tokens (only the sha256
  hash is stored; the raw token is returned once at creation). Acceptance is an
  atomic SECURITY DEFINER function (the accepter is not yet a member, so RLS on
  memberships/invitations cannot let ``nlw_app`` do it directly).
- Owner-preservation invariant — a constraint trigger that locks the workspace
  row and refuses any change leaving a workspace with zero owners (protects the
  final owner against demote/remove, including under concurrency).
- Membership administration — admin/owner may change roles / remove members via
  RLS-gated ``nlw_app`` writes; admins cannot touch owner rows (owner-only).
- Approval separation of duties — ``approvals.requested_by_user_id`` (immutable,
  set by the worker from run provenance) plus a DB-enforced four-eyes rule in the
  RLS ``WITH CHECK``: the decider must be an admin/owner, must stamp themselves,
  and must NOT be the requester. Legacy approvals with an unknown requester fail
  closed for decision.
- ``workflow_runs.initiated_by_user_id`` — the authenticated manual-run creator
  (scheduled runs keep NULL here; ``schedules.created_by`` is authoritative).
- ``authz_audit_events`` — append-only, tenant-scoped audit (no tokens/secrets).

Reversible. Downgrade WARNING: dropping the SoD ``WITH CHECK`` and the owner
trigger re-opens self-approval and final-owner removal — do not downgrade a
database that has relied on these invariants without an operator review.

Revision ID: 0015_membership_approval_sod
Revises: 0014_dr_restore_events
Create Date: 2026-09-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_membership_approval_sod"
down_revision: str | Sequence[str] | None = "0014_dr_restore_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_GUC = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_USER_GUC = "NULLIF(current_setting('app.user_id', true), '')::uuid"
_ADMIN = f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_admin_or_owner(tenant_id))"


def upgrade() -> None:
    # --- owner helper (read-only SECURITY DEFINER), mirrors is_current_user_admin_or_owner ---
    op.execute(
        """
        CREATE FUNCTION is_current_user_owner(p_tenant_id uuid) RETURNS boolean
            LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
            AS $$
                SELECT EXISTS (
                    SELECT 1 FROM public.memberships m
                    WHERE m.user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
                      AND m.workspace_id = p_tenant_id
                      AND m.role = 'owner'
                )
            $$
        """
    )
    op.execute("ALTER FUNCTION is_current_user_owner(uuid) OWNER TO nlw_rls_bypass")
    op.execute("REVOKE ALL ON FUNCTION is_current_user_owner(uuid) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION is_current_user_owner(uuid) TO nlw_app")

    # --- owner-preservation invariant (a workspace always has >= 1 owner) ---
    # A CHECK cannot span rows; a constraint trigger that LOCKS the workspace row
    # serializes concurrent membership changes for that workspace, so two parallel
    # "demote/remove the last owner" transactions cannot both succeed.
    op.execute(
        """
        CREATE FUNCTION enforce_workspace_owner_present() RETURNS trigger
            LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
            AS $$
            DECLARE
                v_ws uuid := COALESCE(OLD.workspace_id, NEW.workspace_id);
                v_owners int;
            BEGIN
                -- Serialize concurrent membership changes for this workspace via a
                -- transaction-scoped advisory lock keyed on the workspace id. This
                -- needs NO table privilege (unlike SELECT ... FOR UPDATE on
                -- workspaces), keeping the trigger owner's grants minimal.
                PERFORM pg_catalog.pg_advisory_xact_lock(
                    pg_catalog.hashtextextended(v_ws::text, 0)
                );
                SELECT count(*) INTO v_owners FROM public.memberships
                    WHERE workspace_id = v_ws AND role = 'owner';
                IF v_owners = 0 THEN
                    RAISE EXCEPTION 'workspace % would have no owner', v_ws
                        USING ERRCODE = 'check_violation';
                END IF;
                RETURN NULL;
            END;
            $$
        """
    )
    op.execute("ALTER FUNCTION enforce_workspace_owner_present() OWNER TO nlw_rls_bypass")
    # A trigger function needs no EXECUTE grant (it runs as the definer via the
    # trigger); revoke PUBLIC EXECUTE so no role can call it directly.
    op.execute("REVOKE ALL ON FUNCTION enforce_workspace_owner_present() FROM PUBLIC")
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER trg_workspace_owner_present
            AFTER UPDATE OR DELETE ON memberships
            DEFERRABLE INITIALLY IMMEDIATE
            FOR EACH ROW EXECUTE FUNCTION enforce_workspace_owner_present()
        """
    )

    # --- membership administration by admin/owner (RLS-gated nlw_app writes) ---
    # An admin may manage MEMBER/ADMIN rows; only an OWNER may touch an owner row
    # (promote-to-owner, demote/remove an owner). The trigger above still guards
    # the final owner. Creating a membership stays function-only (bootstrap/accept).
    op.execute("GRANT UPDATE (role, updated_at), DELETE ON memberships TO nlw_app")
    # memberships has no tenant_id column — its workspace_id IS the tenant.
    _MEM_ADMIN = "(public.is_current_user_admin_or_owner(workspace_id))"
    _MEM_TARGET = "(role <> 'owner' OR public.is_current_user_owner(workspace_id))"
    op.execute(
        f"CREATE POLICY memberships_app_admin_update ON memberships FOR UPDATE TO nlw_app "
        f"USING ({_MEM_ADMIN} AND {_MEM_TARGET}) "
        f"WITH CHECK ({_MEM_ADMIN} AND {_MEM_TARGET})"
    )
    op.execute(
        f"CREATE POLICY memberships_app_admin_delete ON memberships FOR DELETE TO nlw_app "
        f"USING ({_MEM_ADMIN} AND {_MEM_TARGET})"
    )
    # Co-members may see the roster of their active workspace (product policy).
    op.execute(
        "CREATE POLICY memberships_app_tenant_select ON memberships FOR SELECT TO nlw_app "
        f"USING (workspace_id = {_TENANT_GUC} AND public.is_current_user_member(workspace_id))"
    )

    # --- workspace_invitations ---
    op.create_table(
        "workspace_invitations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        # Normalized (lower+trim) invited email. Never the raw token.
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column(
            "invited_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        # sha256 hex of the high-entropy raw token. ONLY the hash is stored.
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "accepted_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
        ),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("role in ('admin','member')", name="ck_invitation_role"),
        sa.CheckConstraint(
            "status in ('pending','accepted','revoked','expired')", name="ck_invitation_status"
        ),
        sa.UniqueConstraint("token_hash", name="uq_invitation_token_hash"),
    )
    op.create_index("ix_invitations_tenant_id", "workspace_invitations", ["tenant_id"])
    # At most one PENDING invitation per (workspace, email) — conflict-safe duplicates.
    op.execute(
        "CREATE UNIQUE INDEX uq_invitation_pending_email ON workspace_invitations "
        "(tenant_id, email) WHERE status = 'pending'"
    )

    op.execute("GRANT SELECT, INSERT ON workspace_invitations TO nlw_app")
    op.execute("GRANT UPDATE (status, updated_at) ON workspace_invitations TO nlw_app")
    op.execute("GRANT SELECT, UPDATE ON workspace_invitations TO nlw_workspace_bootstrap")
    op.execute("ALTER TABLE workspace_invitations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE workspace_invitations FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY invitations_app_select ON workspace_invitations FOR SELECT TO nlw_app "
        f"USING {_ADMIN}"
    )
    op.execute(
        f"CREATE POLICY invitations_app_insert ON workspace_invitations FOR INSERT TO nlw_app "
        f"WITH CHECK ({_ADMIN} AND invited_by = {_USER_GUC})"
    )
    op.execute(
        f"CREATE POLICY invitations_app_update ON workspace_invitations FOR UPDATE TO nlw_app "
        f"USING {_ADMIN} WITH CHECK {_ADMIN}"
    )

    # --- append-only authorization audit (no tokens/secrets/payloads) ---
    op.create_table(
        "authz_audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("subject_id", sa.Uuid(), nullable=True),
        sa.Column("detail", sa.String(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_authz_audit_tenant_id", "authz_audit_events", ["tenant_id"])
    op.execute("GRANT SELECT, INSERT ON authz_audit_events TO nlw_app")
    op.execute("GRANT INSERT ON authz_audit_events TO nlw_workspace_bootstrap")
    op.execute("ALTER TABLE authz_audit_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE authz_audit_events FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY authz_audit_app_select ON authz_audit_events FOR SELECT TO nlw_app "
        f"USING {_ADMIN}"
    )
    op.execute(
        f"CREATE POLICY authz_audit_app_insert ON authz_audit_events FOR INSERT TO nlw_app "
        f"WITH CHECK (tenant_id = {_TENANT_GUC})"
    )

    # --- single-use atomic invitation acceptance (accepter is not yet a member) ---
    op.execute(
        """
        CREATE FUNCTION accept_workspace_invitation(p_token_hash text) RETURNS uuid
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
            AS $$
            DECLARE
                v_user uuid := NULLIF(current_setting('app.user_id', true), '')::uuid;
                v_email text;
                v_inv public.workspace_invitations%ROWTYPE;
            BEGIN
                IF v_user IS NULL THEN
                    RAISE EXCEPTION 'no authenticated user in context';
                END IF;
                SELECT lower(btrim(email)) INTO v_email FROM public.users WHERE id = v_user;
                IF v_email IS NULL THEN
                    RAISE EXCEPTION 'no user';
                END IF;
                SELECT * INTO v_inv FROM public.workspace_invitations
                    WHERE token_hash = p_token_hash FOR UPDATE;
                -- Uniform failure (no enumeration): not-found / used / revoked /
                -- expired / wrong-email all raise the SAME generic error.
                IF NOT FOUND
                   OR v_inv.status <> 'pending'
                   OR v_inv.expires_at <= pg_catalog.now()
                   OR v_inv.email <> v_email THEN
                    RAISE EXCEPTION 'invitation is not valid' USING ERRCODE = '22023';
                END IF;
                UPDATE public.workspace_invitations
                    SET status = 'accepted', accepted_by = v_user,
                        accepted_at = pg_catalog.now(), updated_at = pg_catalog.now()
                    WHERE id = v_inv.id AND status = 'pending';
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'invitation is not valid' USING ERRCODE = '22023';
                END IF;
                -- Plain INSERT + caught unique_violation keeps the bootstrap role's
                -- grants MINIMAL (INSERT only; ON CONFLICT would require SELECT).
                -- A concurrent accept / re-accept is an idempotent no-op.
                BEGIN
                    INSERT INTO public.memberships
                            (id, user_id, workspace_id, role, created_at, updated_at)
                        VALUES (pg_catalog.gen_random_uuid(), v_user, v_inv.tenant_id,
                                v_inv.role, pg_catalog.now(), pg_catalog.now());
                EXCEPTION WHEN unique_violation THEN
                    NULL;
                END;
                INSERT INTO public.authz_audit_events
                        (id, tenant_id, event_type, actor_user_id, subject_id, created_at)
                    VALUES (pg_catalog.gen_random_uuid(), v_inv.tenant_id,
                            'invitation.accepted', v_user, v_inv.id, pg_catalog.now());
                RETURN v_inv.tenant_id;
            END;
            $$
        """
    )
    op.execute("ALTER FUNCTION accept_workspace_invitation(text) OWNER TO nlw_workspace_bootstrap")
    op.execute("REVOKE ALL ON FUNCTION accept_workspace_invitation(text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION accept_workspace_invitation(text) TO nlw_app")

    # --- run initiator + approval requester (SoD provenance) ---
    op.add_column(
        "workflow_runs",
        sa.Column(
            "initiated_by_user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=True,
        ),
    )
    op.add_column(
        "approvals",
        sa.Column(
            "requested_by_user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=True,
        ),
    )
    # Deterministic backfill ONLY where provenance is reliable: a scheduled run's
    # requester is the immutable schedule creator. Manual-run approvals stay NULL
    # (unknown) and FAIL CLOSED for decision (never guessed from timestamps).
    op.execute(
        """
        UPDATE approvals a SET requested_by_user_id = s.created_by
        FROM workflow_runs r
        JOIN schedules s ON s.id = r.schedule_id
        WHERE a.run_id = r.id AND r.schedule_id IS NOT NULL
              AND a.requested_by_user_id IS NULL
        """
    )

    # --- approval separation of duties (DB-enforced four-eyes) ---
    _ADMIN_APPR = (
        f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_admin_or_owner(tenant_id))"
    )
    op.execute("DROP POLICY approvals_app_update ON approvals")
    op.execute(
        f"CREATE POLICY approvals_app_update ON approvals FOR UPDATE TO nlw_app "
        f"USING {_ADMIN_APPR} "
        f"WITH CHECK ({_ADMIN_APPR} AND decided_by = {_USER_GUC} "
        f"AND requested_by_user_id IS NOT NULL AND decided_by <> requested_by_user_id)"
    )


def downgrade() -> None:
    # WARNING: this re-opens self-approval (drops the four-eyes WITH CHECK) and
    # final-owner removal (drops the owner trigger). Operator review required.
    _ADMIN_APPR = (
        f"(tenant_id = {_TENANT_GUC} AND public.is_current_user_admin_or_owner(tenant_id))"
    )
    _ADMIN_SELF = f"({_ADMIN_APPR} AND decided_by = {_USER_GUC})"
    op.execute("DROP POLICY approvals_app_update ON approvals")
    op.execute(
        f"CREATE POLICY approvals_app_update ON approvals FOR UPDATE TO nlw_app "
        f"USING {_ADMIN_APPR} WITH CHECK {_ADMIN_SELF}"
    )
    op.drop_column("approvals", "requested_by_user_id")
    op.drop_column("workflow_runs", "initiated_by_user_id")

    op.execute("DROP FUNCTION IF EXISTS accept_workspace_invitation(text)")
    op.execute("DROP TABLE IF EXISTS authz_audit_events")
    op.execute("DROP TABLE IF EXISTS workspace_invitations")

    op.execute("DROP POLICY IF EXISTS memberships_app_tenant_select ON memberships")
    op.execute("DROP POLICY IF EXISTS memberships_app_admin_delete ON memberships")
    op.execute("DROP POLICY IF EXISTS memberships_app_admin_update ON memberships")
    op.execute("REVOKE UPDATE (role, updated_at), DELETE ON memberships FROM nlw_app")

    op.execute("DROP TRIGGER IF EXISTS trg_workspace_owner_present ON memberships")
    op.execute("DROP FUNCTION IF EXISTS enforce_workspace_owner_present()")
    op.execute("DROP FUNCTION IF EXISTS is_current_user_owner(uuid)")
