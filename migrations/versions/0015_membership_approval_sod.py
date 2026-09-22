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

    # --- membership administration is FUNCTION-ONLY (owner-race correctness) ---
    # nlw_app is deliberately granted NO direct UPDATE/DELETE on memberships. Every
    # role change / removal must go through ``manage_membership`` (created below,
    # after authz_audit_events), which locks the stable workspace row FOR UPDATE
    # FIRST and only then mutates — making the owner-preservation invariant correct
    # by construction (no READ COMMITTED write skew), not merely trigger-guarded.
    # Co-members may still SEE the roster of their active workspace (product policy).
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
    # Append-only for runtime roles: nlw_app INSERTs + reads (admin); the worker
    # INSERTs approval.requested at park (it sets app.tenant_id). NEITHER runtime
    # role is granted UPDATE or DELETE — the audit trail cannot be rewritten or
    # erased by nlw_app/nlw_worker.
    op.execute("GRANT SELECT, INSERT ON authz_audit_events TO nlw_app")
    op.execute("GRANT INSERT ON authz_audit_events TO nlw_worker")
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
    op.execute(
        f"CREATE POLICY authz_audit_worker_insert ON authz_audit_events FOR INSERT TO nlw_worker "
        f"WITH CHECK (tenant_id = {_TENANT_GUC})"
    )

    # --- correct-by-construction membership administration (owner-race safe) ---
    # The ONLY path that changes a role or removes a member. It locks the stable
    # workspace row FOR UPDATE as its FIRST action, so two concurrent calls for the
    # same workspace fully serialize (the second blocks until the first commits and
    # then re-reads ownership under the lock). This eliminates the READ COMMITTED
    # write skew that an AFTER-trigger owner count alone cannot rule out. The actor
    # is taken from app.user_id (never a parameter); authorization, owner-only owner
    # rows, the >=1 owner invariant, and the append-only audit are all enforced here
    # atomically. Errors are stable and non-enumerating.
    op.execute(
        """
        CREATE FUNCTION manage_membership(
            p_workspace_id uuid, p_target_user_id uuid, p_action text, p_new_role text
        ) RETURNS void
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
            AS $$
            DECLARE
                v_actor uuid := NULLIF(current_setting('app.user_id', true), '')::uuid;
                v_actor_role text;
                v_target_role text;
                v_owners int;
            BEGIN
                IF v_actor IS NULL THEN
                    RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
                END IF;
                -- 1) Serialize on the stable workspace identity FIRST, before any
                --    read of ownership. A transaction-scoped advisory lock keyed on
                --    the workspace id is held to COMMIT, so a second concurrent call
                --    for the same workspace blocks here and only proceeds once the
                --    first commits — it then re-reads ownership under the lock. This
                --    gives correct-by-construction serialization with NO write skew
                --    at READ COMMITTED, and (unlike SELECT ... FOR UPDATE on the
                --    workspaces row, which needs UPDATE privilege) keeps the definer
                --    unable to modify the workspaces table at all.
                PERFORM pg_catalog.pg_advisory_xact_lock(
                    pg_catalog.hashtextextended(p_workspace_id::text, 0)
                );
                -- 2) Authorize the actor as an admin/owner member of THIS workspace.
                SELECT role INTO v_actor_role FROM public.memberships
                    WHERE workspace_id = p_workspace_id AND user_id = v_actor;
                IF v_actor_role IS NULL OR v_actor_role NOT IN ('admin', 'owner') THEN
                    RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
                END IF;
                -- 3) Re-read the target under the lock.
                SELECT role INTO v_target_role FROM public.memberships
                    WHERE workspace_id = p_workspace_id AND user_id = p_target_user_id;
                IF v_target_role IS NULL THEN
                    RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
                END IF;
                -- 4) Only an OWNER may touch an owner row or grant ownership.
                IF (v_target_role = 'owner' OR p_new_role = 'owner')
                        AND v_actor_role <> 'owner' THEN
                    RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
                END IF;
                -- 5) Apply the mutation.
                IF p_action = 'remove' THEN
                    DELETE FROM public.memberships
                        WHERE workspace_id = p_workspace_id AND user_id = p_target_user_id;
                ELSIF p_action = 'set_role' THEN
                    IF p_new_role NOT IN ('owner', 'admin', 'member') THEN
                        RAISE EXCEPTION 'invalid role' USING ERRCODE = '22023';
                    END IF;
                    UPDATE public.memberships SET role = p_new_role, updated_at = pg_catalog.now()
                        WHERE workspace_id = p_workspace_id AND user_id = p_target_user_id;
                ELSE
                    RAISE EXCEPTION 'invalid action' USING ERRCODE = '22023';
                END IF;
                -- 6) Owner-preservation: the workspace still has >= 1 owner (under lock).
                SELECT count(*) INTO v_owners FROM public.memberships
                    WHERE workspace_id = p_workspace_id AND role = 'owner';
                IF v_owners = 0 THEN
                    RAISE EXCEPTION 'workspace must retain at least one owner'
                        USING ERRCODE = 'check_violation';
                END IF;
                -- 7) Append-only audit, same transaction as the state change.
                INSERT INTO public.authz_audit_events
                        (id, tenant_id, event_type, actor_user_id, subject_id, detail, created_at)
                    VALUES (pg_catalog.gen_random_uuid(), p_workspace_id,
                            CASE WHEN p_action = 'remove' THEN 'membership.removed'
                                 ELSE 'membership.role_changed' END,
                            v_actor, p_target_user_id,
                            CASE WHEN p_action = 'set_role' THEN p_new_role ELSE NULL END,
                            pg_catalog.now());
            END;
            $$
        """
    )
    # Owned by nlw_membership_admin — a DEDICATED NOLOGIN BYPASSRLS role that owns
    # ONLY this function, so the identity-bootstrap owner (nlw_workspace_bootstrap)
    # does not also become a general membership administrator. Its entire blast
    # radius is the two grants below; a direct grant test asserts it can touch
    # nothing else (no users email/auth id, connectors, workflows, actions, secrets,
    # backup/recovery state). nlw_rls_bypass stays purely read-only.
    op.execute(
        "ALTER FUNCTION manage_membership(uuid, uuid, text, text) OWNER TO nlw_membership_admin"
    )
    op.execute("REVOKE ALL ON FUNCTION manage_membership(uuid, uuid, text, text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION manage_membership(uuid, uuid, text, text) TO nlw_app")
    # The definer's ONLY privileges: memberships DML (the mutation it performs) and
    # authz_audit_events INSERT (the append-only event it writes). It has NO
    # privilege on workspaces (it only advisory-locks the workspace id, never
    # touches the table) and nothing else. No LOGIN role can use these except
    # through the SECURITY DEFINER function, which authorizes the actor first.
    op.execute("GRANT SELECT, UPDATE, DELETE ON memberships TO nlw_membership_admin")
    op.execute("GRANT INSERT ON authz_audit_events TO nlw_membership_admin")

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
                    -- Emit membership.added ONLY on a genuine new membership (a
                    -- concurrent re-accept hits unique_violation and adds nothing).
                    INSERT INTO public.authz_audit_events
                            (id, tenant_id, event_type, actor_user_id, subject_id, detail,
                             created_at)
                        VALUES (pg_catalog.gen_random_uuid(), v_inv.tenant_id,
                                'membership.added', v_user, v_user, v_inv.role, pg_catalog.now());
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

    # --- provenance & decision immutability (defence in depth at the DB layer) ---
    # Column grants already stop nlw_app from touching approvals.requested_by_user_id
    # and workflow_runs.* it cannot write, but two gaps remain provable by direct SQL:
    #   * nlw_worker holds table-level UPDATE on workflow_runs -> could rewrite
    #     initiated_by_user_id (run provenance);
    #   * nlw_app holds table-level UPDATE on schedules -> could rewrite created_by;
    #   * the four-eyes WITH CHECK does not require the OLD status to be pending, so a
    #     second eligible admin could flip an already-decided approval by direct SQL.
    # These BEFORE-UPDATE triggers close all three for EVERY role (they are SECURITY
    # INVOKER and only compare OLD/NEW, so they need no table privilege). Legitimate
    # updates never touch these columns, so they are unaffected.
    op.execute(
        """
        CREATE FUNCTION enforce_approval_immutability() RETURNS trigger
            LANGUAGE plpgsql SET search_path = pg_catalog
            AS $$
            BEGIN
                IF NEW.requested_by_user_id IS DISTINCT FROM OLD.requested_by_user_id THEN
                    RAISE EXCEPTION 'approvals.requested_by_user_id is immutable'
                        USING ERRCODE = 'check_violation';
                END IF;
                -- The FIRST terminal decision is final: once approved/rejected, the
                -- decision fields cannot change (no APPROVED<->REJECTED / ->PENDING).
                IF OLD.status IN ('approved', 'rejected')
                   AND (NEW.status IS DISTINCT FROM OLD.status
                        OR NEW.decided_by IS DISTINCT FROM OLD.decided_by
                        OR NEW.decided_at IS DISTINCT FROM OLD.decided_at) THEN
                    RAISE EXCEPTION 'a decided approval is immutable'
                        USING ERRCODE = 'check_violation';
                END IF;
                RETURN NEW;
            END;
            $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION enforce_approval_immutability() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER trg_approval_immutable BEFORE UPDATE ON approvals "
        "FOR EACH ROW EXECUTE FUNCTION enforce_approval_immutability()"
    )
    op.execute(
        """
        CREATE FUNCTION enforce_run_initiator_immutability() RETURNS trigger
            LANGUAGE plpgsql SET search_path = pg_catalog
            AS $$
            BEGIN
                IF NEW.initiated_by_user_id IS DISTINCT FROM OLD.initiated_by_user_id THEN
                    RAISE EXCEPTION 'workflow_runs.initiated_by_user_id is immutable'
                        USING ERRCODE = 'check_violation';
                END IF;
                RETURN NEW;
            END;
            $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION enforce_run_initiator_immutability() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER trg_run_initiator_immutable BEFORE UPDATE ON workflow_runs "
        "FOR EACH ROW EXECUTE FUNCTION enforce_run_initiator_immutability()"
    )
    op.execute(
        """
        CREATE FUNCTION enforce_schedule_creator_immutability() RETURNS trigger
            LANGUAGE plpgsql SET search_path = pg_catalog
            AS $$
            BEGIN
                IF NEW.created_by IS DISTINCT FROM OLD.created_by THEN
                    RAISE EXCEPTION 'schedules.created_by is immutable'
                        USING ERRCODE = 'check_violation';
                END IF;
                RETURN NEW;
            END;
            $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION enforce_schedule_creator_immutability() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER trg_schedule_creator_immutable BEFORE UPDATE ON schedules "
        "FOR EACH ROW EXECUTE FUNCTION enforce_schedule_creator_immutability()"
    )


def downgrade() -> None:
    # WARNING: this re-opens self-approval (drops the four-eyes WITH CHECK), the
    # provenance/decision immutability triggers, and final-owner removal (drops the
    # owner trigger + the function-only mutation path). Operator review required.
    op.execute("DROP TRIGGER IF EXISTS trg_schedule_creator_immutable ON schedules")
    op.execute("DROP FUNCTION IF EXISTS enforce_schedule_creator_immutability()")
    op.execute("DROP TRIGGER IF EXISTS trg_run_initiator_immutable ON workflow_runs")
    op.execute("DROP FUNCTION IF EXISTS enforce_run_initiator_immutability()")
    op.execute("DROP TRIGGER IF EXISTS trg_approval_immutable ON approvals")
    op.execute("DROP FUNCTION IF EXISTS enforce_approval_immutability()")

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
    op.execute("DROP FUNCTION IF EXISTS manage_membership(uuid, uuid, text, text)")
    op.execute("REVOKE INSERT ON authz_audit_events FROM nlw_membership_admin")
    op.execute("REVOKE SELECT, UPDATE, DELETE ON memberships FROM nlw_membership_admin")
    op.execute("DROP TABLE IF EXISTS authz_audit_events")
    op.execute("DROP TABLE IF EXISTS workspace_invitations")

    op.execute("DROP POLICY IF EXISTS memberships_app_tenant_select ON memberships")

    op.execute("DROP TRIGGER IF EXISTS trg_workspace_owner_present ON memberships")
    op.execute("DROP FUNCTION IF EXISTS enforce_workspace_owner_present()")
    op.execute("DROP FUNCTION IF EXISTS is_current_user_owner(uuid)")
