"""signed database context: purpose-bound, expiring, HMAC-verified RLS (M11.5 P3B)

Replaces every authorization policy/helper that trusted the forgeable settings
``app.user_id`` / ``app.tenant_id`` with verification of a SIGNED transaction-local
context (``app.ctx_*``, ADR-024). After this migration NO live policy or helper
reads those legacy settings; a bare ``set_config('app.user_id', ...)`` grants nothing.

- ``ctx_keys`` — the protected key registry (owned by the dedicated NOLOGIN
  ``nlw_ctx_verifier`` role; no runtime role has any privilege on it). HMAC is
  SYMMETRIC: this material is signing-capable, which is exactly why it is
  unreadable to every login role. ``ctx_key_events`` audits installs/revocations
  WITHOUT material.
- ``app_ctx_claims()`` — the single SECURITY DEFINER verifier: canonical
  length-prefixed message v1 (byte-identical to the Python signer), key lookup by
  id (active window), purpose <-> key class, purpose <-> ``session_user`` binding,
  claim-shape checks, issued-at/expiry/max-lifetime, constant-time tag compare.
  Returns NULL on ANY failure (RLS then denies). It never returns key material
  and never computes a tag for caller-supplied data (not a signing oracle).
- ``ctx_user_id()`` / ``ctx_tenant_id()`` / ``ctx_run_id()`` / ``ctx_purpose()``
  — typed accessors gated by purpose (a worker/scheduler context has no user; an
  identity context has no tenant).
- Purposes: api_identity (nlw_app; human, no workspace), api_request (nlw_app;
  human + workspace, live membership re-checked by the helpers on every call so a
  removal/demotion takes effect immediately), worker_execution (nlw_worker;
  tenant + run, rows bound to the claimed run), scheduler_reconcile
  (nlw_scheduler; cross-tenant scan/reconcile only with a valid signed context).
- Deny-by-default: until keys are installed the verifier finds no key and every
  policy denies. There is no unsigned fallback.

DEPLOYMENT ORDER (security sensitive): stop runtimes -> apply this migration ->
install keys (``python -m nlw.ctxkeys install``, owner credential, secrets from
files) -> start runtimes with their key files -> signed-context readiness.

DOWNGRADE WARNING: downgrading below 0016 re-installs the legacy unsigned-GUC
policies and REOPENS context forgery. Never downgrade a live customer environment
without explicit security review; prefer fix-forward. Runtime code >= P3B signs
``app.ctx_*`` and sets nothing legacy, so a downgraded database with new runtimes
fails CLOSED (nothing matches) rather than trusting unsigned context.

Revision ID: 0016_signed_database_context
Revises: 0015_membership_approval_sod
Create Date: 2026-09-22
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0016_signed_database_context"
down_revision: str | Sequence[str] | None = "0015_membership_approval_sod"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ---------------------------------------------------------------------------
# Signed-context accessors (the ONLY authorization inputs after this migration)
# ---------------------------------------------------------------------------
_U = "public.ctx_user_id()"
_T = "public.ctx_tenant_id()"
_R = "public.ctx_run_id()"
_P = "public.ctx_purpose()"
_MEMBER = f"(tenant_id = {_T} AND public.is_current_user_member(tenant_id))"
_ADMIN = f"(tenant_id = {_T} AND public.is_current_user_admin_or_owner(tenant_id))"
_WRK = f"({_P} = 'worker_execution' AND tenant_id = {_T})"
_WRK_RUN = f"({_WRK} AND run_id = {_R})"
_WRK_RUN_SELF = f"({_WRK} AND id = {_R})"
_SCHED = f"({_P} = 'scheduler_reconcile')"

# (policy, table, command, role, using, with_check) — the COMPLETE live set.
_POLICIES: list[tuple[str, str, str, str, str | None, str | None]] = [
    # users — verified human identity, own row only
    ("users_app_self_select", "users", "SELECT", "nlw_app", f"(id = {_U})", None),
    ("users_app_self_update", "users", "UPDATE", "nlw_app", f"(id = {_U})", f"(id = {_U})"),
    # workspaces — discovery of the workspaces the verified user belongs to
    (
        "workspaces_app_select",
        "workspaces",
        "SELECT",
        "nlw_app",
        "(public.is_current_user_member(id))",
        None,
    ),
    # memberships — own rows (discovery) + roster of the active workspace
    ("memberships_app_select", "memberships", "SELECT", "nlw_app", f"(user_id = {_U})", None),
    (
        "memberships_app_tenant_select",
        "memberships",
        "SELECT",
        "nlw_app",
        f"(workspace_id = {_T} AND public.is_current_user_member(workspace_id))",
        None,
    ),
    # workflows
    ("workflows_app_select", "workflows", "SELECT", "nlw_app", _MEMBER, None),
    ("workflows_app_insert", "workflows", "INSERT", "nlw_app", None, _MEMBER),
    ("workflows_app_update", "workflows", "UPDATE", "nlw_app", _MEMBER, _MEMBER),
    # workflow_versions
    ("workflow_versions_app_select", "workflow_versions", "SELECT", "nlw_app", _MEMBER, None),
    ("workflow_versions_app_insert", "workflow_versions", "INSERT", "nlw_app", None, _MEMBER),
    ("workflow_versions_worker_select", "workflow_versions", "SELECT", "nlw_worker", _WRK, None),
    # workflow_runs
    ("workflow_runs_app_select", "workflow_runs", "SELECT", "nlw_app", _MEMBER, None),
    ("workflow_runs_app_insert", "workflow_runs", "INSERT", "nlw_app", None, _MEMBER),
    ("workflow_runs_worker_select", "workflow_runs", "SELECT", "nlw_worker", _WRK_RUN_SELF, None),
    (
        "workflow_runs_worker_update",
        "workflow_runs",
        "UPDATE",
        "nlw_worker",
        _WRK_RUN_SELF,
        _WRK_RUN_SELF,
    ),
    ("workflow_runs_sched_select", "workflow_runs", "SELECT", "nlw_scheduler", _SCHED, None),
    ("workflow_runs_sched_insert", "workflow_runs", "INSERT", "nlw_scheduler", None, _SCHED),
    # step_runs
    ("step_runs_app_select", "step_runs", "SELECT", "nlw_app", _MEMBER, None),
    ("step_runs_worker_select", "step_runs", "SELECT", "nlw_worker", _WRK_RUN, None),
    ("step_runs_worker_insert", "step_runs", "INSERT", "nlw_worker", None, _WRK_RUN),
    ("step_runs_worker_update", "step_runs", "UPDATE", "nlw_worker", _WRK_RUN, _WRK_RUN),
    ("step_runs_sched_select", "step_runs", "SELECT", "nlw_scheduler", _SCHED, None),
    # connectors
    ("connectors_app_select", "connectors", "SELECT", "nlw_app", _MEMBER, None),
    ("connectors_app_insert", "connectors", "INSERT", "nlw_app", None, _ADMIN),
    ("connectors_worker_select", "connectors", "SELECT", "nlw_worker", _WRK, None),
    ("connectors_worker_update", "connectors", "UPDATE", "nlw_worker", _WRK, _WRK),
    # plan_proposals
    ("plan_proposals_app_select", "plan_proposals", "SELECT", "nlw_app", _MEMBER, None),
    ("plan_proposals_app_insert", "plan_proposals", "INSERT", "nlw_app", None, _MEMBER),
    ("plan_proposals_app_update", "plan_proposals", "UPDATE", "nlw_app", _MEMBER, _MEMBER),
    # approvals — four-eyes: decider is the VERIFIED human, never the requester
    ("approvals_app_select", "approvals", "SELECT", "nlw_app", _MEMBER, None),
    (
        "approvals_app_update",
        "approvals",
        "UPDATE",
        "nlw_app",
        _ADMIN,
        f"({_ADMIN} AND decided_by = {_U} AND requested_by_user_id IS NOT NULL "
        f"AND decided_by <> requested_by_user_id)",
    ),
    ("approvals_worker_select", "approvals", "SELECT", "nlw_worker", _WRK_RUN, None),
    ("approvals_worker_insert", "approvals", "INSERT", "nlw_worker", None, _WRK_RUN),
    ("approvals_sched_select", "approvals", "SELECT", "nlw_scheduler", _SCHED, None),
    # external_actions
    ("ext_actions_app_select", "external_actions", "SELECT", "nlw_app", _MEMBER, None),
    ("ext_actions_worker_select", "external_actions", "SELECT", "nlw_worker", _WRK_RUN, None),
    ("ext_actions_worker_insert", "external_actions", "INSERT", "nlw_worker", None, _WRK_RUN),
    ("ext_actions_worker_update", "external_actions", "UPDATE", "nlw_worker", _WRK_RUN, _WRK_RUN),
    ("ext_actions_sched_select", "external_actions", "SELECT", "nlw_scheduler", _SCHED, None),
    # schedules
    ("schedules_app_select", "schedules", "SELECT", "nlw_app", _MEMBER, None),
    ("schedules_app_insert", "schedules", "INSERT", "nlw_app", None, _ADMIN),
    ("schedules_app_update", "schedules", "UPDATE", "nlw_app", _ADMIN, _ADMIN),
    ("schedules_app_delete", "schedules", "DELETE", "nlw_app", _ADMIN, None),
    ("schedules_sched_select", "schedules", "SELECT", "nlw_scheduler", _SCHED, None),
    ("schedules_sched_update", "schedules", "UPDATE", "nlw_scheduler", _SCHED, _SCHED),
    # workspace_invitations — inviter is the VERIFIED human
    ("invitations_app_select", "workspace_invitations", "SELECT", "nlw_app", _ADMIN, None),
    (
        "invitations_app_insert",
        "workspace_invitations",
        "INSERT",
        "nlw_app",
        None,
        f"({_ADMIN} AND invited_by = {_U})",
    ),
    ("invitations_app_update", "workspace_invitations", "UPDATE", "nlw_app", _ADMIN, _ADMIN),
    # authz_audit_events — append-only; a member context of THAT tenant, or the
    # worker bound to that tenant. (Previously tenant-GUC only: forgeable.)
    ("authz_audit_app_select", "authz_audit_events", "SELECT", "nlw_app", _ADMIN, None),
    ("authz_audit_app_insert", "authz_audit_events", "INSERT", "nlw_app", None, _MEMBER),
    ("authz_audit_worker_insert", "authz_audit_events", "INSERT", "nlw_worker", None, _WRK),
]

# ---------------------------------------------------------------------------
# LEGACY definitions (downgrade only). These trust unsigned settings on purpose:
# they are the pre-P3B state and are re-installed ONLY by downgrade().
# ---------------------------------------------------------------------------
_L_USER = "NULLIF(current_setting('app.user_id', true), '')::uuid"
_L_TEN = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_L_MEMBER = f"(tenant_id = {_L_TEN} AND public.is_current_user_member(tenant_id))"
_L_ADMIN = f"(tenant_id = {_L_TEN} AND public.is_current_user_admin_or_owner(tenant_id))"
_L_WRK = f"(tenant_id = {_L_TEN})"

_LEGACY_POLICIES: list[tuple[str, str, str, str, str | None, str | None]] = [
    ("users_app_self_select", "users", "SELECT", "nlw_app", f"(id = {_L_USER})", None),
    (
        "users_app_self_update",
        "users",
        "UPDATE",
        "nlw_app",
        f"(id = {_L_USER})",
        f"(id = {_L_USER})",
    ),
    (
        "workspaces_app_select",
        "workspaces",
        "SELECT",
        "nlw_app",
        "(public.is_current_user_member(id))",
        None,
    ),
    ("memberships_app_select", "memberships", "SELECT", "nlw_app", f"(user_id = {_L_USER})", None),
    (
        "memberships_app_tenant_select",
        "memberships",
        "SELECT",
        "nlw_app",
        f"(workspace_id = {_L_TEN} AND public.is_current_user_member(workspace_id))",
        None,
    ),
    ("workflows_app_select", "workflows", "SELECT", "nlw_app", _L_MEMBER, None),
    ("workflows_app_insert", "workflows", "INSERT", "nlw_app", None, _L_MEMBER),
    ("workflows_app_update", "workflows", "UPDATE", "nlw_app", _L_MEMBER, _L_MEMBER),
    ("workflow_versions_app_select", "workflow_versions", "SELECT", "nlw_app", _L_MEMBER, None),
    ("workflow_versions_app_insert", "workflow_versions", "INSERT", "nlw_app", None, _L_MEMBER),
    ("workflow_versions_worker_select", "workflow_versions", "SELECT", "nlw_worker", _L_WRK, None),
    ("workflow_runs_app_select", "workflow_runs", "SELECT", "nlw_app", _L_MEMBER, None),
    ("workflow_runs_app_insert", "workflow_runs", "INSERT", "nlw_app", None, _L_MEMBER),
    ("workflow_runs_worker_select", "workflow_runs", "SELECT", "nlw_worker", _L_WRK, None),
    ("workflow_runs_worker_update", "workflow_runs", "UPDATE", "nlw_worker", _L_WRK, _L_WRK),
    ("workflow_runs_sched_select", "workflow_runs", "SELECT", "nlw_scheduler", "(true)", None),
    ("workflow_runs_sched_insert", "workflow_runs", "INSERT", "nlw_scheduler", None, "(true)"),
    ("step_runs_app_select", "step_runs", "SELECT", "nlw_app", _L_MEMBER, None),
    ("step_runs_worker_select", "step_runs", "SELECT", "nlw_worker", _L_WRK, None),
    ("step_runs_worker_insert", "step_runs", "INSERT", "nlw_worker", None, _L_WRK),
    ("step_runs_worker_update", "step_runs", "UPDATE", "nlw_worker", _L_WRK, _L_WRK),
    ("step_runs_sched_select", "step_runs", "SELECT", "nlw_scheduler", "(true)", None),
    ("connectors_app_select", "connectors", "SELECT", "nlw_app", _L_MEMBER, None),
    ("connectors_app_insert", "connectors", "INSERT", "nlw_app", None, _L_ADMIN),
    ("connectors_worker_select", "connectors", "SELECT", "nlw_worker", _L_WRK, None),
    ("connectors_worker_update", "connectors", "UPDATE", "nlw_worker", _L_WRK, _L_WRK),
    ("plan_proposals_app_select", "plan_proposals", "SELECT", "nlw_app", _L_MEMBER, None),
    ("plan_proposals_app_insert", "plan_proposals", "INSERT", "nlw_app", None, _L_MEMBER),
    ("plan_proposals_app_update", "plan_proposals", "UPDATE", "nlw_app", _L_MEMBER, _L_MEMBER),
    ("approvals_app_select", "approvals", "SELECT", "nlw_app", _L_MEMBER, None),
    (
        "approvals_app_update",
        "approvals",
        "UPDATE",
        "nlw_app",
        _L_ADMIN,
        f"({_L_ADMIN} AND decided_by = {_L_USER} AND requested_by_user_id IS NOT NULL "
        f"AND decided_by <> requested_by_user_id)",
    ),
    ("approvals_worker_select", "approvals", "SELECT", "nlw_worker", _L_WRK, None),
    ("approvals_worker_insert", "approvals", "INSERT", "nlw_worker", None, _L_WRK),
    ("approvals_sched_select", "approvals", "SELECT", "nlw_scheduler", "(true)", None),
    ("ext_actions_app_select", "external_actions", "SELECT", "nlw_app", _L_MEMBER, None),
    ("ext_actions_worker_select", "external_actions", "SELECT", "nlw_worker", _L_WRK, None),
    ("ext_actions_worker_insert", "external_actions", "INSERT", "nlw_worker", None, _L_WRK),
    ("ext_actions_worker_update", "external_actions", "UPDATE", "nlw_worker", _L_WRK, _L_WRK),
    ("ext_actions_sched_select", "external_actions", "SELECT", "nlw_scheduler", "(true)", None),
    ("schedules_app_select", "schedules", "SELECT", "nlw_app", _L_MEMBER, None),
    ("schedules_app_insert", "schedules", "INSERT", "nlw_app", None, _L_ADMIN),
    ("schedules_app_update", "schedules", "UPDATE", "nlw_app", _L_ADMIN, _L_ADMIN),
    ("schedules_app_delete", "schedules", "DELETE", "nlw_app", _L_ADMIN, None),
    ("schedules_sched_select", "schedules", "SELECT", "nlw_scheduler", "(true)", None),
    ("schedules_sched_update", "schedules", "UPDATE", "nlw_scheduler", "(true)", "(true)"),
    ("invitations_app_select", "workspace_invitations", "SELECT", "nlw_app", _L_ADMIN, None),
    (
        "invitations_app_insert",
        "workspace_invitations",
        "INSERT",
        "nlw_app",
        None,
        f"({_L_ADMIN} AND invited_by = {_L_USER})",
    ),
    ("invitations_app_update", "workspace_invitations", "UPDATE", "nlw_app", _L_ADMIN, _L_ADMIN),
    ("authz_audit_app_select", "authz_audit_events", "SELECT", "nlw_app", _L_ADMIN, None),
    (
        "authz_audit_app_insert",
        "authz_audit_events",
        "INSERT",
        "nlw_app",
        None,
        f"(tenant_id = {_L_TEN})",
    ),
    (
        "authz_audit_worker_insert",
        "authz_audit_events",
        "INSERT",
        "nlw_worker",
        None,
        f"(tenant_id = {_L_TEN})",
    ),
]

_CTX_ROLES = (
    "nlw_app",
    "nlw_worker",
    "nlw_scheduler",
    "nlw_rls_bypass",
    "nlw_workspace_bootstrap",
    "nlw_membership_admin",
)


def _create_policies(policies: list[tuple[str, str, str, str, str | None, str | None]]) -> None:
    for name, table, cmd, role, using, check in policies:
        sql = f"CREATE POLICY {name} ON {table} FOR {cmd} TO {role}"
        if using is not None:
            sql += f" USING {using}"
        if check is not None:
            sql += f" WITH CHECK {check}"
        op.execute(sql)


def _drop_policies(policies: list[tuple[str, str, str, str, str | None, str | None]]) -> None:
    for name, table, *_ in policies:
        op.execute(f"DROP POLICY IF EXISTS {name} ON {table}")


def _grant_exec(sig: str, roles: tuple[str, ...]) -> None:
    op.execute(f"REVOKE ALL ON FUNCTION {sig} FROM PUBLIC")
    for r in roles:
        op.execute(f"GRANT EXECUTE ON FUNCTION {sig} TO {r}")


# ---------------------------------------------------------------------------
# SIGNED helpers
# ---------------------------------------------------------------------------
_SQL_MEMBER_HELPER = """
CREATE OR REPLACE FUNCTION is_current_user_member(p_tenant_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
    AS $$
        SELECT EXISTS (
            SELECT 1 FROM public.memberships m
            WHERE m.user_id = public.ctx_user_id()
              AND m.workspace_id = p_tenant_id
        )
    $$
"""
_SQL_ADMIN_HELPER = """
CREATE OR REPLACE FUNCTION is_current_user_admin_or_owner(p_tenant_id uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
    AS $$
        SELECT EXISTS (
            SELECT 1 FROM public.memberships m
            WHERE m.user_id = public.ctx_user_id()
              AND m.workspace_id = p_tenant_id
              AND m.role IN ('owner', 'admin')
        )
    $$
"""
# LEGACY helper bodies (downgrade only).
_SQL_MEMBER_HELPER_LEGACY = _SQL_MEMBER_HELPER.replace("public.ctx_user_id()", _L_USER)
_SQL_ADMIN_HELPER_LEGACY = _SQL_ADMIN_HELPER.replace("public.ctx_user_id()", _L_USER)

_SQL_CREATE_WORKSPACE = """
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
_SQL_CREATE_WORKSPACE_LEGACY = _SQL_CREATE_WORKSPACE.replace("public.ctx_user_id()", _L_USER)

_SQL_ACCEPT = """
CREATE OR REPLACE FUNCTION accept_workspace_invitation(p_token_hash text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
    AS $$
    DECLARE
        v_user uuid := public.ctx_user_id();
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
        BEGIN
            INSERT INTO public.memberships
                    (id, user_id, workspace_id, role, created_at, updated_at)
                VALUES (pg_catalog.gen_random_uuid(), v_user, v_inv.tenant_id,
                        v_inv.role, pg_catalog.now(), pg_catalog.now());
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
_SQL_ACCEPT_LEGACY = _SQL_ACCEPT.replace("public.ctx_user_id()", _L_USER)

# manage_membership now ALSO requires that the claimed workspace is the signed
# tenant of an api_request context (the pre-P3B version never cross-checked the
# tenant at all).
_SQL_MANAGE = """
CREATE OR REPLACE FUNCTION manage_membership(
    p_workspace_id uuid, p_target_user_id uuid, p_action text, p_new_role text
) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
    AS $$
    DECLARE
        v_actor uuid := public.ctx_user_id();
        v_actor_role text;
        v_target_role text;
        v_owners int;
    BEGIN
        IF v_actor IS NULL OR public.ctx_purpose() <> 'api_request'
           OR public.ctx_tenant_id() IS DISTINCT FROM p_workspace_id THEN
            RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
        END IF;
        PERFORM pg_catalog.pg_advisory_xact_lock(
            pg_catalog.hashtextextended(p_workspace_id::text, 0)
        );
        SELECT role INTO v_actor_role FROM public.memberships
            WHERE workspace_id = p_workspace_id AND user_id = v_actor;
        IF v_actor_role IS NULL OR v_actor_role NOT IN ('admin', 'owner') THEN
            RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
        END IF;
        SELECT role INTO v_target_role FROM public.memberships
            WHERE workspace_id = p_workspace_id AND user_id = p_target_user_id;
        IF v_target_role IS NULL THEN
            RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
        END IF;
        IF (v_target_role = 'owner' OR p_new_role = 'owner')
                AND v_actor_role <> 'owner' THEN
            RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
        END IF;
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
        SELECT count(*) INTO v_owners FROM public.memberships
            WHERE workspace_id = p_workspace_id AND role = 'owner';
        IF v_owners = 0 THEN
            RAISE EXCEPTION 'workspace must retain at least one owner'
                USING ERRCODE = 'check_violation';
        END IF;
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
_SQL_MANAGE_LEGACY = _SQL_MANAGE.replace(
    "IF v_actor IS NULL OR public.ctx_purpose() <> 'api_request'\n"
    "           OR public.ctx_tenant_id() IS DISTINCT FROM p_workspace_id THEN",
    "IF v_actor IS NULL THEN",
).replace("public.ctx_user_id()", _L_USER)


def upgrade() -> None:
    # pgcrypto is a TRUSTED extension (installable by the DB owner, no superuser).
    # Pinned to schema public so the verifier can call it fully qualified from a
    # hardened search_path.
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")

    # --- protected key registry -------------------------------------------
    op.execute(
        """
        CREATE TABLE ctx_keys (
            key_id        text PRIMARY KEY,
            key_class     text NOT NULL CHECK (key_class IN ('api', 'worker', 'scheduler')),
            secret        bytea NOT NULL CHECK (octet_length(secret) >= 32),
            secret_sha256 text NOT NULL,
            status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
            activated_at  timestamptz NOT NULL DEFAULT now(),
            retired_at    timestamptz,
            revoked_at    timestamptz,
            created_at    timestamptz NOT NULL DEFAULT now(),
            CHECK (key_id ~ '^[A-Za-z0-9._-]{1,64}$')
        )
        """
    )
    # Owned by the dedicated verifier role. NO grants to any login role, and no
    # RLS (FORCE RLS would blind the owner-run verifier itself); protection is
    # ownership + the absence of grants + the verifier never returning material.
    op.execute("ALTER TABLE ctx_keys OWNER TO nlw_ctx_verifier")
    op.execute("REVOKE ALL ON TABLE ctx_keys FROM PUBLIC")
    # Append-only audit of key lifecycle: NEVER material. Owner-only.
    op.execute(
        """
        CREATE TABLE ctx_key_events (
            id         bigserial PRIMARY KEY,
            key_id     text NOT NULL,
            key_class  text NOT NULL,
            event      text NOT NULL
                       CHECK (event IN ('installed', 'activated', 'revoked', 'retired')),
            actor      text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("REVOKE ALL ON TABLE ctx_key_events FROM PUBLIC")

    # --- canonical message + verifier -------------------------------------
    op.execute(
        "CREATE TYPE app_ctx_claims_t AS "
        "(purpose text, user_id uuid, tenant_id uuid, run_id uuid, key_id text)"
    )
    op.execute(
        """
        CREATE FUNCTION app_ctx_canon(
            v text, kid text, role text, purpose text, usr text, ten text, run text,
            iat text, exp text, nonce text
        ) RETURNS bytea
            LANGUAGE sql IMMUTABLE SET search_path = pg_catalog
            AS $$
                SELECT convert_to(
                    'nlwctx1'
                    || octet_length(v)       || ':' || v
                    || octet_length(kid)     || ':' || kid
                    || octet_length(role)    || ':' || role
                    || octet_length(purpose) || ':' || purpose
                    || octet_length(usr)     || ':' || usr
                    || octet_length(ten)     || ':' || ten
                    || octet_length(run)     || ':' || run
                    || octet_length(iat)     || ':' || iat
                    || octet_length(exp)     || ':' || exp
                    || octet_length(nonce)   || ':' || nonce,
                    'UTF8')
            $$
        """
    )
    op.execute(
        "ALTER FUNCTION app_ctx_canon(text,text,text,text,text,text,text,text,text,text) "
        "OWNER TO nlw_ctx_verifier"
    )
    # Pure canonicalizer (no key): only the verifier (its owner) needs to call it.
    op.execute(
        "REVOKE ALL ON FUNCTION app_ctx_canon(text,text,text,text,text,text,text,text,text,text) "
        "FROM PUBLIC"
    )
    op.execute(
        """
        CREATE FUNCTION app_ctx_claims() RETURNS app_ctx_claims_t
            LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog
            AS $$
            DECLARE
                v       text := current_setting('app.ctx_v', true);
                kid     text := current_setting('app.ctx_kid', true);
                role    text := current_setting('app.ctx_role', true);
                purpose text := current_setting('app.ctx_purpose', true);
                usr     text := coalesce(current_setting('app.ctx_user', true), '');
                ten     text := coalesce(current_setting('app.ctx_tenant', true), '');
                run     text := coalesce(current_setting('app.ctx_run', true), '');
                iat     text := current_setting('app.ctx_iat', true);
                exp     text := current_setting('app.ctx_exp', true);
                nonce   text := current_setting('app.ctx_nonce', true);
                mac     text := current_setting('app.ctx_mac', true);
                k_secret bytea;
                k_class  text;
                k_expected text;
                want    bytea;
                got     bytea;
                acc     int := 0;
                i       int;
                now_e   bigint := floor(extract(epoch FROM clock_timestamp()))::bigint;
                iat_i   bigint;
                exp_i   bigint;
                uuid_re constant text :=
                    '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
            BEGIN
                -- 1) presence + version + formats (every check fails CLOSED -> NULL)
                IF v IS DISTINCT FROM '1' THEN RETURN NULL; END IF;
                IF kid IS NULL OR kid !~ '^[A-Za-z0-9._-]{1,64}$' THEN RETURN NULL; END IF;
                IF role IS NULL OR role !~ '^[a-z_][a-z0-9_]{0,62}$' THEN RETURN NULL; END IF;
                IF purpose IS NULL OR purpose NOT IN
                   ('api_identity', 'api_request', 'worker_execution', 'scheduler_reconcile')
                THEN RETURN NULL; END IF;
                IF usr <> '' AND usr !~ uuid_re THEN RETURN NULL; END IF;
                IF ten <> '' AND ten !~ uuid_re THEN RETURN NULL; END IF;
                IF run <> '' AND run !~ uuid_re THEN RETURN NULL; END IF;
                IF iat IS NULL OR iat !~ '^[0-9]{1,12}$' THEN RETURN NULL; END IF;
                IF exp IS NULL OR exp !~ '^[0-9]{1,12}$' THEN RETURN NULL; END IF;
                IF nonce IS NULL OR nonce !~ '^[0-9a-f]{32}$' THEN RETURN NULL; END IF;
                IF mac IS NULL OR mac !~ '^[0-9a-f]{64}$' THEN RETURN NULL; END IF;
                -- 2) the signed expected role must be THIS login role, and the
                --    purpose must be one that role may present
                IF role <> session_user::text THEN RETURN NULL; END IF;
                IF (purpose IN ('api_identity', 'api_request') AND role <> 'nlw_app')
                   OR (purpose = 'worker_execution' AND role <> 'nlw_worker')
                   OR (purpose = 'scheduler_reconcile' AND role <> 'nlw_scheduler')
                THEN RETURN NULL; END IF;
                -- 3) claim shape per purpose
                IF purpose = 'api_identity' AND (usr = '' OR ten <> '' OR run <> '')
                THEN RETURN NULL; END IF;
                IF purpose = 'api_request' AND (usr = '' OR ten = '' OR run <> '')
                THEN RETURN NULL; END IF;
                IF purpose = 'worker_execution' AND (usr <> '' OR ten = '')
                THEN RETURN NULL; END IF;
                IF purpose = 'scheduler_reconcile' AND (usr <> '' OR ten <> '' OR run <> '')
                THEN RETURN NULL; END IF;
                -- 4) time window: not from the future (60s skew), not expired,
                --    lifetime bounded (independent of the application's cap)
                iat_i := iat::bigint; exp_i := exp::bigint;
                IF iat_i > now_e + 60 THEN RETURN NULL; END IF;
                IF exp_i <= now_e THEN RETURN NULL; END IF;
                IF exp_i - iat_i < 1 OR exp_i - iat_i > 600 THEN RETURN NULL; END IF;
                -- 5) active key of the right class (unknown/revoked/retired -> NULL)
                SELECT k.secret, k.key_class INTO k_secret, k_class FROM public.ctx_keys k
                    WHERE k.key_id = kid AND k.status = 'active'
                      AND k.activated_at <= now()
                      AND (k.retired_at IS NULL OR k.retired_at > now());
                IF NOT FOUND THEN RETURN NULL; END IF;
                -- (assigned first: a CASE inside an IF condition would be cut at
                -- its inner THEN by the PL/pgSQL parser)
                k_expected := CASE purpose
                                WHEN 'worker_execution' THEN 'worker'
                                WHEN 'scheduler_reconcile' THEN 'scheduler'
                                ELSE 'api' END;
                IF k_class <> k_expected THEN RETURN NULL; END IF;
                -- 6) recompute the tag and compare in constant time
                want := public.hmac(
                    public.app_ctx_canon(v, kid, role, purpose, usr, ten, run, iat, exp, nonce),
                    k_secret, 'sha256');
                got := decode(mac, 'hex');
                IF octet_length(want) <> 32 OR octet_length(got) <> 32 THEN RETURN NULL; END IF;
                FOR i IN 0..31 LOOP
                    acc := acc | (get_byte(want, i) # get_byte(got, i));
                END LOOP;
                IF acc <> 0 THEN RETURN NULL; END IF;
                RETURN ROW(purpose, NULLIF(usr, '')::uuid, NULLIF(ten, '')::uuid,
                           NULLIF(run, '')::uuid, kid)::public.app_ctx_claims_t;
            END;
            $$
        """
    )
    op.execute("ALTER FUNCTION app_ctx_claims() OWNER TO nlw_ctx_verifier")
    _grant_exec("app_ctx_claims()", _CTX_ROLES)
    # Typed, purpose-gated accessors. SECURITY INVOKER: they only call the definer.
    op.execute(
        "CREATE FUNCTION ctx_purpose() RETURNS text LANGUAGE sql STABLE "
        "SET search_path = pg_catalog AS $$ SELECT (public.app_ctx_claims()).purpose $$"
    )
    op.execute(
        "CREATE FUNCTION ctx_user_id() RETURNS uuid LANGUAGE sql STABLE "
        "SET search_path = pg_catalog AS $$ "
        "SELECT c.user_id FROM public.app_ctx_claims() c "
        "WHERE c.purpose IN ('api_identity', 'api_request') $$"
    )
    op.execute(
        "CREATE FUNCTION ctx_tenant_id() RETURNS uuid LANGUAGE sql STABLE "
        "SET search_path = pg_catalog AS $$ "
        "SELECT c.tenant_id FROM public.app_ctx_claims() c "
        "WHERE c.purpose IN ('api_request', 'worker_execution') $$"
    )
    op.execute(
        "CREATE FUNCTION ctx_run_id() RETURNS uuid LANGUAGE sql STABLE "
        "SET search_path = pg_catalog AS $$ "
        "SELECT c.run_id FROM public.app_ctx_claims() c WHERE c.purpose = 'worker_execution' $$"
    )
    for fn in ("ctx_purpose()", "ctx_user_id()", "ctx_tenant_id()", "ctx_run_id()"):
        op.execute(f"ALTER FUNCTION {fn} OWNER TO nlw_ctx_verifier")
        _grant_exec(fn, _CTX_ROLES)

    # --- helpers now key off the VERIFIED human identity ------------------
    op.execute(_SQL_MEMBER_HELPER)
    op.execute(_SQL_ADMIN_HELPER)
    # Dead since P3A and an unsigned-GUC oracle reachable by nlw_app: remove it.
    op.execute("DROP FUNCTION IF EXISTS is_current_user_owner(uuid)")
    # Privileged write functions: verified identity (+ tenant for admin).
    op.execute(_SQL_CREATE_WORKSPACE)
    op.execute(_SQL_ACCEPT)
    op.execute(_SQL_MANAGE)

    # --- atomic policy cutover: drop EVERY legacy policy, install signed ones
    _drop_policies(_LEGACY_POLICIES)
    _create_policies(_POLICIES)


def downgrade() -> None:
    # SECURITY WARNING: re-installs unsigned-GUC trust (see module docstring).
    _drop_policies(_POLICIES)
    _create_policies(_LEGACY_POLICIES)
    op.execute(_SQL_MANAGE_LEGACY)
    op.execute(_SQL_ACCEPT_LEGACY)
    op.execute(_SQL_CREATE_WORKSPACE_LEGACY)
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
    _grant_exec("is_current_user_owner(uuid)", ("nlw_app",))
    op.execute(_SQL_ADMIN_HELPER_LEGACY)
    op.execute(_SQL_MEMBER_HELPER_LEGACY)
    for fn in ("ctx_run_id()", "ctx_tenant_id()", "ctx_user_id()", "ctx_purpose()"):
        op.execute(f"DROP FUNCTION IF EXISTS {fn}")
    op.execute("DROP FUNCTION IF EXISTS app_ctx_claims()")
    op.execute(
        "DROP FUNCTION IF EXISTS app_ctx_canon(text,text,text,text,text,text,text,text,text,text)"
    )
    op.execute("DROP TYPE IF EXISTS app_ctx_claims_t")
    op.execute("DROP TABLE IF EXISTS ctx_key_events")
    op.execute("DROP TABLE IF EXISTS ctx_keys")
