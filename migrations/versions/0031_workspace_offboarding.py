"""Workspace offboarding (Phase 2 plan section 0.6; ADR-037).

- ``workspaces.status``: ``ACTIVE -> OFFBOARDING -> OFFBOARDED`` only, set by
  the operator (owner connection) alone; an OFFBOARDED row is the tombstone
  (name and slug scrubbed, ids, timestamps, the operator label, row counts and
  the receipt id kept) and never changes again. Created workspaces are ACTIVE.
- ``workspace_is_active(uuid)`` (SECURITY DEFINER, ``nlw_rls_bypass``): the one
  check. ``ctx_tenant_id()`` and ``ctx_ingest_tenant_id()`` return NULL for a
  workspace that is not ACTIVE, so every tenant policy of the API, worker and
  ingest runtime denies it at once, whatever signed context a caller holds.
  ``schedule_creator_block_reason`` returns ``WORKSPACE_NOT_ACTIVE``.
- ``enforce_workspace_owner_present`` no longer requires an owner once the
  workspace is not ACTIVE, so offboarding can remove its memberships.
- Reason code ``WORKSPACE_OFFBOARDING``: the operator moves the workspace's
  datasets to DELETING with it.
- Independent review of PR #70: ``accept_workspace_invitation`` refuses an
  invitation into a workspace that is not ACTIVE (it is SECURITY DEFINER and
  never read the tenant context); the discovery policy ``workspaces_app_select``
  and the scheduler's ``workflow_runs`` policies exclude a non-ACTIVE workspace.
  Policies are altered in place (the count stays 74).

No table and no RLS policy is added (the signed policy count stays 74).

DOWNGRADE: disposable databases only. Refused while any workspace is not
ACTIVE or any ``WORKSPACE_OFFBOARDING`` event exists.

Revision ID: 0031_workspace_offboarding
Revises: 0030_inactive_version_retention
Create Date: 2026-10-15
"""

import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

from alembic import op

revision: str = "0031_workspace_offboarding"
down_revision: str | Sequence[str] | None = "0030_inactive_version_retention"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_REASON_CODES = ("WORKSPACE_OFFBOARDING",)
STATUSES = ("ACTIVE", "OFFBOARDING", "OFFBOARDED")
RUNTIME_ROLES = (
    "nlw_app",
    "nlw_worker",
    "nlw_scheduler",
    "nlw_ingest",
    "nlw_ingest_dispatch",
    "nlw_workspace_bootstrap",
    "nlw_membership_admin",
)
# Every role that may evaluate a tenant accessor (0016 _CTX_ROLES, plus 0026).
ACCESSOR_ROLES = (
    "nlw_app",
    "nlw_worker",
    "nlw_scheduler",
    "nlw_rls_bypass",
    "nlw_workspace_bootstrap",
    "nlw_membership_admin",
    "nlw_ingest",
)


def _load(filename: str) -> ModuleType:
    name = f"_nlw_migration_{filename.removesuffix('.py')}"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _m0030() -> ModuleType:
    return _load("0030_inactive_version_retention.py")


def _m0016() -> ModuleType:
    return _load("0016_signed_database_context.py")


_INVALID = "           OR v_inv.email <> v_email THEN\n"
_INVALID_0031 = (
    "           OR v_inv.email <> v_email\n"
    "           OR NOT public.workspace_is_active(v_inv.tenant_id) THEN\n"
)


def accept_0031() -> str:
    original: str = _m0016()._SQL_ACCEPT
    assert original.count(_INVALID) == 1
    return original.replace(_INVALID, _INVALID_0031)


_DISCOVERY_0016 = "(public.is_current_user_member(id))"
_DISCOVERY_0031 = "(public.is_current_user_member(id) AND public.workspace_is_active(id))"
_SCHED_0016 = "(public.ctx_purpose() = 'scheduler_reconcile')"
_SCHED_0031 = (
    "(public.ctx_purpose() = 'scheduler_reconcile' AND public.workspace_is_active(tenant_id))"
)


def _alter_policies(discovery: str, sched: str) -> None:
    op.execute(f"ALTER POLICY workspaces_app_select ON workspaces USING {discovery}")
    op.execute(f"ALTER POLICY workflow_runs_sched_select ON workflow_runs USING {sched}")
    op.execute(f"ALTER POLICY workflow_runs_sched_insert ON workflow_runs WITH CHECK {sched}")


def reason_codes() -> tuple[str, ...]:
    return (*_m0030().reason_codes(), *NEW_REASON_CODES)


_ACTIVE = "public.workspace_is_active(c.tenant_id)"

CTX_TENANT_ID = (
    "CREATE OR REPLACE FUNCTION ctx_tenant_id() RETURNS uuid LANGUAGE sql STABLE "
    "SET search_path = pg_catalog AS $$ "
    "SELECT c.tenant_id FROM public.app_ctx_claims() c "
    f"WHERE c.purpose IN ('api_request', 'worker_execution') AND {_ACTIVE} $$"
)
CTX_INGEST_TENANT_ID = (
    "CREATE OR REPLACE FUNCTION ctx_ingest_tenant_id() RETURNS uuid LANGUAGE sql STABLE "
    "SET search_path = pg_catalog AS $$ "
    "SELECT c.tenant_id FROM public.app_ctx_claims() c "
    f"WHERE c.purpose = 'dataset_ingest' AND {_ACTIVE} $$"
)
_CTX_TENANT_ID_0016 = (
    "CREATE OR REPLACE FUNCTION ctx_tenant_id() RETURNS uuid LANGUAGE sql STABLE "
    "SET search_path = pg_catalog AS $$ "
    "SELECT c.tenant_id FROM public.app_ctx_claims() c "
    "WHERE c.purpose IN ('api_request', 'worker_execution') $$"
)
_CTX_INGEST_TENANT_ID_0026 = (
    "CREATE OR REPLACE FUNCTION ctx_ingest_tenant_id() RETURNS uuid LANGUAGE sql STABLE "
    "SET search_path = pg_catalog AS $$ "
    "SELECT c.tenant_id FROM public.app_ctx_claims() c WHERE c.purpose = 'dataset_ingest' $$"
)

_WORKSPACE_IS_ACTIVE = """
CREATE FUNCTION workspace_is_active(p_workspace uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
    AS $$
        SELECT COALESCE(
            (SELECT w.status = 'ACTIVE' FROM public.workspaces w WHERE w.id = p_workspace),
            false
        )
    $$
"""

_listed_runtime = ", ".join(f"'{r}'" for r in RUNTIME_ROLES)
_WORKSPACES_GUARD = f"""
CREATE FUNCTION workspaces_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog
    AS $$
    BEGIN
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'ACTIVE' OR NEW.offboarding_requested_at IS NOT NULL
               OR NEW.offboarded_at IS NOT NULL OR NEW.offboarded_by IS NOT NULL
               OR NEW.offboard_receipt_id IS NOT NULL OR NEW.offboard_counts IS NOT NULL THEN
                RAISE EXCEPTION 'a workspace is created ACTIVE' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END IF;
        IF TG_OP = 'DELETE' THEN
            IF OLD.status <> 'ACTIVE' THEN
                RAISE EXCEPTION 'an offboarding or offboarded workspace is never deleted'
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN OLD;
        END IF;
        IF OLD.status = 'OFFBOARDED' THEN
            RAISE EXCEPTION 'an offboarded workspace never changes'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.status IS DISTINCT FROM OLD.status THEN
            IF session_user IN ({_listed_runtime}) THEN
                RAISE EXCEPTION 'only the operator changes a workspace status'
                    USING ERRCODE = 'insufficient_privilege';
            END IF;
            IF NOT ((OLD.status = 'ACTIVE' AND NEW.status = 'OFFBOARDING')
                    OR (OLD.status = 'OFFBOARDING' AND NEW.status = 'OFFBOARDED')) THEN
                RAISE EXCEPTION 'workspace transition % -> % is not allowed',
                    OLD.status, NEW.status USING ERRCODE = 'check_violation';
            END IF;
        END IF;
        IF NEW.status = 'OFFBOARDING' AND (NEW.offboarding_requested_at IS NULL
                OR NEW.offboarded_at IS NOT NULL OR NEW.offboard_receipt_id IS NOT NULL) THEN
            RAISE EXCEPTION 'an offboarding workspace records its request time only'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.status = 'OFFBOARDED' AND (NEW.offboarded_at IS NULL
                OR NEW.offboarded_by IS NULL OR NEW.offboard_receipt_id IS NULL
                OR NEW.offboard_counts IS NULL) THEN
            RAISE EXCEPTION 'an offboarded workspace records its time, operator, receipt and counts'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.status <> 'OFFBOARDED' AND OLD.status <> 'ACTIVE'
           AND (NEW.name IS DISTINCT FROM OLD.name OR NEW.slug IS DISTINCT FROM OLD.slug) THEN
            RAISE EXCEPTION 'an offboarding workspace is renamed only by its tombstone'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END;
    $$
"""

_OWNER_PRESENT_0031 = """
CREATE OR REPLACE FUNCTION enforce_workspace_owner_present() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
    AS $$
    DECLARE
        v_ws uuid := COALESCE(OLD.workspace_id, NEW.workspace_id);
        v_owners int;
    BEGIN
        PERFORM pg_catalog.pg_advisory_xact_lock(
            pg_catalog.hashtextextended(v_ws::text, 0)
        );
        -- 0031: a workspace being offboarded loses its memberships, owners too.
        IF NOT public.workspace_is_active(v_ws) THEN
            RETURN NULL;
        END IF;
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

_OWNER_PRESENT_0015 = """
CREATE OR REPLACE FUNCTION enforce_workspace_owner_present() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
    AS $$
    DECLARE
        v_ws uuid := COALESCE(OLD.workspace_id, NEW.workspace_id);
        v_owners int;
    BEGIN
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


def _schedule_block(with_workspace: bool) -> str:
    first = (
        "WHEN NOT public.workspace_is_active(s.tenant_id) THEN 'WORKSPACE_NOT_ACTIVE'"
        if (with_workspace)
        else ""
    )
    return f"""
CREATE OR REPLACE FUNCTION schedule_creator_block_reason(p_schedule_id uuid) RETURNS text
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog
    AS $$
        SELECT CASE
            {first}
            WHEN m.role IS NULL THEN 'CREATOR_NOT_A_MEMBER'
            WHEN m.role NOT IN ('owner', 'admin') THEN 'CREATOR_ROLE_INSUFFICIENT'
            ELSE NULL
        END
        FROM public.schedules s
        LEFT JOIN public.memberships m
          ON m.user_id = s.created_by AND m.workspace_id = s.tenant_id
        WHERE s.id = p_schedule_id
    $$
"""


def upgrade() -> None:
    listed = ", ".join(f"'{s}'" for s in STATUSES)
    op.execute(
        "ALTER TABLE workspaces "
        "ADD COLUMN status text NOT NULL DEFAULT 'ACTIVE', "
        "ADD COLUMN offboarding_requested_at timestamptz, "
        "ADD COLUMN offboarded_at timestamptz, "
        "ADD COLUMN offboarded_by text, "
        "ADD COLUMN offboard_receipt_id text, "
        "ADD COLUMN offboard_counts jsonb, "
        f"ADD CONSTRAINT workspaces_status_check CHECK (status IN ({listed})), "
        "ADD CONSTRAINT workspaces_offboarded_by_check CHECK "
        "(offboarded_by IS NULL OR offboarded_by ~ '^[A-Za-z0-9._-]{1,64}$')"
    )
    op.execute(_WORKSPACES_GUARD)
    op.execute(
        "CREATE TRIGGER workspaces_guard BEFORE INSERT OR UPDATE OR DELETE ON workspaces "
        "FOR EACH ROW EXECUTE FUNCTION workspaces_guard()"
    )
    op.execute("REVOKE ALL ON FUNCTION workspaces_guard() FROM PUBLIC")

    op.execute("GRANT SELECT (id, status) ON workspaces TO nlw_rls_bypass")
    op.execute(_WORKSPACE_IS_ACTIVE)
    op.execute("ALTER FUNCTION workspace_is_active(uuid) OWNER TO nlw_rls_bypass")
    op.execute("REVOKE ALL ON FUNCTION workspace_is_active(uuid) FROM PUBLIC")
    for role in ACCESSOR_ROLES:
        op.execute(f"GRANT EXECUTE ON FUNCTION workspace_is_active(uuid) TO {role}")

    op.execute(CTX_TENANT_ID)
    op.execute(CTX_INGEST_TENANT_ID)
    op.execute(_OWNER_PRESENT_0031)
    op.execute(_schedule_block(True))
    op.execute(accept_0031())
    _alter_policies(_DISCOVERY_0031, _SCHED_0031)
    _m0030()._m0029()._m0028()._replace_reason_check(reason_codes())


def downgrade() -> None:
    op.execute(
        """
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM workspaces WHERE status <> 'ACTIVE')
               OR EXISTS (SELECT 1 FROM dataset_events
                          WHERE reason_code = 'WORKSPACE_OFFBOARDING') THEN
                RAISE EXCEPTION '0031 downgrade refused: a workspace was offboarded '
                    '(disposable databases only)' USING ERRCODE = '55000';
            END IF;
        END $$
        """
    )
    _m0030()._m0029()._m0028()._replace_reason_check(_m0030().reason_codes())
    _alter_policies(_DISCOVERY_0016, _SCHED_0016)
    op.execute(_m0016()._SQL_ACCEPT)
    op.execute(_schedule_block(False))
    op.execute(_OWNER_PRESENT_0015)
    op.execute(_CTX_INGEST_TENANT_ID_0026)
    op.execute(_CTX_TENANT_ID_0016)
    op.execute("DROP FUNCTION workspace_is_active(uuid)")
    op.execute("REVOKE SELECT (id, status) ON workspaces FROM nlw_rls_bypass")
    op.execute("DROP TRIGGER workspaces_guard ON workspaces")
    op.execute("DROP FUNCTION workspaces_guard()")
    op.execute(
        "ALTER TABLE workspaces DROP CONSTRAINT workspaces_offboarded_by_check, "
        "DROP CONSTRAINT workspaces_status_check, DROP COLUMN offboard_counts, "
        "DROP COLUMN offboard_receipt_id, DROP COLUMN offboarded_by, "
        "DROP COLUMN offboarded_at, DROP COLUMN offboarding_requested_at, DROP COLUMN status"
    )
