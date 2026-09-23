"""Post-restore validation (M11.5 P2).

Validates far more than row counts: migration revision, schema objects, critical
constraints/indexes, roles + attributes + ownership, RLS/FORCE-RLS, SECURITY
DEFINER function owners + hardened search_path + no unintended PUBLIC EXECUTE, and
application invariants (users isolation, connector scoping, approval binding,
external-action keys/states, P1D structures, and that restored non-terminal work
was quiesced with schedules recomputed after the recovery cutoff).

Produces a machine-readable result (list of named checks) + a concise human
summary. Neither contains customer data or secrets.
"""

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Engine

_RUNTIME_ROLES = ("nlw_app", "nlw_worker", "nlw_scheduler")
_ALL_ROLES = _RUNTIME_ROLES + (
    "nlw_rls_bypass",
    "nlw_workspace_bootstrap",
    "nlw_membership_admin",
    "nlw_ctx_verifier",
)
_FORCED_RLS_TABLES = (
    "users",
    "workflow_runs",
    "step_runs",
    "external_actions",
    "approvals",
    "schedules",
    "connectors",
    "workspace_invitations",
    "authz_audit_events",
)
_SECURITY_DEFINER_FUNCS = {
    "resolve_run_tenant": "nlw_rls_bypass",
    "is_current_user_member": "nlw_rls_bypass",
    "is_current_user_admin_or_owner": "nlw_rls_bypass",
    "enforce_workspace_owner_present": "nlw_rls_bypass",
    # P3B: the single signed-context verifier (owned by the dedicated verifier role)
    "app_ctx_claims": "nlw_ctx_verifier",
    "resolve_or_create_user": "nlw_workspace_bootstrap",
    "create_workspace_for_current_user": "nlw_workspace_bootstrap",
    "accept_workspace_invitation": "nlw_workspace_bootstrap",
    "manage_membership": "nlw_membership_admin",
    # M12B Part 4: fail-closed schedule authorization checker (0020).
    "schedule_creator_block_reason": "nlw_rls_bypass",
}
# The authorization audit must remain append-only for runtime roles after a
# restore: neither nlw_app nor nlw_worker may hold UPDATE or DELETE on it.
_APPEND_ONLY_AUDIT_ROLES = ("nlw_app", "nlw_worker")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


def _q(conn: Any, sql: str, **params: Any) -> Any:
    return conn.execute(text(sql), params)


def validate_restore(engine: Engine, *, expected_revision: str | None = None) -> dict[str, Any]:
    checks: list[Check] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append(Check(name=name, ok=ok, detail=detail))

    with engine.connect() as conn:
        # --- migrations / schema ---
        rev = _q(conn, "SELECT version_num FROM alembic_version").scalar_one_or_none()
        add(
            "alembic_revision_matches_manifest",
            expected_revision is None or rev == expected_revision,
            f"restored={rev} expected={expected_revision}",
        )
        tables = {
            r[0]
            for r in _q(
                conn,
                "SELECT table_name FROM information_schema.tables WHERE table_schema='public'",
            ).all()
        }
        required = set(_FORCED_RLS_TABLES) | {"dr_restore_events", "alembic_version"}
        missing = sorted(required - tables)
        add("required_tables_present", not missing, f"missing={missing}")
        cons = {r[0] for r in _q(conn, "SELECT conname FROM pg_constraint").all()}
        need_cons = {
            "uq_run_schedule_occurrence",
            "uq_approval_run_step",
            "uq_external_action_run_step",
            "ck_run_status",
            "ck_external_action_status",
        }
        add(
            "critical_constraints_present",
            need_cons <= cons,
            f"missing={sorted(need_cons - cons)}",
        )
        idx = {r[0] for r in _q(conn, "SELECT indexname FROM pg_indexes").all()}
        recon = {
            "ix_workflow_runs_recon_pending",
            "ix_workflow_runs_recon_running",
            "ix_workflow_runs_recon_waiting",
        }
        add("p1d_recon_indexes_present", recon <= idx, f"missing={sorted(recon - idx)}")
        unknown_ok = bool(
            _q(
                conn,
                "SELECT 1 FROM pg_constraint WHERE conname='ck_external_action_status' "
                "AND pg_get_constraintdef(oid) LIKE '%unknown%'",
            ).scalar_one_or_none()
        )
        add("external_action_unknown_status_allowed", unknown_ok, "P1C 'unknown' terminal state")
        add(
            "last_progress_at_column_present",
            bool(
                _q(
                    conn,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='workflow_runs' "
                    "AND column_name='last_progress_at'",
                ).scalar_one_or_none()
            ),
            "P1D progress column",
        )

        # --- roles / authorization ---
        roles = {
            r[0]: (r[1], r[2])
            for r in _q(conn, "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles").all()
        }
        add("expected_roles_present", set(_ALL_ROLES) <= set(roles), f"have={sorted(roles)}")
        bad_runtime = [r for r in _RUNTIME_ROLES if r in roles and (roles[r][0] or roles[r][1])]
        add(
            "runtime_roles_nosuperuser_nobypassrls",
            not bad_runtime,
            f"violating={bad_runtime}",
        )
        owners = {
            r[0]: r[1]
            for r in _q(
                conn,
                "SELECT tablename, tableowner FROM pg_tables WHERE schemaname='public'",
            ).all()
        }
        # Ownership must be CONSISTENT and belong to the privileged owner role we
        # connect as (the migration/owner role — ``nlw`` in production). We assert
        # topology-agnostically: every forced-RLS table is owned by current_user,
        # and current_user is a superuser (the owner that bypasses FORCE RLS for
        # dump/restore/quiescence). This holds whatever the owner is named.
        current_user = _q(conn, "SELECT current_user").scalar_one()
        wrong_owner = [t for t in _FORCED_RLS_TABLES if owners.get(t) != current_user]
        owner_is_super = bool(
            _q(
                conn,
                "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
            ).scalar_one_or_none()
        )
        add(
            "tables_owned_by_privileged_owner",
            not wrong_owner and owner_is_super,
            f"owner={current_user} super={owner_is_super} wrong_owner={wrong_owner}",
        )

        # --- RLS + FORCE ---
        rls = {
            r[0]: (r[1], r[2])
            for r in _q(
                conn,
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'",
            ).all()
        }
        not_forced = [t for t in _FORCED_RLS_TABLES if rls.get(t) != (True, True)]
        add("rls_enabled_and_forced", not not_forced, f"not_forced={not_forced}")

        # --- SECURITY DEFINER functions ---
        funcs = {
            r[0]: (r[1], r[2], r[3])
            for r in _q(
                conn,
                "SELECT p.proname, r.rolname, p.prosecdef, "
                "  array_to_string(p.proconfig, ',') "
                "FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner "
                "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'",
            ).all()
        }
        secdef_issues = []
        for fn, expected_owner in _SECURITY_DEFINER_FUNCS.items():
            if fn not in funcs:
                secdef_issues.append(f"{fn}:absent")
                continue
            owner, secdef, cfg = funcs[fn]
            if owner != expected_owner:
                secdef_issues.append(f"{fn}:owner={owner}")
            if not secdef:
                secdef_issues.append(f"{fn}:not-secdef")
            if not cfg or "search_path" not in cfg:
                secdef_issues.append(f"{fn}:search_path-unset")
        add("security_definer_owners_and_search_path", not secdef_issues, f"issues={secdef_issues}")
        # No unintended PUBLIC EXECUTE on the SECURITY DEFINER helpers.
        public_exec = _q(
            conn,
            "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='public' AND p.prosecdef "
            "AND has_function_privilege('public', p.oid, 'EXECUTE')",
        ).all()
        add(
            "no_public_execute_on_secdef",
            not public_exec,
            f"public_exec={[r[0] for r in public_exec]}",
        )

        # --- authorization audit is append-only for runtime roles (P3A) ---
        audit_writable = [
            f"{role}:{priv}"
            for role in _APPEND_ONLY_AUDIT_ROLES
            for priv in ("UPDATE", "DELETE")
            if bool(
                _q(
                    conn,
                    "SELECT has_table_privilege(:r, 'authz_audit_events', :p)",
                    r=role,
                    p=priv,
                ).scalar_one_or_none()
            )
        ]
        add(
            "authz_audit_append_only_for_runtime_roles",
            not audit_writable,
            f"writable={audit_writable}",
        )

        # --- P3A membership/invitation/provenance objects survived the restore ---
        cons = {
            r[0]
            for r in _q(
                conn,
                "SELECT conname FROM pg_constraint WHERE conrelid = "
                "'public.workspace_invitations'::regclass",
            ).all()
        }
        missing_inv_cons = {
            "ck_invitation_role",
            "ck_invitation_status",
            "uq_invitation_token_hash",
        } - cons
        add(
            "invitation_constraints_present",
            not missing_inv_cons,
            f"missing={sorted(missing_inv_cons)}",
        )
        has_pending_idx = bool(
            _q(
                conn,
                "SELECT 1 FROM pg_indexes WHERE schemaname='public' "
                "AND indexname='uq_invitation_pending_email'",
            ).scalar_one_or_none()
        )
        add("invitation_pending_unique_index_present", has_pending_idx, "partial unique index")
        # Invitations are least-privilege for nlw_app: SELECT+INSERT, column-scoped
        # UPDATE, and crucially NO DELETE. Only the hash is stored (no raw column).
        inv_delete = bool(
            _q(
                conn,
                "SELECT has_table_privilege('nlw_app', 'workspace_invitations', 'DELETE')",
            ).scalar_one()
        )
        inv_cols = {
            r[0]
            for r in _q(
                conn,
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema='public' AND table_name='workspace_invitations'",
            ).all()
        }
        add(
            "invitations_hash_only_and_no_app_delete",
            (not inv_delete) and "token_hash" in inv_cols and "token" not in inv_cols,
            f"app_delete={inv_delete} has_token_col={'token' in inv_cols}",
        )

        # nlw_membership_admin (manage_membership owner) blast radius: exactly
        # memberships DML + audit INSERT, nothing on unrelated sensitive tables.
        ma_ok = all(
            bool(
                _q(
                    conn, "SELECT has_table_privilege('nlw_membership_admin', :t, :p)", t=t, p=p
                ).scalar_one()
            )
            for t, p in (
                ("memberships", "SELECT"),
                ("memberships", "UPDATE"),
                ("memberships", "DELETE"),
                ("authz_audit_events", "INSERT"),
            )
        )
        ma_leak = [
            f"{t}:{p}"
            for t in ("users", "workspaces", "connectors", "dr_restore_events", "approvals")
            for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
            if bool(
                _q(
                    conn, "SELECT has_table_privilege('nlw_membership_admin', :t, :p)", t=t, p=p
                ).scalar_one()
            )
        ]
        add(
            "membership_admin_least_privilege",
            ma_ok and not ma_leak,
            f"has_needed={ma_ok} leak={ma_leak}",
        )
        # PUBLIC cannot execute the privileged membership/invitation functions.
        pub_exec = [
            sig
            for sig in (
                "public.manage_membership(uuid, uuid, text, text)",
                "public.accept_workspace_invitation(text)",
            )
            if bool(
                _q(
                    conn, "SELECT has_function_privilege('public', :s, 'EXECUTE')", s=sig
                ).scalar_one()
            )
        ]
        add("privileged_funcs_no_public_execute", not pub_exec, f"public_exec={pub_exec}")
        # search_path is hardened to exactly pg_catalog for the P3A definers.
        bad_search_path = [
            r[0]
            for r in _q(
                conn,
                "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname='public' AND p.proname IN "
                "('manage_membership','accept_workspace_invitation','app_ctx_claims',"
                "'enforce_workspace_owner_present') "
                "AND array_to_string(p.proconfig, ',') <> 'search_path=pg_catalog'",
            ).all()
        ]
        add("p3a_definers_search_path_pg_catalog", not bad_search_path, f"bad={bad_search_path}")
        # Approval requester provenance: column present, and immutable for nlw_app
        # (no column-level UPDATE grant on requested_by_user_id).
        req_col = bool(
            _q(
                conn,
                "SELECT 1 FROM information_schema.columns WHERE table_schema='public' "
                "AND table_name='approvals' AND column_name='requested_by_user_id'",
            ).scalar_one_or_none()
        )
        req_writable = bool(
            _q(
                conn,
                "SELECT has_column_privilege('nlw_app', 'approvals', 'requested_by_user_id', "
                "'UPDATE')",
            ).scalar_one()
        )
        add(
            "approval_requester_present_and_immutable",
            req_col and not req_writable,
            f"col={req_col} app_can_write={req_writable}",
        )
        # Provenance/decision immutability triggers survived the restore.
        trg = {
            r[0]
            for r in _q(
                conn,
                "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal AND tgname IN "
                "('trg_approval_immutable','trg_run_initiator_immutable',"
                "'trg_schedule_creator_immutable','trg_workspace_owner_present')",
            ).all()
        }
        missing_trg = {
            "trg_approval_immutable",
            "trg_run_initiator_immutable",
            "trg_schedule_creator_immutable",
            "trg_workspace_owner_present",
        } - trg
        add(
            "provenance_immutability_triggers_present",
            not missing_trg,
            f"missing={sorted(missing_trg)}",
        )

        # --- P3B signed database context survived the restore ------------------
        add(
            "pgcrypto_present",
            bool(
                _q(conn, "SELECT 1 FROM pg_extension WHERE extname='pgcrypto'").scalar_one_or_none()
            ),
            "HMAC verification extension",
        )
        # The key registry: present, owned by the dedicated verifier role, and NO
        # privilege for any login role or PUBLIC (symmetric signing-capable
        # material must be unreadable to every runtime role).
        reg_owner = _q(
            conn, "SELECT tableowner FROM pg_tables WHERE tablename='ctx_keys'"
        ).scalar_one_or_none()
        reg_leak = [
            f"{role}:{priv}"
            for role in (*_RUNTIME_ROLES, "public")
            for priv in ("SELECT", "INSERT", "UPDATE", "DELETE")
            if bool(
                _q(
                    conn, "SELECT has_table_privilege(:r, 'ctx_keys', :p)", r=role, p=priv
                ).scalar_one_or_none()
            )
        ]
        ev_leak = [
            f"{role}:{priv}"
            for role in (*_RUNTIME_ROLES, "public")
            for priv in ("SELECT", "INSERT", "UPDATE", "DELETE")
            if bool(
                _q(
                    conn,
                    "SELECT has_table_privilege(:r, 'ctx_key_events', :p)",
                    r=role,
                    p=priv,
                ).scalar_one_or_none()
            )
        ]
        add(
            "ctx_keys_registry_protected",
            reg_owner == "nlw_ctx_verifier" and not reg_leak and not ev_leak,
            f"owner={reg_owner} leak={reg_leak} events_leak={ev_leak}",
        )
        # Verifier + accessors: present, hardened search_path, no PUBLIC EXECUTE,
        # verifier is SECURITY DEFINER owned by the verifier role.
        vfn = {
            r[0]: (r[1], r[2], r[3], r[4])
            for r in _q(
                conn,
                "SELECT p.proname, r.rolname, p.prosecdef, "
                "  array_to_string(p.proconfig, ','), "
                "  has_function_privilege('public', p.oid, 'EXECUTE') "
                "FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner "
                "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' "
                "AND p.proname IN ('app_ctx_claims','app_ctx_canon','ctx_user_id',"
                "'ctx_tenant_id','ctx_run_id','ctx_purpose')",
            ).all()
        }
        vissues = []
        for fn in (
            "app_ctx_claims",
            "app_ctx_canon",
            "ctx_user_id",
            "ctx_tenant_id",
            "ctx_run_id",
            "ctx_purpose",
        ):
            if fn not in vfn:
                vissues.append(f"{fn}:absent")
                continue
            owner, secdef, cfg, pub = vfn[fn]
            if owner != "nlw_ctx_verifier":
                vissues.append(f"{fn}:owner={owner}")
            if cfg != "search_path=pg_catalog":
                vissues.append(f"{fn}:search_path={cfg}")
            if pub:
                vissues.append(f"{fn}:public-execute")
            if fn == "app_ctx_claims" and not secdef:
                vissues.append(f"{fn}:not-secdef")
        add("ctx_verifier_functions_hardened", not vissues, f"issues={vissues}")
        # THE cutover invariant: no live policy or helper trusts the unsigned GUCs,
        # none is unconditional, and the full inventory is present.
        pols = _q(
            conn,
            "SELECT policyname, coalesce(qual,''), coalesce(with_check,'') FROM pg_policies "
            "WHERE schemaname='public'",
        ).all()
        legacy = [
            p[0] for p in pols if "app.user_id" in p[1] + p[2] or "app.tenant_id" in p[1] + p[2]
        ]
        uncond = [
            p[0]
            for p in pols
            if p[1].strip() in ("true", "(true)") or p[2].strip() in ("true", "(true)")
        ]
        helper_legacy = [
            r[0]
            for r in _q(
                conn,
                "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname='public' AND (p.prosrc LIKE '%app.user_id%' "
                "OR p.prosrc LIKE '%app.tenant_id%')",
            ).all()
        ]
        add(
            "no_policy_trusts_unsigned_context",
            not legacy and not uncond and not helper_legacy and len(pols) == 51,
            f"legacy={legacy} unconditional={uncond} helpers={helper_legacy} n={len(pols)}",
        )

        # --- application invariants ---
        add(
            "external_action_key_not_null",
            not bool(
                _q(
                    conn, "SELECT 1 FROM external_actions WHERE external_action_key IS NULL LIMIT 1"
                ).scalar_one_or_none()
            ),
            "stable idempotency keys preserved",
        )
        # Restored non-terminal work was quiesced.
        non_terminal_runs = int(
            _q(
                conn,
                "SELECT count(*) FROM workflow_runs "
                "WHERE status IN ('PENDING','RUNNING','WAITING_APPROVAL')",
            ).scalar_one()
        )
        add("non_terminal_runs_quiesced", non_terminal_runs == 0, f"remaining={non_terminal_runs}")
        pending_actions = int(
            _q(conn, "SELECT count(*) FROM external_actions WHERE status='pending'").scalar_one()
        )
        add("no_pending_external_actions", pending_actions == 0, f"remaining={pending_actions}")
        # Schedules recomputed after the recovery cutoff (from the latest event).
        cutoff = _q(
            conn, "SELECT cutoff_at FROM dr_restore_events ORDER BY restored_at DESC LIMIT 1"
        ).scalar_one_or_none()
        if cutoff is None:
            add("dr_restore_event_recorded", False, "no dr_restore_events row")
            add("schedules_after_recovery_cutoff", False, "no cutoff to check against")
        else:
            add("dr_restore_event_recorded", True, "quiescence audited")
            stale = int(
                _q(
                    conn,
                    "SELECT count(*) FROM schedules WHERE next_run_at <= :c",
                    c=cutoff,
                ).scalar_one()
            )
            add("schedules_after_recovery_cutoff", stale == 0, f"stale={stale}")

        # --- functional (read-only) ---
        add(
            "read_only_verification_query",
            _q(conn, "SELECT 1").scalar_one() == 1,
            "restored DB answers a read query",
        )

    ok = all(c.ok for c in checks)
    return {"ok": ok, "checks": [asdict(c) for c in checks]}


def human_summary(report: dict[str, Any]) -> str:
    lines = [f"restore validation: {'PASS' if report['ok'] else 'FAIL'}"]
    for c in report["checks"]:
        mark = "ok " if c["ok"] else "FAIL"
        detail = f" — {c['detail']}" if (not c["ok"] and c["detail"]) else ""
        lines.append(f"  [{mark}] {c['name']}{detail}")
    return "\n".join(lines)
