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
_ALL_ROLES = _RUNTIME_ROLES + ("nlw_rls_bypass", "nlw_workspace_bootstrap")
_FORCED_RLS_TABLES = (
    "users",
    "workflow_runs",
    "step_runs",
    "external_actions",
    "approvals",
    "schedules",
    "connectors",
)
_SECURITY_DEFINER_FUNCS = {
    "resolve_run_tenant": "nlw_rls_bypass",
    "is_current_user_member": "nlw_rls_bypass",
    "is_current_user_admin_or_owner": "nlw_rls_bypass",
    "resolve_or_create_user": "nlw_workspace_bootstrap",
    "create_workspace_for_current_user": "nlw_workspace_bootstrap",
}


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
