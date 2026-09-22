"""Migration reversibility for the P1A migration (and the full chain).

Exercises the required matrix against a real Postgres with the runtime roles
bootstrapped: head -> previous -> head -> base -> head. Proves the P1A migration
(and every migration below it) downgrades and re-upgrades cleanly, and that the
prior ``users``/``connectors`` grants+policies are restored on downgrade.
"""

import uuid
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.config import Config

pytestmark = pytest.mark.integration

_HEAD = "0016_signed_database_context"
# The P3A revision just below the P3B head (for the 0016 up/down/up test).
_P3A = "0015_membership_approval_sod"
_P2 = "0014_dr_restore_events"
_PREV = "0011_identity_connector_authz"
# The P1C revision just below the P1D head (for the 0013 up/down/up test).
_P1C = "0012_action_unknown_outcome"
# The P1D revision just below the P2 head (for the 0014 up/down/up test).
_P1D = "0013_scheduler_reconciler"
# The P1A revision whose users/connectors posture the matrix below asserts.
_P1A = "0011_identity_connector_authz"
_P1A_PREV = "0010_readiness_schema_grant"


def _one(cur: Any) -> tuple[Any, ...]:
    row = cur.fetchone()
    assert row is not None
    return row  # type: ignore[no-any-return]


def _cfg(owner_sa: str) -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", owner_sa)
    return cfg


def _users_posture(owner_libpq: str) -> dict[str, Any]:
    with psycopg.connect(owner_libpq) as c:
        rls = _one(
            c.execute(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname='users'"
            )
        )
        grants = sorted(
            r[0]
            for r in c.execute(
                "SELECT privilege_type FROM information_schema.role_table_grants "
                "WHERE table_name='users' AND grantee='nlw_app'"
            ).fetchall()
        )
        fn = _one(c.execute("SELECT count(*) FROM pg_proc WHERE proname='resolve_or_create_user'"))[
            0
        ]
        policies = sorted(
            r[0]
            for r in c.execute(
                "SELECT policyname FROM pg_policies WHERE tablename='users'"
            ).fetchall()
        )
        # Column-level UPDATE(email) is not in role_table_grants; check separately.
        upd_cols = sorted(
            r[0]
            for r in c.execute(
                "SELECT column_name FROM information_schema.column_privileges "
                "WHERE table_name='users' AND grantee='nlw_app' AND privilege_type='UPDATE'"
            ).fetchall()
        )
    return {
        "rls": rls,
        "app_grants": grants,
        "bootstrap_fn": fn,
        "policies": policies,
        "app_update_cols": upd_cols,
    }


def test_reversibility_matrix(pg_stack: SimpleNamespace) -> None:
    cfg = _cfg(pg_stack.owner_sa)

    # pg_stack already applied head. Verify the P1A posture.
    at_head = _users_posture(pg_stack.owner_libpq)
    assert at_head["rls"] == (True, True)
    assert at_head["app_grants"] == ["SELECT"]  # table-level; UPDATE is column-only
    assert at_head["app_update_cols"] == ["email", "updated_at"]
    assert at_head["policies"] == ["users_app_self_select", "users_app_self_update"]
    assert at_head["bootstrap_fn"] == 1

    # down to pre-P1A: restores the pre-P1A posture exactly.
    command.downgrade(cfg, _P1A_PREV)
    at_prev = _users_posture(pg_stack.owner_libpq)
    assert at_prev["rls"] == (False, False)
    assert at_prev["app_grants"] == ["INSERT", "SELECT", "UPDATE"]
    # The restored table-level UPDATE covers every column (the old broad posture);
    # crucially auth_provider_id is writable again — that is the re-opened defect.
    assert "auth_provider_id" in at_prev["app_update_cols"]
    assert at_prev["policies"] == []
    assert at_prev["bootstrap_fn"] == 0

    # back up to head again.
    command.upgrade(cfg, _HEAD)
    assert _users_posture(pg_stack.owner_libpq)["rls"] == (True, True)

    # head -> base -> head: the whole chain is reversible.
    command.downgrade(cfg, "base")
    with psycopg.connect(pg_stack.owner_libpq) as c:
        tables = _one(
            c.execute(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema='public' AND table_name IN ('users','connectors')"
            )
        )[0]
    assert tables == 0  # base leaves no app tables

    command.upgrade(cfg, _HEAD)
    final = _users_posture(pg_stack.owner_libpq)
    assert final["rls"] == (True, True)
    assert final["app_grants"] == ["SELECT"]
    assert final["bootstrap_fn"] == 1


def test_connectors_insert_policy_flips_with_migration(pg_stack: SimpleNamespace) -> None:
    cfg = _cfg(pg_stack.owner_sa)

    def _insert_check() -> str:
        with psycopg.connect(pg_stack.owner_libpq) as c:
            return str(
                _one(
                    c.execute(
                        "SELECT with_check FROM pg_policies "
                        "WHERE tablename='connectors' AND policyname='connectors_app_insert'"
                    )
                )[0]
            )

    # At head: admin/owner required.
    assert "is_current_user_admin_or_owner" in _insert_check()
    # Downgrade below P1A restores the member-level check.
    command.downgrade(cfg, _P1A_PREV)
    assert "is_current_user_member" in _insert_check()
    # Re-upgrade restores the admin/owner boundary.
    command.upgrade(cfg, _HEAD)
    assert "is_current_user_admin_or_owner" in _insert_check()


def _status_check(owner_libpq: str) -> str:
    with psycopg.connect(owner_libpq) as c:
        return str(
            _one(
                c.execute(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname='ck_external_action_status'"
                )
            )[0]
        )


def test_external_action_unknown_status_flips_with_migration(pg_stack: SimpleNamespace) -> None:
    """0012 adds the terminal 'unknown' external-action status; downgrade removes
    it (rewriting any unknown row -> failed) and re-upgrade restores it."""
    cfg = _cfg(pg_stack.owner_sa)

    # At head (0012): 'unknown' is an allowed status.
    assert "unknown" in _status_check(pg_stack.owner_libpq)

    # Downgrade to 0011: the 3-value CHECK is restored (no 'unknown').
    command.downgrade(cfg, _PREV)
    check = _status_check(pg_stack.owner_libpq)
    assert "unknown" not in check
    assert "pending" in check and "success" in check and "failed" in check

    # Re-upgrade restores the 4-value CHECK.
    command.upgrade(cfg, _HEAD)
    assert "unknown" in _status_check(pg_stack.owner_libpq)


def test_downgrade_rewrites_unknown_rows_to_failed(pg_stack: SimpleNamespace) -> None:
    """A row in the terminal 'unknown' status must not block the downgrade: 0012's
    downgrade rewrites it to 'failed' before restoring the 3-value CHECK."""
    cfg = _cfg(pg_stack.owner_sa)
    m = pg_stack.seed_member()
    wf, ver, run, ea = (uuid.uuid4() for _ in range(4))
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, m.tenant_id)
        )
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,'{\"steps\":[]}'::jsonb)",
            (ver, m.tenant_id, wf),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) "
            "VALUES (%s,%s,%s,%s,'FAILED')",
            (run, m.tenant_id, wf, ver),
        )
        c.execute(
            "INSERT INTO external_actions (id, tenant_id, run_id, step_id, connector_id, tool, "
            "external_action_key, status, attempts) "
            "VALUES (%s,%s,%s,'s',%s,'webhook.send',%s,'unknown',1)",
            (ea, m.tenant_id, run, uuid.uuid4(), uuid.uuid4()),
        )

    command.downgrade(cfg, _PREV)
    with psycopg.connect(pg_stack.owner_libpq) as c:
        status = _one(c.execute("SELECT status FROM external_actions WHERE id=%s", (ea,)))[0]
    assert status == "failed"  # rewritten so the restored CHECK holds

    command.upgrade(cfg, _HEAD)


def _has_last_progress_column(owner_libpq: str) -> bool:
    with psycopg.connect(owner_libpq) as c:
        count = _one(
            c.execute(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_name='workflow_runs' AND column_name='last_progress_at'"
            )
        )[0]
    return bool(count == 1)


def test_last_progress_at_column_flips_and_backfills(pg_stack: SimpleNamespace) -> None:
    """0013 adds last_progress_at (up/down/up) and backfills it CONSERVATIVELY from
    the best existing state timestamp; downgrade drops it."""
    cfg = _cfg(pg_stack.owner_sa)
    assert _has_last_progress_column(pg_stack.owner_libpq)  # present at head

    # Downgrade to 0012 drops the column; re-upgrade restores + backfills it.
    command.downgrade(cfg, _P1C)
    assert not _has_last_progress_column(pg_stack.owner_libpq)

    # Seed a run with a known finished_at while the column is ABSENT, so the
    # UPGRADE backfill is what populates last_progress_at.
    m = pg_stack.seed_member()
    wf, ver, run = (uuid.uuid4() for _ in range(3))
    finished = "2026-05-01 09:00:00+00"
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, m.tenant_id)
        )
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,'{\"steps\":[]}'::jsonb)",
            (ver, m.tenant_id, wf),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status, "
            "finished_at) VALUES (%s,%s,%s,%s,'COMPLETED',%s)",
            (run, m.tenant_id, wf, ver, finished),
        )

    command.upgrade(cfg, _HEAD)
    assert _has_last_progress_column(pg_stack.owner_libpq)
    with psycopg.connect(pg_stack.owner_libpq) as c:
        lp = _one(c.execute("SELECT last_progress_at FROM workflow_runs WHERE id=%s", (run,)))[0]
    assert lp is not None and lp.isoformat().startswith("2026-05-01T09:00:00")  # = finished_at


def _has_table(owner_libpq: str, table: str) -> bool:
    with psycopg.connect(owner_libpq) as c:
        return bool(
            _one(
                c.execute(
                    "SELECT count(*) FROM information_schema.tables "
                    "WHERE table_schema='public' AND table_name=%s",
                    (table,),
                )
            )[0]
        )


def test_dr_restore_events_table_flips_with_migration(pg_stack: SimpleNamespace) -> None:
    """0014 adds the DR audit table (up/down/up); downgrade drops it."""
    cfg = _cfg(pg_stack.owner_sa)
    assert _has_table(pg_stack.owner_libpq, "dr_restore_events")  # present at head

    command.downgrade(cfg, _P1D)
    assert not _has_table(pg_stack.owner_libpq, "dr_restore_events")

    command.upgrade(cfg, _HEAD)
    assert _has_table(pg_stack.owner_libpq, "dr_restore_events")
    # Runtime roles may read ONLY the minimal recovery-lock columns (for their
    # mandatory startup preflight); they may NOT read the provenance/note columns,
    # and may NOT write. (M11.5 P2 addendum: the DB lock is the authority.)
    with psycopg.connect(pg_stack.scheduler_libpq) as c:
        c.execute("SELECT id, validation_completed_at, runtime_enabled_at FROM dr_restore_events")
        try:
            c.execute("SELECT note FROM dr_restore_events")
            raise AssertionError("nlw_scheduler could read the note column")
        except psycopg.errors.InsufficientPrivilege:
            pass


def test_membership_sod_migration_flips(pg_stack: SimpleNamespace) -> None:
    """0015 adds invitations + SoD provenance + the owner trigger (up/down/up)."""
    cfg = _cfg(pg_stack.owner_sa)
    assert _has_table(pg_stack.owner_libpq, "workspace_invitations")

    def _has_col(table: str, col: str) -> bool:
        with psycopg.connect(pg_stack.owner_libpq) as c:
            row = c.execute(
                "SELECT 1 FROM information_schema.columns WHERE table_name=%s AND column_name=%s",
                (table, col),
            ).fetchone()
        return row is not None

    assert _has_col("approvals", "requested_by_user_id")
    assert _has_col("workflow_runs", "initiated_by_user_id")

    command.downgrade(cfg, _P2)
    assert not _has_table(pg_stack.owner_libpq, "workspace_invitations")
    assert not _has_col("approvals", "requested_by_user_id")

    command.upgrade(cfg, _HEAD)
    assert _has_table(pg_stack.owner_libpq, "workspace_invitations")
    assert _has_col("approvals", "requested_by_user_id")
    # The owner-preservation trigger + four-eyes policy are back.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        trg = c.execute(
            "SELECT 1 FROM pg_trigger WHERE tgname='trg_workspace_owner_present'"
        ).fetchone()
    assert trg is not None


def _legacy_guc_policies(owner_libpq: str) -> list[str]:
    with psycopg.connect(owner_libpq) as c:
        rows = c.execute(
            "SELECT policyname FROM pg_policies WHERE schemaname='public' AND ("
            "coalesce(qual,'') LIKE '%app.user_id%' OR coalesce(qual,'') LIKE '%app.tenant_id%' "
            "OR coalesce(with_check,'') LIKE '%app.user_id%' "
            "OR coalesce(with_check,'') LIKE '%app.tenant_id%')"
        ).fetchall()
    return sorted(str(r[0]) for r in rows)


def test_signed_context_migration_flips(pg_stack: SimpleNamespace) -> None:
    """0016 (P3B) installs the key registry + signed verifiers and rewrites EVERY
    policy/helper off the unsigned GUCs (up/down/up). Downgrade is reversible but
    SECURITY SENSITIVE: it re-installs the legacy unsigned-GUC trust."""
    cfg = _cfg(pg_stack.owner_sa)
    assert _has_table(pg_stack.owner_libpq, "ctx_keys")
    assert _legacy_guc_policies(pg_stack.owner_libpq) == []  # nothing trusts unsigned GUCs
    with psycopg.connect(pg_stack.owner_libpq) as c:
        fns = {
            str(r[0])
            for r in c.execute(
                "SELECT proname FROM pg_proc WHERE proname IN "
                "('app_ctx_claims','ctx_user_id','ctx_tenant_id','ctx_run_id','ctx_purpose',"
                "'is_current_user_owner')"
            )
        }
    assert fns == {"app_ctx_claims", "ctx_user_id", "ctx_tenant_id", "ctx_run_id", "ctx_purpose"}

    command.downgrade(cfg, _P3A)
    assert not _has_table(pg_stack.owner_libpq, "ctx_keys")
    # The pre-P3B posture is restored exactly: 43 policies read the unsigned GUCs
    # directly again (51 total minus the 7 scheduler USING(true) policies minus
    # workspaces_app_select, which only calls a helper) — the documented,
    # reviewed-only downgrade re-opens forgery.
    assert len(_legacy_guc_policies(pg_stack.owner_libpq)) == 43
    with psycopg.connect(pg_stack.owner_libpq) as c:
        gone = _one(c.execute("SELECT count(*) FROM pg_proc WHERE proname='app_ctx_claims'"))[0]
        back = _one(
            c.execute("SELECT count(*) FROM pg_proc WHERE proname='is_current_user_owner'")
        )[0]
        assert (gone, back) == (0, 1)

    command.upgrade(cfg, _HEAD)
    assert _has_table(pg_stack.owner_libpq, "ctx_keys")
    assert _legacy_guc_policies(pg_stack.owner_libpq) == []
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = c.execute("SELECT count(*) FROM pg_policies WHERE schemaname='public'").fetchone()
        assert n is not None and n[0] == 51
