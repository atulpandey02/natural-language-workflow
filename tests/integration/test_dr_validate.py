"""Post-restore validation: security posture + invariants survive (P2)."""

import uuid
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy import create_engine

from nlw.backup.quiescence import quiesce
from nlw.backup.validate import validate_restore

pytestmark = pytest.mark.integration


def _head(owner: str) -> str:
    with psycopg.connect(owner) as c:
        row = c.execute("SELECT version_num FROM alembic_version").fetchone()
    assert row is not None
    return str(row[0])


def _check(report: dict[str, object], name: str) -> bool:
    checks: list[dict[str, object]] = report["checks"]  # type: ignore[assignment]
    return bool(next(c["ok"] for c in checks if c["name"] == name))


def test_validation_passes_on_a_clean_migrated_and_quiesced_db(pg_stack: SimpleNamespace) -> None:
    engine = create_engine(pg_stack.owner_sa)
    quiesce(engine)  # records a dr_restore_event so the quiesced/cutoff checks apply
    report = validate_restore(engine, expected_revision=_head(pg_stack.owner_libpq))

    failing = [(c["name"], c["detail"]) for c in report["checks"] if not c["ok"]]
    assert report["ok"], failing
    # Spot-check the security-posture assertions specifically.
    for name in (
        "runtime_roles_nosuperuser_nobypassrls",
        "rls_enabled_and_forced",
        "tables_owned_by_privileged_owner",
        "security_definer_owners_and_search_path",
        "no_public_execute_on_secdef",
        "authz_audit_append_only_for_runtime_roles",
        "invitation_constraints_present",
        "invitations_hash_only_and_no_app_delete",
        "membership_admin_least_privilege",
        "privileged_funcs_no_public_execute",
        "p3a_definers_search_path_pg_catalog",
        "approval_requester_present_and_immutable",
        "provenance_immutability_triggers_present",
        "critical_constraints_present",
        "p1d_recon_indexes_present",
        "external_action_unknown_status_allowed",
        "non_terminal_runs_quiesced",
        "schedules_after_recovery_cutoff",
    ):
        assert _check(report, name), name


def test_validation_fails_if_runtime_role_gains_superuser(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("ALTER ROLE nlw_app SUPERUSER")
    engine = create_engine(pg_stack.owner_sa)
    quiesce(engine)
    report = validate_restore(engine)
    assert report["ok"] is False
    assert _check(report, "runtime_roles_nosuperuser_nobypassrls") is False


def test_validation_fails_on_revision_mismatch(pg_stack: SimpleNamespace) -> None:
    engine = create_engine(pg_stack.owner_sa)
    quiesce(engine)
    report = validate_restore(engine, expected_revision="0000_wrong")
    assert report["ok"] is False
    assert _check(report, "alembic_revision_matches_manifest") is False


def test_validation_fails_if_non_terminal_work_not_quiesced(pg_stack: SimpleNamespace) -> None:
    o = pg_stack.owner_libpq
    tid, wf, ver, rid = (uuid.uuid4() for _ in range(4))
    with psycopg.connect(o, autocommit=True) as c:
        c.execute("INSERT INTO workspaces (id, name, slug) VALUES (%s,'w',%s)", (tid, f"w-{tid}"))
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,'{\"steps\":[]}'::jsonb)",
            (ver, tid, wf),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) "
            "VALUES (%s,%s,%s,%s,'RUNNING')",
            (rid, tid, wf, ver),
        )
    engine = create_engine(pg_stack.owner_sa)
    # NOTE: deliberately NOT quiescing the RUNNING run.
    quiesce(engine)  # quiesces it -> so validation should PASS; assert quiescence fixed it
    report = validate_restore(engine)
    assert _check(report, "non_terminal_runs_quiesced") is True
