"""The workspace-creation grant ledger is scrubbed on offboarding (owner
decision 2026-10-24; migration 0032, ADR-037 amendment).

The grant that founded a workspace keeps no personal data once offboarding
completes: no raw or normalized email, no founder id, no note, and no value
derived from the email anywhere in the database. Reuse, replay and restore
stay safe, and other workspaces are untouched.
"""

import hashlib
import json
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from test_workspace_offboarding import W

from nlw.datasets.deletion_log import DeletionLogUnavailable, WorkspaceReceipt
from nlw.ops import datasets as ops
from nlw.ops import grants
from nlw.ops import workspace_offboarding as wo
from nlw.tenancy.signing import Purpose

# The harness auto-grant is off: these tests issue and consume real grants.
pytestmark = [pytest.mark.integration, pytest.mark.workspace_grants_enforced]


@pytest.fixture
async def h(pg_stack: SimpleNamespace, tmp_path: Path) -> AsyncIterator[W]:
    harness = W(pg_stack, tmp_path)
    yield harness
    await harness.engine.dispose()
    await harness.ingest_engine.dispose()


def _found(pg: SimpleNamespace, *, note: str | None = None) -> tuple[uuid.UUID, uuid.UUID, str]:
    """A user founds a workspace through an operator grant (the real path)."""
    user = pg.seed_user()
    email = f"{user}@example.com"
    gid = pg.grant_workspace_creation(email)
    if note is not None:
        with psycopg.connect(pg.owner_libpq, autocommit=True) as c:
            c.execute("UPDATE workspace_creation_grants SET note = %s WHERE id = %s", (note, gid))
    with psycopg.connect(pg.app_libpq) as conn:
        pg.apply_ctx(conn, pg.sign(Purpose.API_IDENTITY, user_id=user))
        row = conn.execute(
            "SELECT create_workspace_for_current_user('Founded', %s)", (f"f-{gid}",)
        ).fetchone()
        conn.commit()
    assert row is not None
    return row[0], user, email


def _grant(h: W, workspace: uuid.UUID) -> dict[str, Any]:
    with h.owner() as c:
        cur = c.execute(
            "SELECT * FROM workspace_creation_grants WHERE consumed_workspace_id = %s",
            (workspace,),
        )
        names = [d.name for d in cur.description or []]
        (row,) = cur.fetchall()
    return dict(zip(names, row, strict=True))


def _offboard(h: W, workspace: uuid.UUID) -> dict[str, Any]:
    h.request(workspace)
    result: dict[str, Any] = h.complete(workspace)
    return result


def _representations(email: str) -> list[str]:
    norm = email.strip().lower()
    return [email, norm, email.upper(), *(
        getattr(hashlib, a)(v.encode()).hexdigest()
        for a in ("sha256", "sha1", "md5") for v in (email, norm)
    )]  # fmt: skip


def _found_anywhere(h: W, needles: list[str]) -> list[str]:
    """Every text/json column of every public table except ``users`` (the
    platform sign-in identity, ADR-037), searched for each representation."""
    hits: list[str] = []
    with h.owner() as c:
        cols = c.execute(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name <> 'users' "
            "AND data_type IN ('text', 'character varying', 'jsonb', 'json')"
        ).fetchall()
        for table, col in cols:
            for needle in needles:
                n = c.execute(
                    f'SELECT count(*) FROM "{table}" WHERE "{col}"::text ILIKE %s',  # noqa: S608
                    (f"%{needle}%",),
                ).fetchone()
                if n and n[0]:
                    hits.append(f"{table}.{col}")
    return hits


async def test_offboarding_scrubs_the_founding_grant_and_keeps_only_audit_evidence(
    h: W, capsys: pytest.CaptureFixture[str]
) -> None:
    ws, founder, email = _found(h.pg, note=None)
    other_ws, _, other_email = _found(h.pg)
    before = _grant(h, ws)
    assert before["email_normalized"] == email and before["consumed_by_user_id"] == founder
    assert _found_anywhere(h, [email]) == ["workspace_creation_grants.email_normalized"]

    result = _offboard(h, ws)
    after = _grant(h, ws)
    # Scrubbed: every personal column.
    assert (after["email_normalized"], after["consumed_by_user_id"], after["note"]) == (
        None, None, None,
    )  # fmt: skip
    # Kept: the non-personal audit evidence, unchanged.
    for kept in ("id", "granted_by", "created_at", "expires_at", "consumed_at",
                 "consumed_workspace_id", "revoked_at", "revoked_by"):  # fmt: skip
        assert after[kept] == before[kept], kept
    assert after["scrubbed_at"] is not None and after["scrubbed_by"] == "op-off"
    assert set(after) == {*before, "scrubbed_at", "scrubbed_by"}
    # No representation of the email (raw, normalized, any hash) is left in the
    # database, the receipt, the tombstone or the command's output.
    assert _found_anywhere(h, _representations(email)) == []
    record = h.log.read_workspace(next(iter(h.log.workspace_refs())))
    assert record is not None and record["table_counts"][wo.GRANTS_SCRUBBED] == 1
    blob = json.dumps(record) + json.dumps(h.ws(ws)) + json.dumps(result, default=str)
    out = capsys.readouterr()
    for needle in _representations(email):
        assert needle not in blob and needle not in out.out + out.err
    # The operator's listing shows the closed grant without an email.
    with h.owner() as c:
        listed = {r[0]: r for r in grants.list_grants(c, include_closed=True)}
    assert listed[after["id"]][1] is None and listed[after["id"]][6] == ws
    # Another workspace's grant is untouched.
    assert _grant(h, other_ws)["email_normalized"] == other_email
    assert _grant(h, other_ws)["scrubbed_at"] is None


async def test_a_scrubbed_grant_cannot_be_reused_and_a_fresh_grant_still_works(h: W) -> None:
    ws, founder, email = _found(h.pg)
    _offboard(h, ws)
    with psycopg.connect(h.pg.app_libpq) as conn:
        h.pg.apply_ctx(conn, h.pg.sign(Purpose.API_IDENTITY, user_id=founder))
        assert conn.execute("SELECT has_workspace_creation_grant()").fetchone() == (False,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="not granted"):
            conn.execute("SELECT create_workspace_for_current_user('again', 'again-1')")
    # The one-open-grant-per-email rule is intact: a new grant for the same
    # person is a new, separate grant, and founds a new workspace.
    gid = h.pg.grant_workspace_creation(email)
    with psycopg.connect(h.pg.app_libpq) as conn:
        h.pg.apply_ctx(conn, h.pg.sign(Purpose.API_IDENTITY, user_id=founder))
        new_ws = conn.execute(
            "SELECT create_workspace_for_current_user('again', %s)", (f"again-{gid}",)
        ).fetchone()
        conn.commit()
    assert new_ws is not None and new_ws[0] != ws
    assert _grant(h, new_ws[0])["email_normalized"] == email


async def test_the_guard_refuses_unscrubbing_deleting_and_early_or_partial_scrubs(h: W) -> None:
    ws, founder, email = _found(h.pg)
    gid = _grant(h, ws)["id"]
    with h.owner() as c:
        # While the workspace is ACTIVE, nobody scrubs (not even the owner).
        with pytest.raises(psycopg.errors.CheckViolation, match="offboarding workspace"):
            wo.scrub_grants(c, ws, operator="op")
        # A scrub never touches anything but the personal columns.
        h.request(ws)
        with pytest.raises(psycopg.errors.CheckViolation, match="only its personal columns"):
            c.execute(
                "UPDATE workspace_creation_grants SET email_normalized = NULL, "
                "consumed_by_user_id = NULL, note = NULL, scrubbed_at = now(), "
                "scrubbed_by = 'op', granted_by = 'someone-else' WHERE id = %s",
                (gid,),
            )
        # A half scrub (email kept) is refused by the constraints.
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute(
                "UPDATE workspace_creation_grants SET consumed_by_user_id = NULL, "
                "scrubbed_at = now(), scrubbed_by = 'op' WHERE id = %s",
                (gid,),
            )
        assert wo.scrub_grants(c, ws, operator="op") == 1
        assert wo.scrub_grants(c, ws, operator="op") == 0  # idempotent
        # Scrubbed rows never change again and are never deleted.
        with pytest.raises(psycopg.errors.CheckViolation, match="never changes"):
            c.execute(
                "UPDATE workspace_creation_grants SET email_normalized = %s WHERE id = %s",
                (email, gid),
            )
        with pytest.raises(psycopg.errors.CheckViolation, match="never changes"):
            c.execute("DELETE FROM workspace_creation_grants WHERE id = %s", (gid,))
    # Runtime roles still hold no privilege on the ledger at all.
    for libpq in (h.pg.app_libpq, h.pg.worker_libpq, h.pg.scheduler_libpq):
        with psycopg.connect(libpq) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT count(*) FROM workspace_creation_grants")


async def test_a_failed_offboarding_before_commit_keeps_the_grant_unchanged(h: W) -> None:
    ws, founder, email = _found(h.pg)
    h.request(ws)

    def refuse(receipt: Any) -> str:
        raise DeletionLogUnavailable("the log is down")

    h.log.append_workspace = refuse
    with pytest.raises(wo.OffboardingError, match="the log is down"):
        h.complete(ws)
    g = _grant(h, ws)
    assert (g["email_normalized"], g["consumed_by_user_id"], g["scrubbed_at"]) == (
        email, founder, None,
    )  # fmt: skip
    assert h.ws(ws)["status"] == "OFFBOARDING"


async def test_a_restored_snapshot_is_scrubbed_again_before_any_runtime_starts(h: W) -> None:
    # The restored snapshot predates the offboarding: the workspace is ACTIVE
    # and its founding grant still names the founder; the receipt survived.
    ws, founder, email = _found(h.pg)
    h.log.append_workspace(
        WorkspaceReceipt.for_workspace(
            sink=h.log.sink_id, environment="local", tenant_id=ws, dataset_ids=[],
            table_counts={wo.GRANTS_SCRUBBED: 1}, operator="op-before-restore",
            secret_refs=0, secret_store="environment-file",
        )
    )  # fmt: skip
    other_ws, _, other_email = _found(h.pg)
    lock = h.lock()
    with h.owner() as c:
        dry = ops.reapply_receipts(c, h.log, dry_run=True)
    assert (dry["workspaces_reoffboarded"], dry["grants_scrubbed"]) == (1, 1)
    assert _grant(h, ws)["email_normalized"] == email  # a dry run changes nothing
    with h.owner() as c:
        result = ops.reapply_receipts(c, h.log)
    assert (result["workspaces_reoffboarded"], result["grants_scrubbed"]) == (1, 1)
    g = _grant(h, ws)
    assert (g["email_normalized"], g["consumed_by_user_id"]) == (None, None)
    assert g["scrubbed_by"] == wo.RESTORE_SCRUB_OPERATOR
    assert _found_anywhere(h, _representations(email)) == []
    with h.owner() as c:
        again = ops.reapply_receipts(c, h.log)
    assert (again["workspaces_already"], again["grants_scrubbed"]) == (1, 0)  # idempotent
    assert _grant(h, other_ws)["email_normalized"] == other_email
    h.unlock(lock)
    del founder


async def test_migration_0032_downgrade_is_refused_once_a_grant_is_scrubbed(h: W) -> None:
    """Upgrade from a populated 0031 keeps every grant as it was (tested by the
    reversibility suite); downgrade works while nothing is scrubbed and is
    refused once a grant is, leaving the head in place."""
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", h.pg.owner_sa)
    ws, _, email = _found(h.pg)
    command.downgrade(cfg, "0031_workspace_offboarding")
    with h.owner() as c:
        cols = {
            r[0]
            for r in c.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'workspace_creation_grants'"
            ).fetchall()
        }
        assert "scrubbed_at" not in cols
        assert c.execute(
            "SELECT email_normalized FROM workspace_creation_grants "
            "WHERE consumed_workspace_id = %s",
            (ws,),
        ).fetchone() == (email,)
    command.upgrade(cfg, "head")
    assert _grant(h, ws)["email_normalized"] == email and _grant(h, ws)["scrubbed_at"] is None
    _offboard(h, ws)
    with pytest.raises(Exception, match="0032 downgrade refused"):
        command.downgrade(cfg, "0031_workspace_offboarding")
    with h.owner() as c:
        assert c.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0032_workspace_grant_scrub",
        )
