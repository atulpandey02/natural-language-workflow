"""Workspace offboarding (ADR-037, migration 0031) against PostgreSQL. Objects
live in a local store; receipts in the in-memory Object Lock S3 (no network,
no AWS).

``request`` blocks every runtime at once and moves the datasets to DELETING;
``complete`` purges and tombstones them with receipts, deletes every purge
table's rows, appends one workspace receipt and leaves a tombstone. A restore
that brings the workspace back is offboarded again by ``reapply-receipts``.
"""

import json
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from test_deletion_receipt_log import H

from nlw.datasets.deletion_log import WorkspaceReceipt
from nlw.ops import datasets as ops
from nlw.ops import offboarding
from nlw.ops import workspace_offboarding as wo
from nlw.storage.blob import TenantScopedBlobStore
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration


class W(H):  # type: ignore[misc]
    def __init__(self, pg: SimpleNamespace, root: Path) -> None:
        super().__init__(pg, root)
        self.user = self.ctx.user_id

    def seed(self, tenant: uuid.UUID, user: uuid.UUID) -> dict[str, uuid.UUID]:
        """One row in every purge table, and retained evidence (as the owner)."""
        ids = {k: uuid.uuid4() for k in ("wf", "ver", "run", "step", "sched", "appr", "plan",
                                          "inv", "conn", "ext", "audit")}  # fmt: skip
        with self.owner() as c:
            c.execute(
                "INSERT INTO workflows (id, tenant_id, name) VALUES (%s, %s, 'wf')",
                (ids["wf"], tenant),
            )
            c.execute(
                "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
                "VALUES (%s, %s, %s, 1, '{}'::jsonb)",
                (ids["ver"], tenant, ids["wf"]),
            )
            c.execute(
                "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, "
                "status) VALUES (%s, %s, %s, %s, 'COMPLETED')",
                (ids["run"], tenant, ids["wf"], ids["ver"]),
            )
            c.execute(
                "INSERT INTO step_runs (id, tenant_id, run_id, step_id, tool, status, attempt) "
                "VALUES (%s, %s, %s, 's1', 'noop', 'SUCCESS', 1)",
                (ids["step"], tenant, ids["run"]),
            )
            c.execute(
                "INSERT INTO schedules (id, tenant_id, workflow_id, workflow_version_id, "
                "timezone, frequency, minute, enabled, next_run_at, created_by) "
                "VALUES (%s, %s, %s, %s, 'UTC', 'hourly', 0, true, now(), %s)",
                (ids["sched"], tenant, ids["wf"], ids["ver"], user),
            )
            c.execute(
                "INSERT INTO connectors (id, tenant_id, type, name, secret_ref, config, status) "
                "VALUES (%s, %s, 'slack', 'c', 'SLACK_TOKEN', '{}'::jsonb, 'active')",
                (ids["conn"], tenant),
            )
            c.execute(
                "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, "
                "connector_name, tool, requested_by_user_id, status, requested_at) "
                "VALUES (%s, %s, %s, 's1', %s, 'c', 'slack.post', %s, 'pending', now())",
                (ids["appr"], tenant, ids["run"], ids["conn"], user),
            )
            c.execute(
                "INSERT INTO plan_proposals (id, tenant_id, created_by, prompt_len, provider, "
                "model, workflow_name, status, feasibility) "
                "VALUES (%s, %s, %s, 5, 'fake', 'm', 'w', 'PASS', '{}'::jsonb)",
                (ids["plan"], tenant, user),
            )
            c.execute(
                "INSERT INTO workspace_invitations (id, tenant_id, email, role, invited_by, "
                "token_hash, status, expires_at) VALUES (%s, %s, 'x@example.com', 'member', %s, "
                "%s, 'pending', now() + interval '1 day')",
                (ids["inv"], tenant, user, uuid.uuid4().hex),
            )
            c.execute(
                "INSERT INTO external_actions (id, tenant_id, run_id, step_id, connector_id, "
                "tool, external_action_key, status, attempts) "
                "VALUES (%s, %s, %s, 's1', %s, 'slack.post', %s, 'success', 1)",
                (ids["ext"], tenant, ids["run"], ids["conn"], uuid.uuid4().hex),
            )
            c.execute(
                "INSERT INTO authz_audit_events (id, tenant_id, event_type, created_at) "
                "VALUES (%s, %s, 'TEST', now())",
                (ids["audit"], tenant),
            )
        return ids

    def ws(self, tenant: uuid.UUID) -> dict[str, Any]:
        with self.owner() as c:
            row = c.execute(
                "SELECT status, name, slug, offboarded_by, offboard_receipt_id, offboard_counts "
                "FROM workspaces WHERE id = %s",
                (tenant,),
            ).fetchone()
        assert row is not None
        return dict(zip(("status", "name", "slug", "by", "receipt", "counts"), row, strict=True))

    def rows(self, tenant: uuid.UUID) -> dict[str, int]:
        with self.owner() as c:
            inv = offboarding.inventory(c, tenant)
        return {t: v["rows"] for t, v in inv["tables"].items()}

    def request(self, tenant: uuid.UUID) -> dict[str, Any]:
        with self.owner() as c:
            return wo.request_offboarding(c, tenant, operator="op-off")

    def complete(self, tenant: uuid.UUID) -> dict[str, Any]:
        with self.owner() as c:
            return wo.complete_offboarding(
                c, self.store, self.log, tenant, operator="op-off", environment="local"
            )


@pytest.fixture
async def h(pg_stack: SimpleNamespace, tmp_path: Path) -> AsyncIterator[W]:
    harness = W(pg_stack, tmp_path)
    yield harness
    await harness.engine.dispose()
    await harness.ingest_engine.dispose()


def _visible(pg: SimpleNamespace, purpose: Purpose, libpq: str, **ids: Any) -> int:
    with pg.ctx_conn(libpq, purpose, **ids) as c:
        n = c.execute("SELECT count(*) FROM workflow_runs").fetchone()
        c.rollback()
    return int(n[0]) if n else 0


async def test_request_blocks_every_runtime_at_once_and_only_that_workspace(h: W) -> None:
    other = h.pg.seed_member("owner")
    h.seed(h.tenant, h.user)
    h.seed(other.tenant_id, other.user_id)
    d = await h.dataset()
    v = await h.active(d)
    api = {"user_id": h.user, "tenant_id": h.tenant}
    assert _visible(h.pg, Purpose.API_REQUEST, h.pg.app_libpq, **api) == 1

    result = h.request(h.tenant)
    assert result == {"workspace_id": str(h.tenant), "changed": 1, "datasets_deleting": 1}
    assert h.ws(h.tenant)["status"] == "OFFBOARDING"
    # API, worker: no row of the workspace is visible, and nothing can be written.
    assert _visible(h.pg, Purpose.API_REQUEST, h.pg.app_libpq, **api) == 0
    with (
        h.pg.ctx_conn(h.pg.app_libpq, Purpose.API_REQUEST, **api) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s, %s, 'x')",
            (uuid.uuid4(), h.tenant),
        )
    with h.owner() as c:
        run = c.execute("SELECT id FROM workflow_runs WHERE tenant_id = %s", (h.tenant,)).fetchone()
        assert run is not None
        reason = c.execute(
            "SELECT schedule_creator_block_reason(id) FROM schedules WHERE tenant_id = %s",
            (h.tenant,),
        ).fetchone()
        assert reason == ("WORKSPACE_NOT_ACTIVE",)
        assert c.execute("SELECT workspace_is_active(%s)", (other.tenant_id,)).fetchone() == (True,)
    assert (
        _visible(h.pg, Purpose.WORKER_EXECUTION, h.pg.worker_libpq, tenant_id=h.tenant,
                 run_id=run[0]) == 0
    )  # fmt: skip
    # The other workspace is untouched.
    other_api = {"user_id": other.user_id, "tenant_id": other.tenant_id}
    assert _visible(h.pg, Purpose.API_REQUEST, h.pg.app_libpq, **other_api) == 1
    # Datasets: DELETING, with the reason recorded; the active pointer cleared.
    assert h.row(v) == ("DELETING", None)
    with h.owner() as c:
        reasons = c.execute(
            "SELECT event_type, reason_code FROM dataset_events WHERE dataset_id = %s "
            "AND reason_code = 'WORKSPACE_OFFBOARDING' ORDER BY event_type",
            (d,),
        ).fetchall()
    assert reasons == [
        ("DATASET_DELETION_REQUESTED", "WORKSPACE_OFFBOARDING"),
        ("VERSION_DELETION_REQUESTED", "WORKSPACE_OFFBOARDING"),
    ]
    # Idempotent.
    assert h.request(h.tenant) == {
        "workspace_id": str(h.tenant), "changed": 0, "datasets_deleting": 0,
    }  # fmt: skip


async def test_complete_purges_receipts_and_leaves_only_the_tombstone(h: W) -> None:
    other = h.pg.seed_member("owner")
    h.pg.add_membership(h.tenant, "member")
    seeded = h.seed(h.tenant, h.user)
    h.seed(other.tenant_id, other.user_id)
    d = await h.dataset()
    v = await h.active(d)
    d2 = await h.dataset()
    await h.profiled(d2)
    with pytest.raises(wo.OffboardingError, match="not OFFBOARDING"):
        h.complete(h.tenant)
    h.request(h.tenant)

    result = h.complete(h.tenant)
    assert result["datasets_tombstoned"] == 2
    assert result["connector_secret_refs"] == 1
    rows = h.rows(h.tenant)
    for table in wo.PURGE_ORDER:
        assert rows[table] == 0, table
    # Retained by contract: delivery record, audit, lifecycle evidence, tombstones.
    assert rows["external_actions"] == 1 and rows["authz_audit_events"] == 1
    assert rows["dataset_events"] > 0 and rows["datasets"] == 2 and rows["workspaces"] == 1
    assert h.row(v)[0] == "DELETED"
    assert not TenantScopedBlobStore(h.store, h.tenant).list_dataset("datasets", d)
    ws = h.ws(h.tenant)
    assert ws["status"] == "OFFBOARDED" and ws["name"] == "offboarded"
    assert ws["slug"] == f"offboarded-{h.tenant}" and ws["by"] == "op-off"
    assert ws["receipt"] == result["receipt"]
    assert ws["counts"]["table_counts"]["memberships"] == 2
    assert ws["counts"]["table_counts"]["workflows"] == 1
    # Nothing else in the workspace's tombstone: no name, no value, no text.
    assert set(ws["counts"]) == {
        "datasets_tombstoned", "dataset_ids_sha256", "table_counts", "offboarding_set_sha256",
        "receipt_sink",
    }  # fmt: skip
    # The other workspace keeps everything.
    assert h.rows(other.tenant_id)["workflows"] == 1
    assert h.rows(other.tenant_id)["memberships"] == 1
    # The receipt is in the external log and verifies.
    with h.owner() as c:
        report = ops.reconcile_receipts(c, h.log)
    assert report["workspace_unverified"] == [] and report["unverified"] == []
    assert not ops.reconcile_failed(report)
    record = h.log.read_workspace(next(iter(h.log.workspace_refs())))
    assert record is not None and record["tenant_id"] == str(h.tenant)
    assert "SLACK_TOKEN" not in json.dumps(record) and str(seeded["wf"]) not in json.dumps(record)
    # Completed: a second run is refused, the tombstone never changes.
    with pytest.raises(wo.OffboardingError, match="OFFBOARDED"):
        h.complete(h.tenant)
    with h.owner() as c, pytest.raises(psycopg.errors.CheckViolation, match="never changes"):
        c.execute("UPDATE workspaces SET name = 'back' WHERE id = %s", (h.tenant,))


async def test_the_workspace_state_is_guarded(h: W) -> None:
    with h.owner() as c:
        with pytest.raises(psycopg.errors.CheckViolation, match="not allowed"):
            c.execute("UPDATE workspaces SET status = 'OFFBOARDED' WHERE id = %s", (h.tenant,))
        with pytest.raises(psycopg.errors.CheckViolation, match="created ACTIVE"):
            c.execute(
                "INSERT INTO workspaces (id, name, slug, status, offboarding_requested_at) "
                "VALUES (%s, 'x', %s, 'OFFBOARDING', now())",
                (uuid.uuid4(), f"x-{uuid.uuid4()}"),
            )
    h.request(h.tenant)
    with h.owner() as c:
        for bad in ("ACTIVE", "OFFBOARDED"):
            with pytest.raises(psycopg.errors.CheckViolation):
                c.execute("UPDATE workspaces SET status = %s WHERE id = %s", (bad, h.tenant))
        with pytest.raises(psycopg.errors.CheckViolation, match="renamed only"):
            c.execute("UPDATE workspaces SET name = 'n' WHERE id = %s", (h.tenant,))
        with pytest.raises(psycopg.errors.CheckViolation, match="never deleted"):
            c.execute("DELETE FROM workspaces WHERE id = %s", (h.tenant,))
    # No runtime role can change a status (they hold no UPDATE either).
    with (
        h.pg.ctx_conn(h.pg.app_libpq, Purpose.API_REQUEST, user_id=h.user, tenant_id=h.tenant) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("UPDATE workspaces SET status = 'ACTIVE' WHERE id = %s", (h.tenant,))


async def test_offboarding_is_refused_while_the_recovery_lock_holds(h: W) -> None:
    h.lock()
    with pytest.raises(ops.TombstoneError, match="recovery lock"):
        h.request(h.tenant)
    assert h.ws(h.tenant)["status"] == "ACTIVE"


async def test_a_restored_offboarded_workspace_is_offboarded_again(h: W) -> None:
    # The restored snapshot predates the offboarding; the receipt survived in
    # the external log.
    h.seed(h.tenant, h.user)
    h.log.append_workspace(
        WorkspaceReceipt.for_workspace(
            sink=h.log.sink_id, environment="local", tenant_id=h.tenant, dataset_ids=[],
            table_counts={"workflows": 1}, operator="op-before-restore",
        )
    )  # fmt: skip
    gone = uuid.uuid4()  # a workspace created after the snapshot
    h.log.append_workspace(
        WorkspaceReceipt.for_workspace(
            sink=h.log.sink_id, environment="local", tenant_id=gone, dataset_ids=[],
            table_counts={}, operator="op",
        )
    )  # fmt: skip
    lock = h.lock()
    with h.owner() as c:
        dry = ops.reapply_receipts(c, h.log, dry_run=True)
    assert (dry["workspaces_reoffboarded"], dry["workspaces_absent"]) == (1, 1)
    assert h.ws(h.tenant)["status"] == "ACTIVE"
    with h.owner() as c:
        result = ops.reapply_receipts(c, h.log)
    assert result["workspace_receipts"] == 2 and result["workspaces_reoffboarded"] == 1
    assert result["workspace_unreadable"] == [] and not ops.reapply_failed(result)
    assert result["unexpected_objects"] == 0  # workspace receipts are receipts
    assert h.ws(h.tenant)["status"] == "OFFBOARDING"  # blocked before any runtime starts
    with h.owner() as c:
        again = ops.reapply_receipts(c, h.log)
    assert (again["workspaces_reoffboarded"], again["workspaces_already"]) == (0, 1)

    h.unlock(lock)
    h.complete(h.tenant)
    assert h.ws(h.tenant)["status"] == "OFFBOARDED"
    with h.owner() as c:
        report = ops.reconcile_receipts(c, h.log)
    assert report["workspace_unverified"] == []
    # The earlier receipts name no tombstone: reported, not a failure.
    assert sorted(report["workspace_receipts_without_tombstone"]) == sorted(
        [str(h.tenant), str(gone)]
    )
    assert not ops.reconcile_failed(report)


async def test_an_untrustworthy_workspace_receipt_is_reported_and_changes_nothing(h: W) -> None:
    receipt = WorkspaceReceipt.for_workspace(
        sink=h.log.sink_id, environment="local", tenant_id=h.tenant, dataset_ids=[],
        table_counts={"workflows": 1}, operator="op",
    )  # fmt: skip
    forged = {**json.loads(receipt.to_json()), "table_counts": {"workflows": 2}}
    h.bucket.plant(
        f"receipts/{h.tenant}/workspace/{receipt.receipt_id}.json",
        json.dumps(forged, sort_keys=True).encode(),
    )
    h.lock()
    with h.owner() as c:
        result = ops.reapply_receipts(c, h.log)
    assert result["workspace_unreadable"] == [str(h.tenant)]
    assert ops.reapply_failed(result)
    assert h.ws(h.tenant)["status"] == "ACTIVE"


async def test_the_workspace_is_hidden_from_discovery_and_refused_by_the_api(h: W) -> None:
    from sqlalchemy import text

    from nlw.db.repositories import WorkspaceRepository
    from nlw.tenancy.session import set_identity_context

    async def listed() -> list[uuid.UUID]:
        async with h.maker() as s, s.begin():
            await set_identity_context(s, h.pg.signers[Purpose.API_IDENTITY], h.user)
            active = (
                await s.execute(text("SELECT public.workspace_is_active(:w)"), {"w": h.tenant})
            ).scalar_one()
            assert active is (h.ws(h.tenant)["status"] == "ACTIVE")
            return [ws.id for ws, _ in await WorkspaceRepository(s).list_for_user(h.user)]

    assert await listed() == [h.tenant]
    h.request(h.tenant)
    assert await listed() == []


def test_the_purge_order_is_exactly_the_contracts_purge_tables() -> None:
    purge = {t for t, c in offboarding.TABLES.items() if c.on_offboarding.startswith("purge")}
    assert set(wo.PURGE_ORDER) == purge and len(wo.PURGE_ORDER) == len(purge)


def test_the_api_refuses_an_offboarding_workspace(pg_stack: SimpleNamespace) -> None:
    import time

    import jwt
    from fastapi.testclient import TestClient

    from nlw.api.app import create_app

    token = jwt.encode(
        {"iss": "https://proj.supabase.co/auth/v1", "aud": "authenticated",
         "exp": int(time.time()) + 300, "sub": "offboard-api", "email": "ob@example.com"},
        "dev-secret-for-tests-32bytes-min-length", algorithm="HS256",
    )  # fmt: skip
    auth = {"Authorization": f"Bearer {token}"}
    pg_stack.grant_workspace_creation("ob@example.com")
    with TestClient(create_app(pg_stack.settings)) as client:
        created = client.post("/workspaces", json={"name": "W"}, headers=auth)
        assert created.status_code in (200, 201), created.text
        ws = created.json()["id"]
        headers = {**auth, "X-Workspace-Id": ws}
        assert client.get("/connectors", headers=headers).status_code == 200
        with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
            wo.request_offboarding(c, uuid.UUID(ws), operator="op-off")
        refused = client.get("/connectors", headers=headers)
        assert refused.status_code == 403
        assert refused.json()["error"]["message"] == "the workspace is unavailable"
        listed = client.get("/workspaces", headers=auth).json()
        assert ws not in [w["id"] for w in listed]
