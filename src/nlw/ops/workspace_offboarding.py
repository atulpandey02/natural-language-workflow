"""Workspace offboarding (Phase 2 plan section 0.6; ADR-037). Operator only.

    python -m nlw.ops.offboarding request  --workspace <id> --operator <name>
    python -m nlw.ops.offboarding complete --workspace <id> --operator <name>
    python -m nlw.ops.offboarding pending

``request`` moves the workspace ACTIVE -> OFFBOARDING. From that commit on, no
runtime can read or write any of its rows (``workspace_is_active``, migration
0031), whatever signed context it holds, and its schedules stop
(``WORKSPACE_NOT_ACTIVE``). Every live dataset moves to DELETING with it
(reason ``WORKSPACE_OFFBOARDING``). Idempotent.

``complete`` then, for an OFFBOARDING workspace and only while the recovery lock
is clear:

1. purges every DELETING dataset (verified absent, one receipt per version) and
   tombstones it (``nlw.ops.datasets``), so no byte and no name remains;
2. in ONE transaction: deletes the rows of every table the contract marks
   ``purge`` (``PURGE_ORDER``), verifies that none is left, appends ONE
   workspace receipt (``workspace-offboarding-receipt-1``) to the external
   deletion log, and turns the workspace into its tombstone: OFFBOARDED, name
   and slug scrubbed, the operator label, time, row counts and receipt id kept.

Retained by design (the contract, ``nlw.ops.offboarding.TABLES``): audit and
lifecycle events, the delivery record of external actions, the processing
requests, and the dataset and workspace tombstones. Connector secrets live in
the secret store, which this code cannot delete: ``complete`` reports how many
connector secret references the operator must remove there
(``connector_secret_refs``), by count only.

A database restore can bring an offboarded workspace back. ``reapply-receipts``
(``nlw.ops.datasets``) therefore also lists every workspace receipt and moves a
restored ACTIVE workspace back to OFFBOARDING before any runtime starts; the
operator then re-runs ``complete`` once the runtimes are enabled.
``reconcile-receipts`` verifies the receipt of every OFFBOARDED workspace.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

import psycopg
from psycopg import sql

from nlw.datasets.deletion_log import (
    DeletionLog,
    DeletionLogUnavailable,
    ExpectedWorkspaceReceipt,
    ReceiptCheck,
    WorkspaceReceipt,
    WorkspaceReceiptRef,
    workspace_receipt_self_consistent,
)
from nlw.datasets.lifecycle import EventType, ReasonCode
from nlw.ops import datasets as ops
from nlw.ops.offboarding import TABLES
from nlw.storage.blob import BlobStore

# Children first (no table here is referenced by a retained one).
PURGE_ORDER = (
    "approvals",
    "step_runs",
    "workflow_runs",
    "schedules",
    "workflow_versions",
    "workflows",
    "plan_proposals",
    "workspace_invitations",
    "connectors",
    "memberships",
)
_OPERATOR = re.compile(r"[A-Za-z0-9._-]{1,64}")


class OffboardingError(ops.TombstoneError):
    """A refusal: nothing was changed by the refused step."""


def _operator(label: str) -> str:
    if not _OPERATOR.fullmatch(label):
        raise OffboardingError("--operator must be a short operator label ([A-Za-z0-9._-])")
    return label


def _scope(table: str) -> str:
    return TABLES[table].scope


def _status(conn: psycopg.Connection[Any], workspace_id: uuid.UUID, lock: bool = False) -> str:
    query = (
        "SELECT status FROM workspaces WHERE id = %s FOR UPDATE"
        if lock
        else "SELECT status FROM workspaces WHERE id = %s"
    )
    row = conn.execute(query, (workspace_id,)).fetchone()
    if row is None:
        raise OffboardingError("no such workspace")
    return str(row[0])


# --- request -------------------------------------------------------------------


def _datasets_to_deleting(conn: psycopg.Connection[Any], workspace_id: uuid.UUID) -> int:
    moved = 0
    for (dataset_id,) in conn.execute(
        "SELECT id FROM datasets WHERE tenant_id = %s AND status = 'ACTIVE' ORDER BY id FOR UPDATE",
        (workspace_id,),
    ).fetchall():
        for vid, status in conn.execute(
            "SELECT id, status FROM dataset_versions WHERE dataset_id = %s AND tenant_id = %s "
            "AND status NOT IN ('DELETING', 'DELETED') ORDER BY version_number FOR UPDATE",
            (dataset_id, workspace_id),
        ).fetchall():
            conn.execute(
                "UPDATE dataset_versions SET status = 'DELETING' WHERE id = %s AND status = %s",
                (vid, status),
            )
            ops._event(
                conn, workspace_id, dataset_id, vid, EventType.VERSION_DELETION_REQUESTED,
                status, to_status="DELETING", reason=ReasonCode.WORKSPACE_OFFBOARDING,
            )  # fmt: skip
        conn.execute(
            "UPDATE datasets SET status = 'DELETING', active_version_id = NULL "
            "WHERE id = %s AND status = 'ACTIVE'",
            (dataset_id,),
        )
        ops._event(
            conn, workspace_id, dataset_id, None, EventType.DATASET_DELETION_REQUESTED,
            "ACTIVE", to_status="DELETING", reason=ReasonCode.WORKSPACE_OFFBOARDING,
        )  # fmt: skip
        moved += 1
    return moved


def request_offboarding(
    conn: psycopg.Connection[Any], workspace_id: uuid.UUID, *, operator: str
) -> dict[str, Any]:
    """ACTIVE -> OFFBOARDING, and every live dataset -> DELETING, atomically."""
    _operator(operator)
    ops._require_runtimes_permitted(conn)
    with conn.transaction():
        status = _status(conn, workspace_id, lock=True)
        if status == "OFFBOARDED":
            raise OffboardingError("the workspace is already offboarded")
        changed = status == "ACTIVE"
        if changed:
            conn.execute(
                "UPDATE workspaces SET status = 'OFFBOARDING', offboarding_requested_at = now() "
                "WHERE id = %s AND status = 'ACTIVE'",
                (workspace_id,),
            )
        moved = _datasets_to_deleting(conn, workspace_id)
    return {"workspace_id": str(workspace_id), "changed": int(changed), "datasets_deleting": moved}


# --- complete ------------------------------------------------------------------


def _purge_rows(conn: psycopg.Connection[Any], workspace_id: uuid.UUID) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in PURGE_ORDER:
        cur = conn.execute(
            sql.SQL("DELETE FROM {} WHERE {} = %s").format(
                sql.Identifier(table), sql.Identifier(_scope(table))
            ),
            (workspace_id,),
        )
        counts[table] = cur.rowcount
    for table in PURGE_ORDER:
        left = conn.execute(
            sql.SQL("SELECT count(*) FROM {} WHERE {} = %s").format(
                sql.Identifier(table), sql.Identifier(_scope(table))
            ),
            (workspace_id,),
        ).fetchone()
        if left is None or left[0] != 0:
            raise OffboardingError(f"rows of {table} are still present")
    return counts


def complete_offboarding(
    conn: psycopg.Connection[Any],
    store: BlobStore | None,
    log: DeletionLog,
    workspace_id: uuid.UUID,
    *,
    operator: str,
    environment: str,
) -> dict[str, Any]:
    """Purge and tombstone the workspace (see the module docstring). Re-running
    after a failure is safe: finished datasets are skipped and the row purge
    and the tombstone are one transaction."""
    _operator(operator)
    ops._preflight(log)
    ops._require_runtimes_permitted(conn)
    if _status(conn, workspace_id) != "OFFBOARDING":
        raise OffboardingError(
            f"the workspace is {_status(conn, workspace_id)}, not OFFBOARDING: run request"
        )
    live = conn.execute(
        "SELECT count(*) FROM datasets WHERE tenant_id = %s AND status = 'ACTIVE'",
        (workspace_id,),
    ).fetchone()
    if live is None or live[0]:
        raise OffboardingError("a dataset of the workspace is still ACTIVE: run request")
    for (dataset_id,) in conn.execute(
        "SELECT id FROM datasets WHERE tenant_id = %s AND status = 'DELETING' ORDER BY id",
        (workspace_id,),
    ).fetchall():
        ops.purge(
            conn, store, log, dataset_id=dataset_id, operator=operator, environment=environment
        )
        ops.tombstone(conn, dataset_id=dataset_id, store=store, log=log)
    dataset_ids = [
        r[0]
        for r in conn.execute(
            "SELECT id FROM datasets WHERE tenant_id = %s ORDER BY id", (workspace_id,)
        ).fetchall()
    ]
    with conn.transaction():
        if _status(conn, workspace_id, lock=True) != "OFFBOARDING":
            raise OffboardingError("the workspace changed state: re-run")
        not_deleted = conn.execute(
            "SELECT count(*) FROM datasets WHERE tenant_id = %s AND status <> 'DELETED'",
            (workspace_id,),
        ).fetchone()
        if not_deleted is None or not_deleted[0]:
            raise OffboardingError("a dataset of the workspace is not tombstoned")
        secrets = conn.execute(
            "SELECT count(*) FROM connectors WHERE tenant_id = %s AND secret_ref IS NOT NULL",
            (workspace_id,),
        ).fetchone()
        counts = _purge_rows(conn, workspace_id)
        receipt = WorkspaceReceipt.for_workspace(
            sink=log.sink_id, environment=environment, tenant_id=workspace_id,
            dataset_ids=dataset_ids, table_counts=counts, operator=operator,
        )  # fmt: skip
        try:
            receipt_id = log.append_workspace(receipt)
        except DeletionLogUnavailable as exc:
            raise OffboardingError(str(exc)) from None
        conn.execute(
            "UPDATE workspaces SET status = 'OFFBOARDED', name = 'offboarded', "
            "slug = 'offboarded-' || id::text, offboarded_at = now(), offboarded_by = %s, "
            "offboard_receipt_id = %s, offboard_counts = %s::jsonb "
            "WHERE id = %s AND status = 'OFFBOARDING'",
            (
                operator,
                receipt_id,
                _counts_json(receipt),
                workspace_id,
            ),
        )
    return {
        "workspace_id": str(workspace_id),
        "datasets_tombstoned": len(dataset_ids),
        "rows_purged": sum(counts.values()),
        "connector_secret_refs": int(secrets[0]) if secrets else 0,
        "receipt": receipt_id,
    }


def _counts_json(receipt: WorkspaceReceipt) -> str:
    return json.dumps(
        {
            "datasets_tombstoned": receipt.datasets_tombstoned,
            "dataset_ids_sha256": receipt.dataset_ids_sha256,
            "table_counts": receipt.table_counts,
            "offboarding_set_sha256": receipt.offboarding_set_sha256,
            "receipt_sink": receipt.sink,
        },
        sort_keys=True,
    )


def pending_offboardings(conn: psycopg.Connection[Any]) -> list[tuple[Any, ...]]:
    """OFFBOARDING workspaces (ids and request time only): ``complete`` is due."""
    return conn.execute(
        "SELECT id, offboarding_requested_at FROM workspaces WHERE status = 'OFFBOARDING' "
        "ORDER BY offboarding_requested_at, id"
    ).fetchall()


# --- restore and reconciliation ----------------------------------------------


def reapply_workspace_receipts(
    conn: psycopg.Connection[Any], log: DeletionLog, *, dry_run: bool = False
) -> dict[str, Any]:
    """While the recovery lock holds a restored database: every workspace a
    receipt proves offboarded is moved back to OFFBOARDING (no runtime can
    reach it) unless it already is OFFBOARDING or OFFBOARDED. Its rows are
    purged again by ``complete`` once the runtimes are enabled."""
    try:
        refs = sorted(set(log.workspace_refs()))
    except DeletionLogUnavailable as exc:
        raise OffboardingError(str(exc)) from None
    out: dict[str, Any] = dict.fromkeys(
        (
            "workspace_receipts",
            "workspaces_reoffboarded",
            "workspaces_already",
            "workspaces_absent",
        ),
        0,
    )
    unreadable: list[str] = []
    for ref in refs:
        out["workspace_receipts"] += 1
        try:
            record = log.read_workspace(ref)
        except DeletionLogUnavailable:
            record = None
        if (
            not workspace_receipt_self_consistent(record)
            or record is None
            or record.get("sink") != log.sink_id
        ):
            unreadable.append(str(ref.tenant_id))
            continue
        with conn.transaction():
            row = conn.execute(
                "SELECT status FROM workspaces WHERE id = %s FOR UPDATE", (ref.tenant_id,)
            ).fetchone()
            if row is None:
                out["workspaces_absent"] += 1
                continue
            if row[0] != "ACTIVE":
                out["workspaces_already"] += 1
                continue
            if not dry_run:
                conn.execute(
                    "UPDATE workspaces SET status = 'OFFBOARDING', "
                    "offboarding_requested_at = now() WHERE id = %s AND status = 'ACTIVE'",
                    (ref.tenant_id,),
                )
            out["workspaces_reoffboarded"] += 1
    return {**out, "workspace_unreadable": sorted(set(unreadable))}


def reconcile_workspace_receipts(conn: psycopg.Connection[Any], log: DeletionLog) -> dict[str, Any]:
    """The receipt of every OFFBOARDED workspace, verified (``<id>:<check>``),
    and workspace receipts no tombstone names (ids only)."""
    unverified: list[str] = []
    named: set[str] = set()
    for wid, rid, requested, counts in conn.execute(
        "SELECT id, offboard_receipt_id, offboarding_requested_at, offboard_counts "
        "FROM workspaces WHERE status = 'OFFBOARDED' ORDER BY id"
    ).fetchall():
        named.add(str(rid))
        try:
            sink = str(counts["receipt_sink"])
            digest = str(counts["offboarding_set_sha256"])
        except (KeyError, TypeError):
            unverified.append(f"{wid}:{ReceiptCheck.MALFORMED.value}")
            continue
        if sink != log.sink_id:
            unverified.append(f"{wid}:{ReceiptCheck.SINK_MISMATCH.value}")
            continue
        check = log.verify_workspace(
            ExpectedWorkspaceReceipt(
                sink=sink, receipt_id=str(rid), tenant_id=wid,
                offboarding_set_sha256=digest, not_before=requested,
            )
        )  # fmt: skip
        if check is not ReceiptCheck.VERIFIED:
            unverified.append(f"{wid}:{check.value}")
    try:
        refs: list[WorkspaceReceiptRef] = sorted(log.workspace_refs())
    except DeletionLogUnavailable as exc:
        raise OffboardingError(str(exc)) from None
    return {
        "workspace_unverified": sorted(unverified),
        "workspace_receipts_without_tombstone": sorted(
            {str(r.tenant_id) for r in refs if r.receipt_id not in named}
        ),
    }


# --- CLI (``python -m nlw.ops.offboarding``) ------------------------------------------


def run_cli(args: Any) -> int:
    import sys

    from pydantic import ValidationError

    from nlw.core.config import Settings
    from nlw.storage.factory import dataset_store

    try:
        settings = Settings()
        with psycopg.connect(ops._owner_url(), autocommit=True) as conn:
            if args.cmd == "pending":
                for row in pending_offboardings(conn):
                    print("\t".join(str(v) for v in row))
                return 0
            try:
                workspace_id = uuid.UUID(args.workspace)
            except ValueError:
                raise OffboardingError("--workspace must be a UUID") from None
            if args.cmd == "request":
                result = request_offboarding(conn, workspace_id, operator=args.operator)
            else:
                result = complete_offboarding(
                    conn, dataset_store(settings, service="operator"),
                    ops._configured_log(settings), workspace_id, operator=args.operator,
                    environment=settings.app_env,
                )  # fmt: skip
            print(" ".join(f"{k}={v}" for k, v in result.items()))
            return 0
    except ops.TombstoneError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValidationError as exc:
        print(f"error: invalid configuration: {ops.config_reasons(exc, Settings)}", file=sys.stderr)
        return 2
