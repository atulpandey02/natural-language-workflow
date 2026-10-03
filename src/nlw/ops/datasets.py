"""Operator tombstone for dataset metadata (ADR-029), owner credential only.

The runtime role can request deletion (-> DELETING) but can never write DELETED
(RLS). The tombstone is applied here, by the named operator, with the OWNER
credential ``DATABASE_MIGRATION_URL``, exactly like ``python -m nlw.ops.grants``::

    python -m nlw.ops.datasets pending                      # DELETING datasets/versions
    python -m nlw.ops.datasets tombstone --dataset <uuid>   # whole dataset
    python -m nlw.ops.datasets tombstone --dataset <uuid> --version <uuid>

The tombstone scrubs names, description, original filename and storage key to
NULL and keeps ids, version numbers, digests, sizes, actors and timestamps, plus
the append-only event trail. No storage object exists yet, so a version that has
a ``storage_object_key`` is REFUSED: physical object deletion must be built and
verified first (the deletion launch gate). Output carries ids and counts only,
never names.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from typing import Any

import psycopg

from nlw.datasets.lifecycle import ActorKind, EventType, ReasonCode


class TombstoneError(ValueError):
    """An operator input or state error (message is safe to print)."""


def _owner_url() -> str:
    url = os.environ.get("DATABASE_MIGRATION_URL")
    if not url:
        raise SystemExit("DATABASE_MIGRATION_URL (owner credential) is required")
    return url.replace("+psycopg", "", 1)


def _event(
    conn: psycopg.Connection[Any],
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID | None,
    event_type: EventType,
    from_status: str,
) -> None:
    conn.execute(
        "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
        "from_status, to_status, actor_kind, actor_user_id, reason_code) "
        "VALUES (%s, %s, %s, %s, %s, %s, 'DELETED', %s, NULL, %s)",
        (
            uuid.uuid4(),
            tenant_id,
            dataset_id,
            version_id,
            event_type.value,
            from_status,
            ActorKind.OPERATOR.value,
            ReasonCode.OPERATOR_TOMBSTONE.value,
        ),
    )


def _tombstone_versions(
    conn: psycopg.Connection[Any],
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_ids: list[uuid.UUID],
) -> int:
    for vid in version_ids:
        conn.execute(
            "UPDATE dataset_versions SET status = 'DELETED', original_filename = NULL, "
            "storage_object_key = NULL WHERE id = %s AND status = 'DELETING'",
            (vid,),
        )
        _event(conn, tenant_id, dataset_id, vid, EventType.VERSION_TOMBSTONED, "DELETING")
    return len(version_ids)


def tombstone(
    conn: psycopg.Connection[Any], *, dataset_id: uuid.UUID, version_id: uuid.UUID | None = None
) -> dict[str, Any]:
    """Tombstone one DELETING version, or a DELETING dataset with all its
    versions, in one transaction. Refuses anything not already DELETING and any
    version that still references a storage object."""
    with conn.transaction():
        ds = conn.execute(
            "SELECT tenant_id, status FROM datasets WHERE id = %s FOR UPDATE", (dataset_id,)
        ).fetchone()
        if ds is None:
            raise TombstoneError("no such dataset")
        tenant_id, ds_status = ds
        if version_id is not None:
            v = conn.execute(
                "SELECT status, storage_object_key IS NOT NULL FROM dataset_versions "
                "WHERE id = %s AND dataset_id = %s FOR UPDATE",
                (version_id, dataset_id),
            ).fetchone()
            if v is None:
                raise TombstoneError("no such version for this dataset")
            if v[0] != "DELETING":
                raise TombstoneError(f"version is {v[0]}, not DELETING")
            if v[1]:
                raise TombstoneError(
                    "version references a storage object: physical deletion is not implemented"
                )
            n = _tombstone_versions(conn, tenant_id, dataset_id, [version_id])
            return {"dataset_id": str(dataset_id), "versions_tombstoned": n, "dataset": ds_status}
        if ds_status != "DELETING":
            raise TombstoneError(f"dataset is {ds_status}, not DELETING")
        rows = conn.execute(
            "SELECT id, status, storage_object_key IS NOT NULL FROM dataset_versions "
            "WHERE dataset_id = %s ORDER BY version_number FOR UPDATE",
            (dataset_id,),
        ).fetchall()
        if any(r[2] for r in rows):
            raise TombstoneError(
                "a version references a storage object: physical deletion is not implemented"
            )
        pending = [r[0] for r in rows if r[1] == "DELETING"]
        n = _tombstone_versions(conn, tenant_id, dataset_id, pending)
        conn.execute(
            "UPDATE datasets SET status = 'DELETED', name = NULL, normalized_name = NULL, "
            "description = NULL WHERE id = %s AND status = 'DELETING'",
            (dataset_id,),
        )
        _event(conn, tenant_id, dataset_id, None, EventType.DATASET_TOMBSTONED, "DELETING")
        return {"dataset_id": str(dataset_id), "versions_tombstoned": n, "dataset": "DELETED"}


def pending(conn: psycopg.Connection[Any]) -> list[tuple[Any, ...]]:
    """Datasets awaiting a tombstone: DELETING datasets, and live datasets that
    hold DELETING versions. Columns: tenant id, dataset id, dataset status,
    deletion requested at (NULL for a live dataset), DELETING version count.
    Ids, states and counts only."""
    return conn.execute(
        "SELECT d.tenant_id, d.id, d.status, d.deletion_requested_at, "
        "count(v.id) FILTER (WHERE v.status = 'DELETING') "
        "FROM datasets d LEFT JOIN dataset_versions v ON v.dataset_id = d.id "
        "GROUP BY d.tenant_id, d.id, d.status, d.deletion_requested_at "
        "HAVING d.status = 'DELETING' OR count(v.id) FILTER (WHERE v.status = 'DELETING') > 0 "
        "ORDER BY d.deletion_requested_at NULLS LAST, d.id"
    ).fetchall()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ops.datasets")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pending")
    tomb = sub.add_parser("tombstone")
    tomb.add_argument("--dataset", required=True)
    tomb.add_argument("--version", default=None)
    args = p.parse_args(argv)
    try:
        with psycopg.connect(_owner_url(), autocommit=True) as conn:
            if args.cmd == "pending":
                for row in pending(conn):
                    print("\t".join(str(v) for v in row))
                return 0
            try:
                ds = uuid.UUID(args.dataset)
                ver = uuid.UUID(args.version) if args.version else None
            except ValueError as exc:
                raise TombstoneError("--dataset and --version must be UUIDs") from exc
            result = tombstone(conn, dataset_id=ds, version_id=ver)
            print(" ".join(f"{k}={v}" for k, v in result.items()))
            return 0
    except TombstoneError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
