"""Tenant data inventory for offboarding (Phase 2 plan section 0.6), read-only.

Every table in the ``public`` schema is classified here against the plan's
offboarding matrix. The classification is the contract a future purge must
implement; a unit/integration test fails if a table is added without being
classified, so no tenant data can silently escape offboarding.

    DATABASE_MIGRATION_URL=... python -m nlw.ops.offboarding inventory --workspace <uuid>

prints per-table row counts for one workspace (counts only, never values). It
changes nothing. The purge itself is NOT implemented: its retention behaviour
depends on the customer deletion statement awaiting owner approval (plan §22).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from dataclasses import dataclass
from typing import Any, Literal

import psycopg
from psycopg import sql

Artefact = Literal[
    "workspace_metadata",
    "dataset_metadata",
    "workflow_definitions",
    "reports_and_results",
    "external_delivery_record",
    "connector_reference",
    "audit",
    "planning_evidence",
    "platform",
]
Scope = Literal["tenant_id", "workspace_id", "id", "none"]


@dataclass(frozen=True)
class TableClass:
    artefact: Artefact
    scope: Scope  # the column that ties a row to one workspace
    on_offboarding: str


# The contract (plan section 0.6). "retain" rows are kept by design and are
# listed so the customer statement can say so explicitly. Retention PERIODS are
# pilot policy proposals awaiting owner approval, never legal or compliance
# commitments (owner decision, 2026-09-29), so none is stated as settled here.
TABLES: dict[str, TableClass] = {
    "workspaces": TableClass("workspace_metadata", "id", "purge after dependants; tombstone kept"),
    "memberships": TableClass("workspace_metadata", "workspace_id", "purge"),
    "workspace_invitations": TableClass("workspace_metadata", "tenant_id", "purge"),
    "workflows": TableClass("workflow_definitions", "tenant_id", "purge"),
    "workflow_versions": TableClass("workflow_definitions", "tenant_id", "purge"),
    "schedules": TableClass("workflow_definitions", "tenant_id", "purge"),
    "workflow_runs": TableClass("reports_and_results", "tenant_id", "purge (full purge)"),
    "step_runs": TableClass("reports_and_results", "tenant_id", "purge (full purge)"),
    "approvals": TableClass("reports_and_results", "tenant_id", "purge (full purge)"),
    "plan_proposals": TableClass("planning_evidence", "tenant_id", "purge (request_text too)"),
    "external_actions": TableClass(
        "external_delivery_record",
        "tenant_id",
        "retain as delivery audit; delivered Slack messages cannot be recalled",
    ),
    "connectors": TableClass(
        "connector_reference", "tenant_id", "purge row; secret versions deleted in the store"
    ),
    "authz_audit_events": TableClass(
        "audit",
        "tenant_id",
        "retain (ids/codes only); period is a pilot proposal, not yet approved",
    ),
    # Dataset metadata (ADR-029): no file bytes or rows live in these tables.
    "datasets": TableClass(
        "dataset_metadata",
        "tenant_id",
        "request deletion -> DELETING; operator tombstone -> DELETED (names scrubbed)",
    ),
    "dataset_versions": TableClass(
        "dataset_metadata",
        "tenant_id",
        "-> DELETING with the dataset; operator tombstone scrubs filename and storage key",
    ),
    "dataset_events": TableClass(
        "audit", "tenant_id", "retain (codes and ids only); period is a pilot proposal"
    ),
    # Phase 2B (ADR-030): derived from uploaded bytes; never rows or samples.
    "dataset_profiles": TableClass(
        "dataset_metadata",
        "tenant_id",
        "operator tombstone scrubs the profile (counts and digest kept)",
    ),
    "dataset_semantic_revisions": TableClass(
        "dataset_metadata",
        "tenant_id",
        "operator tombstone scrubs the mapping (revision numbers and actors kept)",
    ),
    # ADR-031: immutable processing requests (ids, digests, requester, time only;
    # no names, filenames, keys or content).
    "dataset_processing_requests": TableClass(
        "dataset_metadata",
        "tenant_id",
        "retain with the version (ids and digests only); period is a pilot proposal",
    ),
    "plan_outcome_events": TableClass(
        "audit", "tenant_id", "retain (codes only); proposed 13 months, not yet approved"
    ),
    # Platform tables: not tenant data.
    "users": TableClass("platform", "none", "identity rows are not workspace data"),
    "workspace_creation_grants": TableClass("platform", "none", "operator grant ledger"),
    "ctx_keys": TableClass("platform", "none", "signing-key registry"),
    "ctx_key_events": TableClass("platform", "none", "signing-key audit"),
    "dr_restore_events": TableClass("platform", "none", "restore audit"),
    "alembic_version": TableClass("platform", "none", "schema revision"),
}


def unclassified_tables(conn: psycopg.Connection[Any]) -> list[str]:
    """Tables in ``public`` that the contract does not classify (must be empty)."""
    rows = conn.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"
    ).fetchall()
    return [r[0] for r in rows if r[0] not in TABLES]


def scope_mismatches(conn: psycopg.Connection[Any]) -> list[str]:
    """A classified tenant table whose scope column no longer exists."""
    bad = []
    for table, cls in TABLES.items():
        if cls.scope == "none":
            continue
        found = conn.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name=%s AND column_name=%s",
            (table, cls.scope),
        ).fetchone()
        exists = conn.execute("SELECT to_regclass(%s)", (f"public.{table}",)).fetchone()
        if exists and exists[0] is not None and found is None:
            bad.append(f"{table}.{cls.scope}")
    return bad


def inventory(conn: psycopg.Connection[Any], workspace_id: uuid.UUID) -> dict[str, Any]:
    """Row counts per tenant table for one workspace, grouped by artefact class."""
    tables: dict[str, dict[str, Any]] = {}
    for table, cls in sorted(TABLES.items()):
        if cls.scope == "none":
            continue
        row = conn.execute(
            sql.SQL("SELECT count(*) FROM {} WHERE {} = %s").format(
                sql.Identifier(table), sql.Identifier(cls.scope)
            ),
            (workspace_id,),
        ).fetchone()
        tables[table] = {
            "artefact": cls.artefact,
            "rows": int(row[0]) if row else 0,
            "on_offboarding": cls.on_offboarding,
        }
    return {
        "workspace_id": str(workspace_id),
        "tables": tables,
        "not_in_database": [
            "uploaded dataset objects (dataset object store; purged by "
            "`python -m nlw.ops.datasets purge`, receipts in the deletion log)",
            "messages already delivered to Slack (cannot be recalled by NLW)",
            "encrypted database backups (expire on the configured restic retention; not edited)",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ops.offboarding")
    sub = p.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("inventory")
    inv.add_argument("--workspace", required=True)
    sub.add_parser("check-contract")
    args = p.parse_args(argv)
    url = os.environ.get("DATABASE_MIGRATION_URL")
    if not url:
        raise SystemExit("DATABASE_MIGRATION_URL (owner credential) is required")
    with psycopg.connect(url.replace("+psycopg", "", 1)) as conn:
        if args.cmd == "check-contract":
            problems = unclassified_tables(conn) + scope_mismatches(conn)
            print(json.dumps({"unclassified_or_mismatched": problems}))
            return 1 if problems else 0
        try:
            ws = uuid.UUID(args.workspace)
        except ValueError:
            print("error: --workspace must be a UUID", file=sys.stderr)
            return 2
        print(json.dumps(inventory(conn, ws), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
