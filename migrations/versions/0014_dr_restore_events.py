"""disaster-recovery restore audit + quiescence event log (M11.5 P2)

Adds ``dr_restore_events`` — an append-only, platform-level (NOT tenant-scoped)
audit record of every post-restore quiescence run: when the snapshot was restored,
the recovery CUTOFF instant, the manifest/snapshot identity, the migration
revision, and how much non-terminal work was quiesced.

The recovery REASON (``DR_RESTORE_UNCERTAIN``) is a stable sanitized string written
into the existing ``error`` text columns of workflow_runs/step_runs and the P1C
``unknown`` external-action status — so no run/step/action enum changes are needed.

Non-tenant-forgeable: runtime roles (nlw_app/nlw_worker/nlw_scheduler) get NO write
grant and only a MINIMAL, column-scoped SELECT on the recovery-lock state columns
(id, restored_at, validation_completed_at, runtime_enabled_at) — needed for their
mandatory startup preflight (M11.5 P2 addendum). Only the owner/restore (operator)
connection can INSERT an event, mark it validated, or enable runtime; runtime roles
cannot read the provenance/note columns. It is intentionally OUTSIDE row-level
security (a platform operations table, not tenant data).

Reversible. Downgrade drops the table (losing the DR audit trail — documented).

Revision ID: 0014_dr_restore_events
Revises: 0013_scheduler_reconciler
Create Date: 2026-09-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_dr_restore_events"
down_revision: str | Sequence[str] | None = "0013_scheduler_reconciler"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dr_restore_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        # When the quiescence ran, and the CUTOFF instant that separates
        # "restored from the snapshot" from "may have happened after it".
        sa.Column(
            "restored_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("cutoff_at", sa.DateTime(timezone=True), nullable=False),
        # Non-secret provenance (mirrors the backup manifest; never any payload).
        sa.Column("manifest_format", sa.String(), nullable=True),
        sa.Column("snapshot_id", sa.String(), nullable=True),
        sa.Column("alembic_revision", sa.String(), nullable=True),
        sa.Column("app_version", sa.String(), nullable=True),
        sa.Column("pg_version", sa.String(), nullable=True),
        # Counts of what this quiescence transitioned (audit; idempotent re-runs
        # record 0). No tenant ids, no payloads.
        sa.Column("runs_quiesced", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("steps_quiesced", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("actions_unknowned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("schedules_recomputed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("note", sa.Text(), nullable=True),
        # --- Authoritative recovery-lock state machine (addendum) ---
        # A restored generation is runtime-LOCKED until an operator explicitly
        # enables it. Startup for api/worker/scheduler consults this DB state
        # (not an env flag / file), so a restored DB cannot serve before enablement.
        #   quiesced  -> validation_completed_at set by the restore after validation
        #   validated -> runtime_enabled_at set by the explicit operator enable command
        # The runtime roles get column-scoped SELECT only (below); they can never
        # write these, so the lock is not forgeable by a runtime/tenant role.
        sa.Column("target_project", sa.String(), nullable=True),
        sa.Column("validation_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("runtime_enabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("runtime_enabled_by", sa.String(), nullable=True),
    )
    # Runtime roles get MINIMAL, column-scoped, READ-ONLY access so their startup
    # preflight can read the newest generation's lock state — never the manifest
    # provenance, counts, or note, and never any write. Only the owner/restore
    # (operator) connection can INSERT a restore event, mark it validated, or enable
    # runtime. So a runtime/tenant role can neither forge nor unlock a restore.
    op.execute(
        "GRANT SELECT (id, restored_at, validation_completed_at, runtime_enabled_at) "
        "ON dr_restore_events TO nlw_app, nlw_worker, nlw_scheduler"
    )


def downgrade() -> None:
    # WARNING: dropping dr_restore_events discards the disaster-recovery audit
    # trail (when a restore happened, its cutoff, and what was quiesced). The
    # restored runs/steps/actions themselves keep their DR_RESTORE_UNCERTAIN /
    # unknown states (those are ordinary column values, unaffected by this drop).
    op.drop_table("dr_restore_events")
