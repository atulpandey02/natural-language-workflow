"""scheduler/reconciler correctness: run progress tracking, scheduled-run
idempotency namespace separation, reconciler indexes (M11.5 P1D)

Adds ``workflow_runs.last_progress_at`` — the last MEANINGFUL execution-state
advancement, server-stamped by the worker on genuine transitions only (see
engine/execution.py, engine/actions.py). The reconciler uses it, instead of the
mutable ``updated_at``, to tell a genuinely stuck run from one still progressing.
Existing rows are backfilled CONSERVATIVELY from the best existing state
timestamp (finished_at > started_at > updated_at > created_at) — we do NOT pretend
every old run progressed at migration time.

Also separates the scheduled-run idempotency namespace from the client one:
scheduled runs no longer store a ``sched:*`` idempotency_key (their uniqueness is
the immutable occurrence identity ``uq_run_schedule_occurrence``). Existing
scheduled rows have their redundant ``sched:*`` key nulled so a client key can
never collide with them.

Adds partial indexes so the reconciler candidate query prunes by status and
sorts within a tenant without a full-table sort each poll.

Privileges: nlw_worker already holds table-level SELECT,UPDATE on workflow_runs
(it writes last_progress_at); nlw_scheduler already holds cross-tenant SELECT on
workflow_runs (it reads it). The ONLY new grant is a COLUMN-RESTRICTED cross-tenant
SELECT (id, tenant_id, run_id, step_id, status) on step_runs for nlw_scheduler, so
the reconciler can bind a decided approval to the currently-blocked step. Step I/O
(input/output/error) remains unreadable to the scheduler. RLS/FORCE-RLS/ownership
are otherwise unchanged.

Reversible. See downgrade() for the documented correctness regression.

Revision ID: 0013_scheduler_reconciler
Revises: 0012_action_unknown_outcome
Create Date: 2026-09-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_scheduler_reconciler"
down_revision: str | Sequence[str] | None = "0012_action_unknown_outcome"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1) Progress column (nullable; server-stamped by the worker going forward).
    op.add_column(
        "workflow_runs",
        sa.Column("last_progress_at", sa.DateTime(timezone=True), nullable=True),
    )
    # 2) Conservative backfill from the best existing state-transition timestamp.
    #    (COALESCE picks the first non-null; created_at is NOT NULL so it always
    #    resolves. This does NOT claim old runs progressed "now".)
    op.execute(
        "UPDATE workflow_runs "
        "SET last_progress_at = COALESCE(finished_at, started_at, updated_at, created_at)"
    )
    # 3) Separate namespaces: drop the redundant scheduler-derived client key so it
    #    can never collide with a user-supplied Idempotency-Key. Occurrence
    #    uniqueness is unaffected (uq_run_schedule_occurrence).
    op.execute(
        "UPDATE workflow_runs SET idempotency_key = NULL "
        "WHERE schedule_id IS NOT NULL AND idempotency_key LIKE 'sched:%'"
    )
    # 4) Reconciler candidate indexes (partial, per hot status; support the
    #    partition-by-tenant ordering + a unique id tie-breaker).
    op.create_index(
        "ix_workflow_runs_recon_running",
        "workflow_runs",
        ["tenant_id", "last_progress_at", "id"],
        postgresql_where=sa.text("status = 'RUNNING'"),
    )
    op.create_index(
        "ix_workflow_runs_recon_pending",
        "workflow_runs",
        ["tenant_id", "created_at", "id"],
        postgresql_where=sa.text("status = 'PENDING'"),
    )
    op.create_index(
        "ix_workflow_runs_recon_waiting",
        "workflow_runs",
        ["tenant_id", "id"],
        postgresql_where=sa.text("status = 'WAITING_APPROVAL'"),
    )
    # 5) The reconciler must bind a decided approval to the CURRENTLY-blocked step
    #    (its step_runs.status), so grant nlw_scheduler a COLUMN-RESTRICTED,
    #    cross-tenant SELECT on step_runs — only (id, tenant_id, run_id, step_id,
    #    status). Step I/O (input/output/error) stays UNREADABLE, preserving the
    #    scheduler's isolation from tenant business data.
    op.execute(
        "GRANT SELECT (id, tenant_id, run_id, step_id, status) ON step_runs TO nlw_scheduler"
    )
    op.execute(
        "CREATE POLICY step_runs_sched_select ON step_runs FOR SELECT TO nlw_scheduler USING (true)"
    )


def downgrade() -> None:
    # WARNING (correctness regression): dropping last_progress_at reverts the
    # reconciler's RUNNING staleness/horizon signal to the mutable ``updated_at``,
    # which advances on any row write and does NOT track step progress — a
    # long-running progressing run can then be re-enqueued prematurely or (worse)
    # trip the recovery horizon while healthy. Prefer fix-forward.
    #
    # The scheduled-run idempotency keys nulled in upgrade() are NOT restored
    # (they were redundant metadata; occurrence uniqueness still holds), so a
    # downgrade leaves those rows with NULL idempotency_key. This is harmless.
    op.execute("DROP POLICY IF EXISTS step_runs_sched_select ON step_runs")
    op.execute("REVOKE ALL ON step_runs FROM nlw_scheduler")
    op.drop_index("ix_workflow_runs_recon_waiting", table_name="workflow_runs")
    op.drop_index("ix_workflow_runs_recon_pending", table_name="workflow_runs")
    op.drop_index("ix_workflow_runs_recon_running", table_name="workflow_runs")
    op.drop_column("workflow_runs", "last_progress_at")
