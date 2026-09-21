"""external action UNKNOWN (ambiguous) outcome (M11.5 P1C)

Add an explicit terminal ``unknown`` status to ``external_actions`` for an
external side effect whose transmission may have occurred but whose result cannot
be proven. It is terminal for automatic delivery: never retried, never
re-enqueued by reconciliation. Step and run remain FAILED (with an
``ACTION_OUTCOME_UNKNOWN`` error class) — no new step/run state is introduced.

Only the ``ck_external_action_status`` CHECK changes. Reversible; the downgrade
restores the 3-value set (see the security note in downgrade()).

Revision ID: 0012_action_unknown_outcome
Revises: 0011_identity_connector_authz
Create Date: 2026-09-21
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0012_action_unknown_outcome"
down_revision: str | Sequence[str] | None = "0011_identity_connector_authz"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE external_actions DROP CONSTRAINT ck_external_action_status")
    op.execute(
        "ALTER TABLE external_actions ADD CONSTRAINT ck_external_action_status "
        "CHECK (status in ('pending','success','failed','unknown'))"
    )


def downgrade() -> None:
    # WARNING: downgrading below 0012 removes the 'unknown' terminal status. Any
    # external_actions row currently in 'unknown' would violate the restored
    # 3-value CHECK. This downgrade first rewrites 'unknown' -> 'failed' so the
    # constraint can be re-applied; that LOSES the "may have been delivered"
    # distinction (an ambiguous outcome is then reported as a definite failure).
    #
    # It does NOT silently reactivate automatic delivery of those actions: the
    # owning step and run are already terminal FAILED, and the reconciler only
    # re-enqueues PENDING/RUNNING/WAITING_APPROVAL runs, never FAILED ones — so a
    # collapsed row is not re-attempted. The only loss is the ambiguity signal an
    # operator would use to reconcile the receiver. PREFER FIX-FORWARD on a live
    # pilot; do NOT run this without operator review of any unknown rows.
    op.execute("UPDATE external_actions SET status = 'failed' WHERE status = 'unknown'")
    op.execute("ALTER TABLE external_actions DROP CONSTRAINT ck_external_action_status")
    op.execute(
        "ALTER TABLE external_actions ADD CONSTRAINT ck_external_action_status "
        "CHECK (status in ('pending','success','failed'))"
    )
