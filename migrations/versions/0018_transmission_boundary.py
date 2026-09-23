"""action_transmission_boundary

Add the durable ambiguity boundary for external actions (ADR-013 crash-window
correction). ``external_actions.transmission_started_at`` is committed immediately
before the out-of-lock network transmission; if an attempt crosses it but never
finalizes (worker death), lease recovery transitions the action to terminal
ACTION_OUTCOME_UNKNOWN instead of resending a non-idempotent side effect.

Nullable, no default: existing rows are pre-boundary and read as NULL (they are
already terminal or will be re-driven under the new rule). No grant/policy change:
``nlw_worker`` already holds table-level ``UPDATE`` on ``external_actions`` (0008)
under a row-scoped (not column-scoped) RLS policy (0016), which covers the new
column. Fully reversible.

Revision ID: 0018_transmission_boundary
Revises: 0017_plan_request_provenance
Create Date: 2026-09-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_transmission_boundary"
down_revision: str | Sequence[str] | None = "0017_plan_request_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "external_actions",
        sa.Column("transmission_started_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("external_actions", "transmission_started_at")
