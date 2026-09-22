"""plan_request_provenance

Durably bind the natural-language request to the plan it produced (M12B-A
addendum, Part 1). Adds three columns to the existing immutable planner audit
snapshot ``plan_proposals`` (no new table): the original request text (bounded by
``llm_max_prompt_chars`` at the API before persistence), its sha256 digest (to
detect any unnoticed mutation), and the planner contract version that produced
the plan.

Immutability is preserved WITHOUT any grant change: ``nlw_app`` holds only
``UPDATE(workflow_version_id, updated_at)`` (from 0007), so it can never UPDATE
``request_text`` after INSERT. RLS is unchanged (membership-bound, tenant-scoped
from 0007), so a request is never readable across tenants. The columns are
nullable so historical rows (which intentionally stored only ``prompt_len``)
remain valid; new rows always set them.

Revision ID: 0017_plan_request_provenance
Revises: 0016_signed_database_context
Create Date: 2026-09-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_plan_request_provenance"
down_revision: str | Sequence[str] | None = "0016_signed_database_context"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("plan_proposals", sa.Column("request_text", sa.Text(), nullable=True))
    op.add_column(
        "plan_proposals", sa.Column("request_sha256", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "plan_proposals", sa.Column("planner_contract_version", sa.String(), nullable=True)
    )
    # No grant change: the existing column-limited UPDATE grant (0007) already
    # makes request_text/request_sha256/planner_contract_version immutable to
    # nlw_app after INSERT. RLS policies are unchanged and already cover the new
    # columns (they are row-scoped, not column-scoped).


def downgrade() -> None:
    op.drop_column("plan_proposals", "planner_contract_version")
    op.drop_column("plan_proposals", "request_sha256")
    op.drop_column("plan_proposals", "request_text")
