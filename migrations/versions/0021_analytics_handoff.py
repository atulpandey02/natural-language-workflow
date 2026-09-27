"""Immutable analytics-to-Slack provenance; existing RLS and grants unchanged.

Revision ID: 0021_analytics_handoff
Revises: 0020_schedule_authorization
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0021_analytics_handoff"
down_revision: str | Sequence[str] | None = "0020_schedule_authorization"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # nlw_app can INSERT/SELECT, but only UPDATE workflow_version_id/updated_at.
    # Inherited row policies use the signed, membership-bound request context.
    op.add_column(
        "plan_proposals", sa.Column("analytics_source", postgresql.JSONB(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("plan_proposals", "analytics_source")
