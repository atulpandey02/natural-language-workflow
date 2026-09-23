"""connector_bindings

Bind each connector-backed step of a materialized workflow to the authoritative
connector IDENTITY + a non-secret config fingerprint (M12B final correction,
Part 3). ``workflow_versions.connector_bindings`` is a JSONB map
``{step_id: {connector_id, connector_type, config_fingerprint}}`` computed
deterministically at materialization; execution loads by the bound UUID and fails
closed (STALE_PLAN) if the connector was deleted/recreated, type-changed, or its
execution-relevant configuration changed.

Nullable, no default: historical versions predate binding and read as NULL (they
fall back to name resolution, unchanged). New versions always populate it for
every connector-backed step. No grant change: ``nlw_app``/``nlw_worker`` already
hold the row-scoped access to ``workflow_versions`` that covers a new column.
Fully reversible.

Revision ID: 0019_connector_bindings
Revises: 0018_transmission_boundary
Create Date: 2026-09-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0019_connector_bindings"
down_revision: str | Sequence[str] | None = "0018_transmission_boundary"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "workflow_versions",
        sa.Column("connector_bindings", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("workflow_versions", "connector_bindings")
