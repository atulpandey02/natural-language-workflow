"""readiness: allow nlw_app to read alembic_version for schema-compat checks

M9. The API readiness endpoint (``GET /health/ready``) verifies the database is
migrated to the revision this code expects by reading ``alembic_version``. The
restricted ``nlw_app`` role has no default privilege on that table, so grant it
SELECT (read-only) here. No schema/DDL change and no tenant data is exposed —
``alembic_version`` holds only the current revision id.

Revision ID: 0010_readiness_schema_grant
Revises: 0009_scheduling
Create Date: 2026-09-19
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010_readiness_schema_grant"
down_revision: str | Sequence[str] | None = "0009_scheduling"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("GRANT SELECT ON alembic_version TO nlw_app")


def downgrade() -> None:
    op.execute("REVOKE SELECT ON alembic_version FROM nlw_app")
