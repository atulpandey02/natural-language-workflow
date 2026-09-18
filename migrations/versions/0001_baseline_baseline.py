"""baseline

Empty baseline revision. It establishes the Alembic version table on a clean
database so ``alembic upgrade head`` is meaningful and CI-verifiable. Real
schema starts in M2.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-09-17
"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "0001_baseline"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """No-op baseline."""


def downgrade() -> None:
    """No-op baseline."""
