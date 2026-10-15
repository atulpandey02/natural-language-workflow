"""Inactive-version retention (owner decision O-5, ADR-035).

- Reason code ``INACTIVE_RETENTION``: the operator's ``retention-sweep`` moves
  an unpublished or superseded version to DELETING with it once its 30-day
  retention has ended (never an ACTIVE version), before the verified,
  receipted purge.

No table, grant, trigger or RLS policy changes (the signed policy count stays 74).

DOWNGRADE: disposable databases only. Refused while any ``INACTIVE_RETENTION``
event exists.

Revision ID: 0030_inactive_version_retention
Revises: 0029_deletion_receipt_reapply
Create Date: 2026-10-15
"""

import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

from alembic import op

revision: str = "0030_inactive_version_retention"
down_revision: str | Sequence[str] | None = "0029_deletion_receipt_reapply"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_REASON_CODES = ("INACTIVE_RETENTION",)


def _load(filename: str) -> ModuleType:
    name = f"_nlw_migration_{filename.removesuffix('.py')}"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _m0029() -> ModuleType:
    return _load("0029_deletion_receipt_reapply.py")


def reason_codes() -> tuple[str, ...]:
    return (*_m0029().reason_codes(), *NEW_REASON_CODES)


def upgrade() -> None:
    _m0029()._m0028()._replace_reason_check(reason_codes())


def downgrade() -> None:
    op.execute(
        """
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM dataset_events WHERE reason_code = 'INACTIVE_RETENTION') THEN
                RAISE EXCEPTION '0030 downgrade refused: INACTIVE_RETENTION events exist '
                    '(disposable databases only)' USING ERRCODE = '55000';
            END IF;
        END $$
        """
    )
    _m0029()._m0028()._replace_reason_check(_m0029().reason_codes())
