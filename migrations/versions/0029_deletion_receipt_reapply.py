"""Re-applying deletion receipts after a database restore (ADR-034, owner decision O-3).

- Reason code ``RESTORE_REAPPLY``: the operator's ``reapply-receipts`` (run while
  the recovery lock holds a restored database) moves a version whose bytes an
  external deletion receipt proves deleted back to DELETING, and records that
  receipt as its purge evidence, both with this reason. The tombstone accepts
  such evidence although the receipt predates the restored deletion request;
  every other check (identity, digests, live absence) still applies.

- ``ck_dataset_events_purge_shape``: purge evidence (``VERSION_OBJECT_PURGED``,
  operator, DELETING -> DELETING) may carry ``OPERATOR_PURGE`` (a purge) or
  ``RESTORE_REAPPLY`` (a receipt re-applied after a restore); nothing else.

No table, grant, trigger or RLS policy changes (the signed policy count stays 74).

DOWNGRADE: disposable databases only. Refused while any ``RESTORE_REAPPLY``
event exists.

Revision ID: 0029_deletion_receipt_reapply
Revises: 0028_dataset_object_layout
Create Date: 2026-10-14
"""

import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

from alembic import op

revision: str = "0029_deletion_receipt_reapply"
down_revision: str | Sequence[str] | None = "0028_dataset_object_layout"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_REASON_CODES = ("RESTORE_REAPPLY",)


def _m0028() -> ModuleType:
    name = "_nlw_migration_0028_dataset_object_layout"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).parent / "0028_dataset_object_layout.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def reason_codes() -> tuple[str, ...]:
    return (*_m0028().reason_codes(), *NEW_REASON_CODES)


def _purge_shape(reasons: Sequence[str]) -> None:
    op.execute("ALTER TABLE dataset_events DROP CONSTRAINT ck_dataset_events_purge_shape")
    listed = ", ".join(f"'{r}'" for r in reasons)
    op.execute(
        "ALTER TABLE dataset_events ADD CONSTRAINT ck_dataset_events_purge_shape CHECK ("
        "event_type <> 'VERSION_OBJECT_PURGED' OR (actor_kind = 'operator' "
        "AND from_status = 'DELETING' AND to_status = 'DELETING' "
        f"AND reason_code IN ({listed})))"
    )


def upgrade() -> None:
    _m0028()._replace_reason_check(reason_codes())
    _purge_shape(("OPERATOR_PURGE", "RESTORE_REAPPLY"))


def downgrade() -> None:
    op.execute(
        """
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM dataset_events WHERE reason_code = 'RESTORE_REAPPLY') THEN
                RAISE EXCEPTION '0029 downgrade refused: RESTORE_REAPPLY events exist '
                    '(disposable databases only)' USING ERRCODE = '55000';
            END IF;
        END $$
        """
    )
    _purge_shape(("OPERATOR_PURGE",))
    _m0028()._replace_reason_check(_m0028().reason_codes())
