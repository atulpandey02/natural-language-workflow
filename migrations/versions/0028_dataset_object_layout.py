"""One immutable object per dataset version: the ``versions/`` layout (ADR-033 D1/D2/D4).

- ``dataset_versions.storage_object_key`` accepts the canonical layout
  ``versions/<tenant>/<dataset>/<version>/source.csv``. Legacy development keys
  (``quarantine|datasets/<tenant>/<dataset>/<version>``) stay valid so existing
  rows can still be purged and tombstoned; the tenant/dataset prefix checks and
  ``ck_dataset_versions_key_names_version`` (4th segment = the version id) are
  unchanged.
- The version guard: a key may be set only ONCE, from NULL while QUARANTINED,
  and only to a ``versions/`` key; it never moves afterwards (the
  ``quarantine/ -> datasets/`` move of 0025 is gone: "published" is database
  state) and is cleared only by the tombstone (DELETED).
- ``nlw_ingest`` loses ``UPDATE (storage_object_key)``: the ingest runtime is
  read-only on object storage and can no longer change where a version points.
- Reason code ``REJECTED_RETENTION``: the operator's ``purge-rejected`` moves a
  REJECTED version to DELETING with it before the version-aware purge (D2).

No RLS policy changes (the signed policy count stays 74).

DOWNGRADE: disposable databases only. Refused while any ``versions/`` key or
``REJECTED_RETENTION`` event exists.

Revision ID: 0028_dataset_object_layout
Revises: 0027_dataset_ingest_dispatch
Create Date: 2026-10-09
"""

import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

from alembic import op

revision: str = "0028_dataset_object_layout"
down_revision: str | Sequence[str] | None = "0027_dataset_ingest_dispatch"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_REASON_CODES = ("REJECTED_RETENTION",)
KEY_CHECK = "ck_dataset_versions_key_layout"
LEGACY_KEY_CHECK = "ck_dataset_versions_key_layout_legacy"
# 0024 declared the key check inline (unnamed; it references other columns, so
# PostgreSQL generated its name). It is found by its definition (as is the one a
# 0028 downgrade restores) and replaced by an explicitly named one.
_DROP_INLINE_KEY_CHECK = """
DO $$
DECLARE c text;
BEGIN
    SELECT conname INTO c FROM pg_constraint
     WHERE conrelid = 'public.dataset_versions'::regclass AND contype = 'c'
       AND pg_get_constraintdef(oid) LIKE '%storage_object_key ~%';
    IF c IS NULL THEN
        RAISE EXCEPTION 'the 0024 storage key check was not found' USING ERRCODE = '55000';
    END IF;
    EXECUTE format('ALTER TABLE public.dataset_versions DROP CONSTRAINT %I', c);
END $$
"""
_UUID = "[0-9a-f-]{36}"
_LEGACY_KEY = f"(quarantine|datasets)/{_UUID}/{_UUID}/[a-z0-9][a-z0-9._-]{{0,127}}"
_VERSIONS_KEY = f"versions/{_UUID}/{_UUID}/{_UUID}/source\\.csv"


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


def _m0025() -> ModuleType:
    return _load("0025_dataset_ingestion.py")


def _m0026() -> ModuleType:
    return _load("0026_dataset_ingest_role.py")


def reason_codes() -> tuple[str, ...]:
    return (*_m0025().reason_codes(), *NEW_REASON_CODES)


def _key_check(pattern: str, name: str = KEY_CHECK) -> str:
    return (
        f"ALTER TABLE dataset_versions ADD CONSTRAINT {name} CHECK ("
        "storage_object_key IS NULL OR ("
        "char_length(storage_object_key) <= 300 "
        f"AND storage_object_key ~ '^({pattern})$' "
        "AND split_part(storage_object_key, '/', 2) = tenant_id::text "
        "AND split_part(storage_object_key, '/', 3) = dataset_id::text))"
    )


# The 0025 key rule (kept verbatim by 0026), and its 0028 replacement.
_KEY_HEAD = "        IF NEW.storage_object_key IS DISTINCT FROM OLD.storage_object_key AND NOT ("
_KEY_RULE_0025 = (
    _KEY_HEAD
    + """
            (OLD.storage_object_key IS NULL AND OLD.status = 'QUARANTINED'
             AND NEW.status = 'QUARANTINED')
            OR NEW.status = 'DELETED'
            OR (OLD.status = 'PROFILING' AND NEW.status = 'PROFILED'
                AND OLD.storage_object_key LIKE 'quarantine/%'
                AND NEW.storage_object_key
                    = 'datasets/' || substr(OLD.storage_object_key, 12)))
        THEN"""
)
_KEY_RULE_0028 = (
    _KEY_HEAD
    + """
            (OLD.storage_object_key IS NULL AND OLD.status = 'QUARANTINED'
             AND NEW.status = 'QUARANTINED'
             AND NEW.storage_object_key LIKE 'versions/%')
            OR NEW.status = 'DELETED')
        THEN"""
)


def versions_guard_0028() -> str:
    original = _m0026().versions_guard_0026()
    assert original.count(_KEY_RULE_0025) == 1, "the 0025 key rule must be present exactly once"
    return original.replace(_KEY_RULE_0025, _KEY_RULE_0028)


def _replace_reason_check(values: Sequence[str]) -> None:
    op.execute("ALTER TABLE dataset_events DROP CONSTRAINT dataset_events_reason_code_check")
    listed = ", ".join(f"'{v}'" for v in values)
    op.execute(
        "ALTER TABLE dataset_events ADD CONSTRAINT dataset_events_reason_code_check "
        f"CHECK (reason_code IS NULL OR reason_code IN ({listed}))"
    )


def upgrade() -> None:
    op.execute(_DROP_INLINE_KEY_CHECK)
    op.execute(_key_check(f"{_LEGACY_KEY}|{_VERSIONS_KEY}"))
    op.execute(versions_guard_0028())
    op.execute("REVOKE UPDATE (storage_object_key) ON dataset_versions FROM nlw_ingest")
    _replace_reason_check(reason_codes())


def downgrade() -> None:
    op.execute(
        """
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM dataset_versions WHERE storage_object_key LIKE 'versions/%')
               OR EXISTS (SELECT 1 FROM dataset_events WHERE reason_code = 'REJECTED_RETENTION')
            THEN
                RAISE EXCEPTION '0028 downgrade refused: versions/ keys or REJECTED_RETENTION '
                    'events exist (disposable databases only)' USING ERRCODE = '55000';
            END IF;
        END $$
        """
    )
    _replace_reason_check(_m0025().reason_codes())
    op.execute("GRANT UPDATE (storage_object_key) ON dataset_versions TO nlw_ingest")
    op.execute(_m0026().versions_guard_0026())
    op.execute(f"ALTER TABLE dataset_versions DROP CONSTRAINT {KEY_CHECK}")
    op.execute(_key_check(_LEGACY_KEY, LEGACY_KEY_CHECK))
