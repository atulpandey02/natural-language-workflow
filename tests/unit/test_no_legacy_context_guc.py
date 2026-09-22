"""Static regression guard (M11.5 P3B, ADR-024): nothing after migration 0016 may
re-introduce trust in the unsigned ``app.user_id`` / ``app.tenant_id`` settings.

The runtime proof lives in ``tests/integration/test_signed_context.py`` (every live
policy scanned against a real PostgreSQL) and in ``nlw.backup.validate``; this test
catches the regression at review time, before a database exists:

* any migration NEWER than 0016 that references the legacy settings;
* any application code that sets or reads them (the app signs ``app.ctx_*`` only).
"""

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_MIGRATIONS = _ROOT / "migrations" / "versions"
_SRC = _ROOT / "src" / "nlw"
_CUTOVER = 16  # 0016_signed_database_context

# Forms that would make PostgreSQL or the application TRUST an unsigned setting.
# Prose mentions in docstrings/comments are fine; these match executable shapes.
_LEGACY = re.compile(
    r"current_setting\(\s*'app\.(user|tenant)_id'"
    r"|set_config\(\s*'app\.(user|tenant)_id'"
    r"|SET\s+LOCAL\s+app\.(user|tenant)_id"
    r"|app\.(user|tenant)_id\s*=",
    re.IGNORECASE,
)


def _revision(path: Path) -> int:
    return int(path.name.split("_", 1)[0])


def test_no_migration_after_0016_references_unsigned_context() -> None:
    newer = [p for p in _MIGRATIONS.glob("0*.py") if _revision(p) > _CUTOVER]
    offenders = [p.name for p in newer if _LEGACY.search(p.read_text(encoding="utf-8"))]
    assert offenders == [], f"migrations trusting unsigned context: {offenders}"


def test_cutover_migration_only_references_legacy_settings_for_downgrade() -> None:
    """0016 may spell the legacy settings ONLY inside the downgrade-only policy
    table (``_LEGACY_POLICIES`` / ``_L_*`` macros) and the legacy helper bodies it
    recreates on downgrade — never in the signed policy set it installs."""
    src = (_MIGRATIONS / "0016_signed_database_context.py").read_text(encoding="utf-8")
    # The signed policy table runs from the ``_POLICIES`` definition up to the
    # first downgrade-only macro (``_L_USER``); the legacy table follows it.
    signed_block = src[src.index("\n_POLICIES") : src.index("\n_L_USER =")]
    assert not _LEGACY.search(signed_block), "signed policy set references a legacy setting"
    upgrade = src[src.index("def upgrade") : src.index("def downgrade")]
    assert "_drop_policies(_LEGACY_POLICIES)" in upgrade, "upgrade() must drop the legacy policies"
    assert "_create_policies(_POLICIES)" in upgrade, "upgrade() must install the signed policies"
    assert "_create_policies(_LEGACY_POLICIES)" not in upgrade, (
        "upgrade() must never install the legacy policy table"
    )


def test_application_never_sets_or_reads_unsigned_context() -> None:
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if path.name == "validate.py" and "backup" in path.parts:
            continue  # the restore validator greps FOR the legacy forms to reject them
        if "rollout" in path.parts and path.name in ("phases.py", "smoke.py"):
            continue  # the rollout FORGES legacy settings as nlw_app to prove they grant nothing
        for m in _LEGACY.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            offenders.append(f"{path.relative_to(_ROOT)}:{line}")
    assert offenders == [], f"application code touches unsigned context: {offenders}"
