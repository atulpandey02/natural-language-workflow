"""Backup/restore config: fail-closed secrets + destructive-confirmation (P2)."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from nlw.backup.config import (
    BackupSettings,
    RestoreSettings,
    sa_engine_url,
    validated_work_dir,
)

_PROD_ENV = {
    "app_env": "production",
    "RESTIC_REPOSITORY": "s3:https://s3.example/bucket/nlw",
    "RESTIC_PASSWORD": "repo-pw",
    "AWS_ACCESS_KEY_ID": "AKIA",
    "AWS_SECRET_ACCESS_KEY": "shh",
    "NLW_BACKUP_DATABASE_URL": "postgresql://nlw:pw@db:5432/nlw",
}


def _backup(**over: object) -> BackupSettings:
    env = {**_PROD_ENV, **over}
    return BackupSettings(**env)  # type: ignore[arg-type]


def test_production_fails_closed_without_each_required_secret() -> None:
    for key in (
        "RESTIC_REPOSITORY",
        "RESTIC_PASSWORD",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "NLW_BACKUP_DATABASE_URL",
    ):
        env = {**_PROD_ENV}
        del env[key]
        with pytest.raises(ValidationError):
            BackupSettings(**env)  # type: ignore[arg-type]


def test_local_does_not_require_provider_secrets() -> None:
    s = BackupSettings(app_env="local")
    assert s.app_env == "local"


def test_retention_and_age_validated() -> None:
    with pytest.raises(ValidationError):
        _backup(NLW_BACKUP_RETENTION_DAILY=0)
    with pytest.raises(ValidationError):
        _backup(NLW_BACKUP_MAX_AGE_HOURS=0)


def test_restic_env_carries_only_secrets_not_parent_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOME_OTHER_SECRET", "leaky")
    env = _backup().restic_env()
    assert env["RESTIC_REPOSITORY"] == "s3:https://s3.example/bucket/nlw"
    assert env["RESTIC_PASSWORD"] == "repo-pw"
    assert "SOME_OTHER_SECRET" not in env  # parent env not forwarded


def test_secrets_are_masked_in_repr() -> None:
    blob = repr(_backup())
    assert "repo-pw" not in blob and "shh" not in blob  # SecretStr masks


def test_restore_requires_matching_confirmation() -> None:
    base = {
        "app_env": "local",
        "NLW_RESTORE_DATABASE_URL": "postgresql://nlw:pw@db/restore",
        "NLW_RESTORE_TARGET_ID": "nlw-dr-restore-2026",
    }
    # No confirmation -> refuse.
    with pytest.raises(ValueError):
        RestoreSettings(**base).require_confirmation()  # type: ignore[arg-type]
    # Wrong confirmation -> refuse.
    with pytest.raises(ValueError):
        RestoreSettings(**base, NLW_RESTORE_CONFIRM="wrong").require_confirmation()  # type: ignore[arg-type]
    # Missing target id -> refuse.
    with pytest.raises(ValueError):
        RestoreSettings(app_env="local", NLW_RESTORE_CONFIRM="x").require_confirmation()
    # Exact match -> ok.
    RestoreSettings(**base, NLW_RESTORE_CONFIRM="nlw-dr-restore-2026").require_confirmation()  # type: ignore[arg-type]


def test_immutable_mode_plus_local_prune_is_a_contradiction() -> None:
    # Immutable writer + a forced local prune is contradictory -> fail closed.
    with pytest.raises(ValidationError):
        _backup(NLW_BACKUP_RETENTION_MODE="immutable", NLW_BACKUP_FORCE_LOCAL_PRUNE=True)
    # Immutable mode WITHOUT a forced prune is fine (the writer just never prunes).
    s = _backup(NLW_BACKUP_RETENTION_MODE="immutable")
    assert s.retention_mode == "immutable"
    # Simple mode (default) permits local prune.
    assert _backup().retention_mode == "simple"


def test_restore_requires_scoped_runtime_guard_in_production() -> None:
    base = {
        "app_env": "production",
        "NLW_RESTORE_DATABASE_URL": "postgresql://nlw:pw@db/nlw",
        "NLW_RESTORE_TARGET_ID": "nlw-dr",
        "NLW_RESTORE_CONFIRM": "nlw-dr",
    }
    # No compose project in production -> the runtime guard cannot be scoped -> fail.
    with pytest.raises(ValidationError):
        RestoreSettings(**base)  # type: ignore[arg-type]
    # Disabling the guard in production -> fail closed.
    off = {**base, "NLW_RESTORE_COMPOSE_PROJECT": "p", "NLW_RESTORE_RUNTIME_GUARD": "off"}
    with pytest.raises(ValidationError):
        RestoreSettings(**off)  # type: ignore[arg-type]
    # Scoped compose guard -> ok.
    s = RestoreSettings(**base, NLW_RESTORE_COMPOSE_PROJECT="p")  # type: ignore[arg-type]
    assert s.compose_project == "p" and s.runtime_guard == "compose"


def test_sa_engine_url_forces_psycopg_v3_dialect() -> None:
    # A bare libpq URL (what pg_dump/pg_restore consume) must be routed to psycopg
    # v3 for the SQLAlchemy engine paths — SQLAlchemy would otherwise import
    # psycopg2, which we do not ship.
    assert (
        sa_engine_url("postgresql://nlw:pw@db:5432/nlw")
        == "postgresql+psycopg://nlw:pw@db:5432/nlw"
    )
    assert sa_engine_url("postgres://nlw:pw@db/nlw") == "postgresql+psycopg://nlw:pw@db/nlw"
    # An already-qualified driver URL is left untouched (no double-prefix).
    assert (
        sa_engine_url("postgresql+psycopg://nlw:pw@db/nlw") == "postgresql+psycopg://nlw:pw@db/nlw"
    )
    assert (
        sa_engine_url("postgresql+asyncpg://nlw:pw@db/nlw") == "postgresql+asyncpg://nlw:pw@db/nlw"
    )


def test_validated_work_dir_refuses_dangerous_targets(tmp_path: Path) -> None:
    for bad in ("/", str(Path.home()), str(Path.cwd())):
        with pytest.raises(ValueError):
            validated_work_dir(bad)
    good = validated_work_dir(str(tmp_path / "wd"))
    assert good.exists() and (good.stat().st_mode & 0o777) == 0o700


def test_validation_errors_never_echo_supplied_credential_values() -> None:
    """The CLI prints the validation error to the journal; a partly filled env
    file must not leak the values that WERE supplied (pydantic input echo)."""
    from pydantic import SecretStr, ValidationError

    from nlw.backup.config import BackupSettings, RestoreSettings

    with pytest.raises(ValidationError) as info:
        BackupSettings(
            app_env="production",
            RESTIC_REPOSITORY="s3:https://s3.example/b/nlw",
            RESTIC_PASSWORD=SecretStr("hunter2-repo-passphrase"),
            AWS_ACCESS_KEY_ID=SecretStr("AKIAEXAMPLEEXAMPLE"),
            AWS_SECRET_ACCESS_KEY=SecretStr(""),  # missing -> fail closed
            NLW_BACKUP_DATABASE_URL=SecretStr(""),
        )
    text = str(info.value)
    assert "fail-closed" in text
    for secret in ("hunter2-repo-passphrase", "AKIAEXAMPLEEXAMPLE", "s3.example"):
        assert secret not in text
    with pytest.raises(ValidationError) as info2:
        RestoreSettings(
            app_env="production",
            NLW_RESTORE_RUNTIME_GUARD="off",
            RESTIC_PASSWORD=SecretStr("another-passphrase-value"),
        )
    assert "another-passphrase-value" not in str(info2.value)
