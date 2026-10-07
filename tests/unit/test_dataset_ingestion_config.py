"""Phase 2B configuration gates (ADR-030): bounded limits, development-only
local storage and fake deletion log, no sharing of the backup repository, and
the unchanged refusal of the dataset API in staging and production."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from nlw.core.config import Settings
from nlw.ingest.strict import (
    CEILING_BYTES,
    CEILING_COLUMNS,
    CEILING_FIELD_CHARS,
    CEILING_ROWS,
    StrictLimits,
)
from nlw.storage.factory import dataset_store


def _settings(**kw: Any) -> Settings:
    return Settings(_env_file=None, **kw)  # type: ignore[call-arg]


def test_defaults_are_the_documented_pilot_limits_and_everything_is_off() -> None:
    s = _settings()
    assert (s.datasets_api_enabled, s.dataset_storage_backend, s.dataset_deletion_log) == (
        False,
        "disabled",
        "none",
    )
    assert (
        s.dataset_max_upload_bytes,
        s.dataset_max_rows,
        s.dataset_max_columns,
        s.dataset_max_field_chars,
        s.dataset_profile_timeout_s,
    ) == (25_000_000, 250_000, 200, 8_192, 60)
    assert dataset_store(s) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("dataset_max_upload_bytes", CEILING_BYTES + 1),
        ("dataset_max_upload_bytes", 0),
        ("dataset_max_rows", CEILING_ROWS + 1),
        ("dataset_max_columns", CEILING_COLUMNS + 1),
        ("dataset_max_field_chars", CEILING_FIELD_CHARS + 1),
        ("dataset_profile_timeout_s", 301),
        ("dataset_profile_memory_mb", 4096),
        ("dataset_profile_memory_mb", 16),
    ],
)
def test_limits_cannot_exceed_their_ceilings(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        _settings(**{field: value})


def test_strict_limits_refuse_unbounded_values_directly() -> None:
    for kw in ({"max_rows": 0}, {"max_bytes": CEILING_BYTES + 1}, {"timeout_s": 1e9}):
        with pytest.raises(ValueError):
            StrictLimits(**kw)


@pytest.mark.parametrize("env", ["staging", "production"])
def test_local_storage_and_fake_deletion_log_are_refused_when_deployed(
    env: str, tmp_path: Path
) -> None:
    with pytest.raises(ValidationError, match="local dataset storage"):
        _settings(app_env=env, dataset_storage_backend="local", dataset_storage_root=str(tmp_path))
    with pytest.raises(ValidationError, match="fake"):
        _settings(
            app_env=env, dataset_deletion_log="local", dataset_deletion_log_path=str(tmp_path)
        )
    with pytest.raises(ValidationError, match="DATASETS_API_ENABLED"):
        _settings(app_env=env, datasets_api_enabled=True)


def test_local_storage_needs_an_absolute_root(tmp_path: Path) -> None:
    for root in (None, "relative/datasets"):
        with pytest.raises(ValidationError, match="absolute"):
            _settings(dataset_storage_backend="local", dataset_storage_root=root)
    s = _settings(dataset_storage_backend="local", dataset_storage_root=str(tmp_path))
    store = dataset_store(s)
    assert store is not None and store.root == (tmp_path / "local").resolve()
    assert (store.root.stat().st_mode & 0o777) == 0o700


@pytest.mark.parametrize(
    "repo,root",
    [
        ("{t}/backup", "{t}/backup"),
        ("{t}/backup", "{t}/backup/datasets"),
        ("local:{t}/backup", "{t}/backup/x"),
        ("{t}/backup/inner", "{t}/backup"),
    ],
)
def test_dataset_storage_never_shares_the_backup_repository(
    tmp_path: Path, repo: str, root: str
) -> None:
    with pytest.raises(ValidationError, match="backup repository"):
        _settings(
            dataset_storage_backend="local",
            dataset_storage_root=root.format(t=tmp_path),
            RESTIC_REPOSITORY=repo.format(t=tmp_path),
        )


def test_a_remote_backup_repository_does_not_block_local_development(tmp_path: Path) -> None:
    s = _settings(
        dataset_storage_backend="local",
        dataset_storage_root=str(tmp_path / "datasets"),
        RESTIC_REPOSITORY="s3:https://s3.example.invalid/bucket/nlw",
    )
    assert s.dataset_storage_backend == "local"
