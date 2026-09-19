"""SecretStore: env resolution, canonical refs, non-leak in errors."""

import pytest

from nlw.secrets.store import (
    EnvironmentSecretStore,
    InvalidSecretRefError,
    SecretNotFoundError,
    validate_secret_ref,
)


def test_env_resolution() -> None:
    store = EnvironmentSecretStore({"NLW_SECRET_STATIC_DEMO": "s3cr3t"})
    assert store.resolve("STATIC_DEMO") == "s3cr3t"


def test_missing_secret_raises_without_value() -> None:
    store = EnvironmentSecretStore({})
    with pytest.raises(SecretNotFoundError) as exc:
        store.resolve("STATIC_DEMO")
    assert "STATIC_DEMO" in str(exc.value)  # the ref, which is not a secret


def test_empty_secret_treated_as_missing() -> None:
    store = EnvironmentSecretStore({"NLW_SECRET_EMPTY": ""})
    with pytest.raises(SecretNotFoundError):
        store.resolve("EMPTY")


@pytest.mark.parametrize("bad", ["lower", "1STARTS_DIGIT", "HAS-DASH", "HAS SPACE", "", "A" * 65])
def test_invalid_refs_rejected(bad: str) -> None:
    with pytest.raises(InvalidSecretRefError):
        validate_secret_ref(bad)


@pytest.mark.parametrize("ok", ["A", "STATIC_DEMO", "PG_MAIN_1", "X" * 64])
def test_valid_refs_accepted(ok: str) -> None:
    assert validate_secret_ref(ok) == ok
