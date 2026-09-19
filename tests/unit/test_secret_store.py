"""SecretStore: tenant-scoped env resolution, canonical refs, non-leak in errors."""

import uuid

import pytest

from nlw.secrets.store import (
    EnvironmentSecretStore,
    InvalidSecretRefError,
    SecretNotFoundError,
    env_key_for,
    validate_secret_ref,
)

TENANT = uuid.uuid4()


def test_tenant_scoped_env_resolution() -> None:
    store = EnvironmentSecretStore({env_key_for(TENANT, "STATIC_DEMO"): "s3cr3t"})
    assert store.resolve(TENANT, "STATIC_DEMO") == "s3cr3t"


def test_identical_ref_in_different_tenants_is_not_shared() -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    store = EnvironmentSecretStore({env_key_for(a, "SHARED_NAME"): "a-value"})
    assert store.resolve(a, "SHARED_NAME") == "a-value"
    # B has no tenant-scoped secret and must never receive A's value.
    with pytest.raises(SecretNotFoundError):
        store.resolve(b, "SHARED_NAME")


def test_env_key_format() -> None:
    assert env_key_for(TENANT, "X") == f"NLW_SECRET_{TENANT.hex.upper()}_X"


def test_missing_secret_raises_without_value() -> None:
    store = EnvironmentSecretStore({})
    with pytest.raises(SecretNotFoundError) as exc:
        store.resolve(TENANT, "STATIC_DEMO")
    assert "STATIC_DEMO" in str(exc.value)  # the ref, which is not a secret


def test_empty_secret_treated_as_missing() -> None:
    store = EnvironmentSecretStore({env_key_for(TENANT, "EMPTY"): ""})
    with pytest.raises(SecretNotFoundError):
        store.resolve(TENANT, "EMPTY")


@pytest.mark.parametrize("bad", ["lower", "1STARTS_DIGIT", "HAS-DASH", "HAS SPACE", "", "A" * 65])
def test_invalid_refs_rejected(bad: str) -> None:
    with pytest.raises(InvalidSecretRefError):
        validate_secret_ref(bad)


@pytest.mark.parametrize("ok", ["A", "STATIC_DEMO", "PG_MAIN_1", "X" * 64])
def test_valid_refs_accepted(ok: str) -> None:
    assert validate_secret_ref(ok) == ok
