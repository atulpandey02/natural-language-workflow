"""Secret resolution.

DB stores only a ``secret_ref`` (a canonical name), never a secret value.
Resolution is **tenant-scoped**: a ref is a name *within a tenant's namespace*,
so identical aliases across tenants never identify the same credential. The
SecretStore resolves (tenant_id, ref) -> value at execution time, in the worker
only, using the authoritative tenant from the execution context. Errors and
reprs never include the resolved value; a ref is not a secret.
"""

import os
import re
import uuid
from collections.abc import Mapping
from typing import Protocol

# Canonical secret reference (per-tenant namespace).
SECRET_REF_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_ENV_PREFIX = "NLW_SECRET_"


def env_key_for(tenant_id: uuid.UUID, secret_ref: str) -> str:
    """Tenant-scoped env var name: NLW_SECRET_<TENANT_UUID_HEX>_<SECRET_REF>."""
    return f"{_ENV_PREFIX}{tenant_id.hex.upper()}_{secret_ref}"


class SecretError(Exception):
    """Base for secret resolution failures (message carries the ref, never the value)."""


class InvalidSecretRefError(SecretError):
    """The secret_ref is not in canonical form."""


class SecretNotFoundError(SecretError):
    """No secret is configured for the given ref."""


def validate_secret_ref(secret_ref: str) -> str:
    if not SECRET_REF_PATTERN.match(secret_ref):
        raise InvalidSecretRefError(f"invalid secret_ref format: {secret_ref!r}")
    return secret_ref


class SecretStore(Protocol):
    def resolve(self, tenant_id: uuid.UUID, secret_ref: str) -> str: ...


class EnvironmentSecretStore:
    """Dev/self-hosted store: (tenant, ref) -> env NLW_SECRET_<TENANT_HEX>_<ref>."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ if environ is not None else os.environ

    def resolve(self, tenant_id: uuid.UUID, secret_ref: str) -> str:
        validate_secret_ref(secret_ref)
        value = self._environ.get(env_key_for(tenant_id, secret_ref))
        if not value:
            # Message carries only the ref (not the value, not another tenant's).
            raise SecretNotFoundError(f"no secret for ref: {secret_ref}")
        return value


def build_secret_store() -> SecretStore:
    """Construct the configured SecretStore (env-backed for dev/self-hosted)."""
    return EnvironmentSecretStore()
