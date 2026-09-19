"""Secret resolution.

DB stores only a ``secret_ref`` (a canonical name), never a secret value. The
SecretStore resolves a ref to a value at execution time — in the worker only.
Errors and reprs never include the resolved value; a ref is not a secret.
"""

import os
import re
from collections.abc import Mapping
from typing import Protocol

# Canonical secret reference: STATIC_DEMO -> env NLW_SECRET_STATIC_DEMO
SECRET_REF_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_ENV_PREFIX = "NLW_SECRET_"


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
    def resolve(self, secret_ref: str) -> str: ...


class EnvironmentSecretStore:
    """Dev/self-hosted store: ``secret_ref`` -> env ``NLW_SECRET_<ref>``."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ if environ is not None else os.environ

    def resolve(self, secret_ref: str) -> str:
        validate_secret_ref(secret_ref)
        value = self._environ.get(f"{_ENV_PREFIX}{secret_ref}")
        if not value:
            raise SecretNotFoundError(f"no secret for ref: {secret_ref}")
        return value


def build_secret_store() -> SecretStore:
    """Construct the configured SecretStore (env-backed for dev/self-hosted)."""
    return EnvironmentSecretStore()
