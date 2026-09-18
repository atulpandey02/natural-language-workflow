"""Authentication provider abstraction.

Authentication answers *identity only* — never tenant or role. The rest of the
system depends on this small interface, not on any specific provider, so the
provider can be swapped (e.g. self-hosted GoTrue, a different IdP) without
touching call sites.
"""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class AuthedIdentity:
    """The verified identity carried by a token. V1 is email-authenticated."""

    sub: str
    email: str


class InvalidTokenError(Exception):
    """Raised when a token cannot be verified. Mapped to HTTP 401 at the edge."""


class AuthProvider(Protocol):
    """Verifies a raw bearer token and returns the authenticated identity."""

    def verify_token(self, raw: str) -> AuthedIdentity: ...
