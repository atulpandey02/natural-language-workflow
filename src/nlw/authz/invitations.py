"""Invitation token + email helpers (M11.5 P3A).

The raw invitation token is a high-entropy random string returned ONCE at creation
for manual sharing; the database stores only its sha256 hash. The raw token is
never logged, metered, audited, or persisted.
"""

import hashlib
import secrets

# 32 bytes -> 43-char urlsafe base64 (~256 bits). Bounded so it can never be an
# unbounded attacker-controlled blob when a hash is looked up.
_TOKEN_NBYTES = 32
MAX_TOKEN_LENGTH = 128


def new_invitation_token() -> tuple[str, str]:
    """Return ``(raw_token, token_hash)``. Only the hash is ever stored."""
    raw = secrets.token_urlsafe(_TOKEN_NBYTES)
    return raw, hash_token(raw)


def hash_token(raw_token: str) -> str:
    """sha256 hex of the raw token. Deterministic, so acceptance looks up by hash."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def normalize_email(email: str) -> str:
    """Trim + lowercase. Deliberately conservative: no provider-specific transforms
    (e.g. gmail dot/plus stripping) that could merge distinct identities."""
    return email.strip().lower()
