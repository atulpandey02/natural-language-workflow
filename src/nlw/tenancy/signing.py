"""Signed, purpose-bound, expiring database context (M11.5 P3B, ADR-024).

The application no longer asks PostgreSQL to trust bare ``app.user_id`` /
``app.tenant_id`` settings. Instead every tenant-aware transaction carries a small
set of transaction-local GUCs (``app.ctx_*``) whose contents are authenticated by
an HMAC-SHA256 tag over ONE canonical, versioned, length-prefixed message. RLS
helpers in the database recompute the tag with the purpose's key and only then
expose the claims (see migration 0016 and ``app_ctx_claims()``).

Threat model (honest): HMAC is SYMMETRIC. The key PostgreSQL verifies with is the
same signing-capable material this signer holds. What the scheme protects against
is an attacker who can run SQL as a runtime role (SQL injection, or possession of
a runtime DB credential) but does NOT hold the runtime's key file: they can set
any GUC they like, but cannot mint a valid tag. It does NOT protect against a
runtime process compromised together with its key, the key installer, the RLS
bypass/owner roles, or the superuser.

Canonical message v1 (byte-exact in Python and PostgreSQL, see golden vectors):

    "nlwctx1" || for each field in FIXED order: <octet_length> ":" <value>

fields: version, key_id, db_role, purpose, user_id, tenant_id, run_id,
        issued_at, expires_at, nonce   (absent ids encode as the empty string)

Every field is restricted to a conservative ASCII alphabet so ``octet_length``
equals the Python byte length and no delimiter ambiguity is possible. Changing any
field changes the message and therefore invalidates the tag.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import os
import re
import secrets
import stat
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

CTX_VERSION: Final = "1"
CTX_PREFIX: Final = "nlwctx1"
NONCE_BYTES: Final = 16
MAC_HEX_LEN: Final = 64
MIN_KEY_BYTES: Final = 32
MAX_KEY_ID_LEN: Final = 64
# Hard upper bound on any context lifetime the application will ever mint; the
# database enforces the same bound independently (``app_ctx_claims``).
MAX_TTL_S: Final = 600
DEFAULT_TTL_S: Final = 120

# GUC names, in canonical field order for the id/time fields. Set with
# set_config(name, value, true) so they are TRANSACTION-local.
GUC_V: Final = "app.ctx_v"
GUC_KID: Final = "app.ctx_kid"
GUC_ROLE: Final = "app.ctx_role"
GUC_PURPOSE: Final = "app.ctx_purpose"
GUC_USER: Final = "app.ctx_user"
GUC_TENANT: Final = "app.ctx_tenant"
GUC_RUN: Final = "app.ctx_run"
GUC_IAT: Final = "app.ctx_iat"
GUC_EXP: Final = "app.ctx_exp"
GUC_NONCE: Final = "app.ctx_nonce"
GUC_MAC: Final = "app.ctx_mac"
ALL_GUCS: Final = (
    GUC_V,
    GUC_KID,
    GUC_ROLE,
    GUC_PURPOSE,
    GUC_USER,
    GUC_TENANT,
    GUC_RUN,
    GUC_IAT,
    GUC_EXP,
    GUC_NONCE,
    GUC_MAC,
)

_KEY_ID_RE: Final = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_ROLE_RE: Final = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class Purpose(enum.StrEnum):
    """Runtime purposes. Each is bound to exactly one PostgreSQL login role and
    to a fixed claim shape; the database re-checks both."""

    API_IDENTITY = "api_identity"  # verified human, NO workspace: self/bootstrap only
    API_REQUEST = "api_request"  # verified human + selected workspace (active member)
    WORKER_EXECUTION = "worker_execution"  # workspace + run, no human
    SCHEDULER_RECONCILE = "scheduler_reconcile"  # cross-tenant scan/reconcile, no human


# purpose -> the ONLY PostgreSQL login role allowed to present it (mirrored in SQL).
PURPOSE_DB_ROLE: Final[dict[Purpose, str]] = {
    Purpose.API_IDENTITY: "nlw_app",
    Purpose.API_REQUEST: "nlw_app",
    Purpose.WORKER_EXECUTION: "nlw_worker",
    Purpose.SCHEDULER_RECONCILE: "nlw_scheduler",
}


class ContextSigningError(RuntimeError):
    """Signing/key configuration failure. Messages never include key material."""


class SecretBytes:
    """Opaque holder for key material: never printed, compared, or serialized."""

    __slots__ = ("_value",)

    def __init__(self, value: bytes) -> None:
        if not isinstance(value, bytes | bytearray):
            raise ContextSigningError("key material must be bytes")
        if len(value) < MIN_KEY_BYTES:
            raise ContextSigningError(f"key material must be >= {MIN_KEY_BYTES} bytes")
        self._value = bytes(value)

    def reveal(self) -> bytes:
        return self._value

    def fingerprint(self) -> str:
        """Non-secret identifier for logs/audit: sha256 of the material, truncated."""
        return hashlib.sha256(self._value).hexdigest()[:16]

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return "SecretBytes('***')"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:  # pragma: no cover - defensive
        return NotImplemented

    __hash__ = None  # type: ignore[assignment]


def canonical_message(
    *,
    key_id: str,
    db_role: str,
    purpose: str,
    user_id: str,
    tenant_id: str,
    run_id: str,
    issued_at: int,
    expires_at: int,
    nonce: str,
    version: str = CTX_VERSION,
) -> bytes:
    """The exact bytes that are HMAC'd. Mirrors ``app_ctx_canon`` in SQL."""
    fields = (
        version,
        key_id,
        db_role,
        purpose,
        user_id,
        tenant_id,
        run_id,
        str(issued_at),
        str(expires_at),
        nonce,
    )
    for f in fields:
        if not f.isascii():
            raise ContextSigningError("context fields must be ASCII")
    body = "".join(f"{len(f.encode('utf-8'))}:{f}" for f in fields)
    return (CTX_PREFIX + body).encode("utf-8")


def compute_mac(key: SecretBytes, message: bytes) -> str:
    return hmac.new(key.reveal(), message, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class SignedContext:
    """A signed context ready to be applied as transaction-local GUCs."""

    key_id: str
    db_role: str
    purpose: Purpose
    user_id: uuid.UUID | None
    tenant_id: uuid.UUID | None
    run_id: uuid.UUID | None
    issued_at: int
    expires_at: int
    nonce: str
    mac: str
    version: str = CTX_VERSION

    def as_gucs(self) -> dict[str, str]:
        """GUC name -> value, all strings, absent ids as ''. Never logged."""
        return {
            GUC_V: self.version,
            GUC_KID: self.key_id,
            GUC_ROLE: self.db_role,
            GUC_PURPOSE: str(self.purpose),
            GUC_USER: str(self.user_id) if self.user_id else "",
            GUC_TENANT: str(self.tenant_id) if self.tenant_id else "",
            GUC_RUN: str(self.run_id) if self.run_id else "",
            GUC_IAT: str(self.issued_at),
            GUC_EXP: str(self.expires_at),
            GUC_NONCE: self.nonce,
            GUC_MAC: self.mac,
        }

    def __repr__(self) -> str:
        # Never expose the tag/nonce; identifiers are fine for diagnostics.
        return (
            f"SignedContext(purpose={self.purpose!s}, key_id={self.key_id!r}, "
            f"tenant={self.tenant_id}, user={self.user_id}, run={self.run_id}, "
            f"exp={self.expires_at})"
        )


def _require_shape(purpose: Purpose, user: object, tenant: object, run: object) -> None:
    """Each purpose has a FIXED claim shape; refuse to mint anything else."""
    has = (user is not None, tenant is not None, run is not None)
    if purpose is Purpose.API_IDENTITY and has != (True, False, False):
        raise ContextSigningError("api_identity requires user only")
    if (
        purpose is Purpose.API_REQUEST
        and has[:2] != (True, True)
        or (purpose is Purpose.API_REQUEST and has[2])
    ):
        raise ContextSigningError("api_request requires user + tenant (no run)")
    if purpose is Purpose.WORKER_EXECUTION and (has[0] or not has[1]):
        raise ContextSigningError("worker_execution requires tenant (+run), never a user")
    if purpose is Purpose.SCHEDULER_RECONCILE and any(has):
        raise ContextSigningError("scheduler_reconcile carries no identifiers")


@dataclass
class ContextSigner:
    """Mints signed contexts for ONE purpose / DB role / key.

    Purpose and expected DB role are fixed at construction (never caller input);
    callers only supply the identifiers the purpose shape allows.
    """

    purpose: Purpose
    key_id: str
    key: SecretBytes
    ttl_s: int = DEFAULT_TTL_S
    db_role: str = ""
    clock: Callable[[], float] = field(default=time.time, repr=False)

    def __post_init__(self) -> None:
        if not _KEY_ID_RE.match(self.key_id):
            raise ContextSigningError("invalid key id")
        if not self.db_role:
            self.db_role = PURPOSE_DB_ROLE[self.purpose]
        if self.db_role != PURPOSE_DB_ROLE[self.purpose] or not _ROLE_RE.match(self.db_role):
            raise ContextSigningError("db role does not match purpose")
        if not (1 <= self.ttl_s <= MAX_TTL_S):
            raise ContextSigningError(f"ttl must be within 1..{MAX_TTL_S}s")

    def sign(
        self,
        *,
        user_id: uuid.UUID | None = None,
        tenant_id: uuid.UUID | None = None,
        run_id: uuid.UUID | None = None,
    ) -> SignedContext:
        _require_shape(self.purpose, user_id, tenant_id, run_id)
        iat = int(self.clock())
        exp = iat + self.ttl_s
        nonce = secrets.token_hex(NONCE_BYTES)
        msg = canonical_message(
            key_id=self.key_id,
            db_role=self.db_role,
            purpose=str(self.purpose),
            user_id=str(user_id) if user_id else "",
            tenant_id=str(tenant_id) if tenant_id else "",
            run_id=str(run_id) if run_id else "",
            issued_at=iat,
            expires_at=exp,
            nonce=nonce,
        )
        return SignedContext(
            key_id=self.key_id,
            db_role=self.db_role,
            purpose=self.purpose,
            user_id=user_id,
            tenant_id=tenant_id,
            run_id=run_id,
            issued_at=iat,
            expires_at=exp,
            nonce=nonce,
            mac=compute_mac(self.key, msg),
        )

    def __repr__(self) -> str:
        return f"ContextSigner(purpose={self.purpose!s}, key_id={self.key_id!r})"


def load_key_file(path: str | os.PathLike[str], *, strict_permissions: bool = True) -> SecretBytes:
    """Read a signing key from a mounted secret file.

    Format: 64+ hex characters (>= 32 bytes) on one line. The file must be a
    regular file; with ``strict_permissions`` it must not be group/world readable.
    Errors never echo the contents.
    """
    p = Path(path)
    try:
        st = p.stat()
    except OSError as exc:
        raise ContextSigningError(f"context key file unreadable: {p.name}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise ContextSigningError(f"context key file is not a regular file: {p.name}")
    if strict_permissions and (st.st_mode & 0o077):
        raise ContextSigningError(f"context key file is group/world accessible: {p.name}")
    raw = p.read_text(encoding="ascii", errors="strict").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64,}", raw) or len(raw) % 2:
        raise ContextSigningError(f"context key file is not >=32 bytes of hex: {p.name}")
    return SecretBytes(bytes.fromhex(raw))


def generate_test_key() -> str:
    """A fresh random key as hex. TEST/DRILL fixtures only — never production."""
    return secrets.token_hex(MIN_KEY_BYTES)
