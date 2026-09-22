"""Build the process's ``ContextSigner`` from settings (M11.5 P3B).

The key is read from a mounted secret FILE (``NLW_CTX_KEY_FILE``) selected by
``NLW_CTX_KEY_ID``. Purpose and expected DB role are fixed by the CODE PATH that
asks for a signer (API / worker / scheduler) — never by configuration, headers, or
request bodies. Group/world-readable key files are refused in staging/production.
"""

from nlw.core.config import Settings
from nlw.tenancy.signing import (
    ContextSigner,
    ContextSigningError,
    Purpose,
    SecretBytes,
    load_key_file,
)


def build_signer(settings: Settings, purpose: Purpose) -> ContextSigner:
    """Fail closed: a missing/invalid key raises ``ContextSigningError``."""
    if not settings.ctx_key_id or not settings.ctx_key_file:
        raise ContextSigningError(
            "signed database context is not configured (NLW_CTX_KEY_ID / NLW_CTX_KEY_FILE)"
        )
    strict = settings.app_env in ("staging", "production")
    key = load_key_file(settings.ctx_key_file, strict_permissions=strict)
    return ContextSigner(
        purpose=purpose, key_id=settings.ctx_key_id, key=key, ttl_s=settings.ctx_ttl_s
    )


_PROCESS_SIGNERS: dict[Purpose, ContextSigner] = {}


def set_process_signer(signer: ContextSigner) -> None:
    """Register the ONE signer this process uses for ``signer.purpose`` (worker /
    scheduler entrypoints, and the test fixture). Not tenant state: a signer holds
    no identifiers, so a process-wide registry cannot leak context across jobs."""
    _PROCESS_SIGNERS[signer.purpose] = signer


def process_signer(purpose: Purpose) -> ContextSigner:
    """Fail closed: no configured signer for ``purpose`` -> no signed context ->
    every tenant query is denied by RLS, and we say so explicitly here."""
    try:
        return _PROCESS_SIGNERS[purpose]
    except KeyError as exc:
        raise ContextSigningError(f"no signer configured for {purpose}") from exc


def clear_process_signers() -> None:
    _PROCESS_SIGNERS.clear()


def signer_from_material(
    purpose: Purpose, key_id: str, key_hex: str, ttl_s: int = 120
) -> ContextSigner:
    """Construct a signer from in-memory hex material (tests / drills / smokes)."""
    return ContextSigner(
        purpose=purpose, key_id=key_id, key=SecretBytes(bytes.fromhex(key_hex)), ttl_s=ttl_s
    )
