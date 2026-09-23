"""Request→plan provenance digest: the single source of the persisted encoding
plus the validation consumer that makes the stored ``request_sha256`` meaningful.

The digest binds the durable natural-language request text to its plan proposal
(migration 0017). Storing a digest is only security theater unless something
re-derives it and compares: this module is that consumer. ``compute_request_digest``
is used on the write path so the digest always covers the *exact bytes persisted*
(UTF-8), and ``verify_request_provenance`` is called on every read that exposes
``request_text`` so an out-of-band mutation of the stored request (e.g. a direct
owner/superuser ``UPDATE`` that column privileges do not stop) is DETECTED rather
than silently served.

Runtime roles cannot reach this path at all: ``nlw_app`` holds only
``UPDATE(workflow_version_id, updated_at)`` on ``plan_proposals`` (migration 0007),
so it can rewrite neither ``request_text`` nor ``request_sha256`` to a consistent
tampered pair. This validation defends against the residual case a privilege check
does not cover — a mutation performed with elevated rights.

Never place ``request_text`` in an exception message, log field, metric label, or
trace: a mismatch is reported by proposal identity only.
"""

from __future__ import annotations

import hashlib
import hmac


class ProvenanceIntegrityError(Exception):
    """The stored request text and its digest disagree, or exactly one is present.

    Carries only non-sensitive identifiers — never the request text itself.
    """


def compute_request_digest(request_text: str) -> str:
    """The sha256 hex digest over the exact UTF-8 bytes persisted for the request.

    This is the ONE place the persisted encoding is defined; the write path and the
    verification path both go through it so they can never drift.
    """
    return hashlib.sha256(request_text.encode("utf-8")).hexdigest()


def verify_request_provenance(
    request_text: str | None,
    request_sha256: str | None,
    *,
    proposal_id: object | None = None,
) -> None:
    """Fail closed unless the stored digest matches the stored request text.

    - both ``None``  -> OK: a historical row that intentionally stored only
      ``prompt_len`` (the 0017 columns are nullable for backfill).
    - both present   -> the digest MUST equal ``compute_request_digest(request_text)``
      (constant-time compare).
    - exactly one present -> inconsistent persistence -> integrity error.

    Raises ``ProvenanceIntegrityError`` (no request text in the message) on any
    mismatch or inconsistency; returns ``None`` when the provenance is intact.
    """
    if request_text is None and request_sha256 is None:
        return
    if request_text is None or request_sha256 is None:
        raise ProvenanceIntegrityError(
            f"plan proposal {proposal_id!r}: request provenance is partially stored "
            "(exactly one of request_text/request_sha256 is present)"
        )
    expected = compute_request_digest(request_text)
    # Constant-time compare of two hex digests (defensive; not secret material).
    if not hmac.compare_digest(expected, request_sha256):
        raise ProvenanceIntegrityError(
            f"plan proposal {proposal_id!r}: stored request digest does not match the "
            "stored request text (out-of-band mutation detected)"
        )
