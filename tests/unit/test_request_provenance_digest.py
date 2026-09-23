"""Unit coverage for the request→plan provenance digest and its verification.

The digest is only meaningful if something re-derives and compares it. These
tests pin the encoding (UTF-8, over the exact persisted bytes) and the fail-closed
verification semantics, and prove the error never carries the request text.
"""

import hashlib

import pytest

from nlw.planner.provenance import (
    ProvenanceIntegrityError,
    compute_request_digest,
    verify_request_provenance,
)


def test_digest_is_sha256_over_exact_utf8_bytes() -> None:
    # A multibyte request: the digest must cover the UTF-8 encoding, byte for byte.
    text = "send a résumé to 山田 → done ✅"
    assert compute_request_digest(text) == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_verify_passes_when_digest_matches() -> None:
    text = "original request"
    verify_request_provenance(text, compute_request_digest(text))  # no raise


def test_verify_detects_mutated_request_without_updated_digest() -> None:
    original = "original request"
    digest = compute_request_digest(original)
    # The request was mutated out of band but the stored digest was not updated.
    with pytest.raises(ProvenanceIntegrityError):
        verify_request_provenance("tampered request", digest, proposal_id="p1")


def test_verify_detects_mutated_digest_without_updated_request() -> None:
    text = "original request"
    with pytest.raises(ProvenanceIntegrityError):
        verify_request_provenance(text, compute_request_digest("something else"))


def test_verify_rejects_partial_provenance() -> None:
    with pytest.raises(ProvenanceIntegrityError):
        verify_request_provenance("has text", None)
    with pytest.raises(ProvenanceIntegrityError):
        verify_request_provenance(None, "has digest")


def test_verify_allows_legacy_row_with_neither_field() -> None:
    verify_request_provenance(None, None)  # historical row: only prompt_len was stored


def test_integrity_error_never_contains_request_text() -> None:
    secret = "sk-live-DEADBEEF-super-secret-request-body"
    digest = compute_request_digest("original")
    with pytest.raises(ProvenanceIntegrityError) as ei:
        verify_request_provenance(secret, digest, proposal_id="p-123")
    assert secret not in str(ei.value)
