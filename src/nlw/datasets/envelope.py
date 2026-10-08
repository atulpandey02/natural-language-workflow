"""Dataset-ingest work envelopes (ADR-031).

The API records an immutable ``dataset_processing_requests`` row under the
admin's signed context; a database trigger stamps ``requested_at`` and computes
``envelope_sha256`` over the canonical message below. The queue message carries
exactly those fields. The ingest service trusts nothing in it until:

1. the message parses strictly (``parse``) and its digest recomputes
   (``TamperedEnvelope`` otherwise) — no database access;
2. it is not older than the maximum age (``StaleEnvelope``);
3. the request row, read through the ingest role's RLS for exactly that
   workspace and version, exists and matches every field
   (``nlw.ingest_service.processing``).

Integrity anchor (stated precisely): the immutable, RLS-authored request row,
not a MAC by a key shared with the API. Whoever can inject queue messages can
only point the service at a request an admin really made.

Canonical message v1 (byte-identical to migration 0026):

    "nlwingest1" || for each field in FIXED order: <octet_length> ":" <value>

fields: version, request_id, tenant_id, dataset_id, version_id, content_sha256,
        requested_at_us (integer microseconds since the epoch)
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Final, Protocol

# Queue transport (Redis/Dramatiq, transport only). The API enqueues through its
# own broker with these names and never imports the ingest runtime
# (``nlw.ingest_service.actors``), which consumes ONLY this queue.
QUEUE_NAME: Final = "dataset_ingest"
ACTOR_NAME: Final = "process_dataset_version"

ENVELOPE_VERSION: Final = "1"
ENVELOPE_PREFIX: Final = "nlwingest1"
# A request older than this is not processed from a queue message; the admin
# can record a new request for a version still waiting (QUARANTINED/PROFILING).
MAX_ENVELOPE_AGE_S: Final = 24 * 3600
# Messages from the future are refused beyond this skew (database clock vs ours).
MAX_CLOCK_SKEW_S: Final = 60
MAX_ENVELOPE_BYTES: Final = 1024

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = (
    "v",
    "request_id",
    "tenant_id",
    "dataset_id",
    "version_id",
    "content_sha256",
    "requested_at_us",
    "envelope_sha256",
)


class EnvelopeError(ValueError):
    """The envelope must not be processed. ``code`` is stable and content-free."""

    code = "ENVELOPE_INVALID"


class MalformedEnvelope(EnvelopeError):
    code = "ENVELOPE_MALFORMED"


class TamperedEnvelope(EnvelopeError):
    code = "ENVELOPE_TAMPERED"


class StaleEnvelope(EnvelopeError):
    code = "ENVELOPE_STALE"


def canonical_message(
    *,
    request_id: uuid.UUID,
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    content_sha256: str,
    requested_at_us: int,
) -> bytes:
    fields = (
        ENVELOPE_VERSION,
        str(request_id),
        str(tenant_id),
        str(dataset_id),
        str(version_id),
        content_sha256,
        str(requested_at_us),
    )
    return (ENVELOPE_PREFIX + "".join(f"{len(f.encode())}:{f}" for f in fields)).encode()


def envelope_digest(**fields: Any) -> str:
    return hashlib.sha256(canonical_message(**fields)).hexdigest()


@dataclass(frozen=True)
class WorkEnvelope:
    request_id: uuid.UUID
    tenant_id: uuid.UUID
    dataset_id: uuid.UUID
    version_id: uuid.UUID
    content_sha256: str
    requested_at_us: int
    envelope_sha256: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "v": ENVELOPE_VERSION,
                "request_id": str(self.request_id),
                "tenant_id": str(self.tenant_id),
                "dataset_id": str(self.dataset_id),
                "version_id": str(self.version_id),
                "content_sha256": self.content_sha256,
                "requested_at_us": self.requested_at_us,
                "envelope_sha256": self.envelope_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def recomputed_digest(self) -> str:
        return envelope_digest(
            request_id=self.request_id,
            tenant_id=self.tenant_id,
            dataset_id=self.dataset_id,
            version_id=self.version_id,
            content_sha256=self.content_sha256,
            requested_at_us=self.requested_at_us,
        )

    def ids(self) -> dict[str, str]:
        """Identifiers for logs (never content, keys or names)."""
        return {
            "request_id": str(self.request_id),
            "tenant_id": str(self.tenant_id),
            "dataset_id": str(self.dataset_id),
            "version_id": str(self.version_id),
        }


def _uuid(raw: object) -> uuid.UUID:
    if not isinstance(raw, str):
        raise MalformedEnvelope("identifier must be a string")
    try:
        value = uuid.UUID(raw)
    except ValueError as exc:
        raise MalformedEnvelope("identifier is not a UUID") from exc
    if str(value) != raw:  # canonical lower-case hyphenated form only
        raise MalformedEnvelope("identifier is not canonical")
    return value


def parse(message: str | bytes) -> WorkEnvelope:
    """Strict: exact field set, canonical formats, recomputed digest."""
    raw = message.encode() if isinstance(message, str) else message
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise MalformedEnvelope("envelope too large")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MalformedEnvelope("envelope is not JSON") from exc
    if not isinstance(doc, dict) or set(doc) != set(_FIELDS):
        raise MalformedEnvelope("envelope fields")
    if doc["v"] != ENVELOPE_VERSION:
        raise MalformedEnvelope("envelope version")
    sha, digest, at = doc["content_sha256"], doc["envelope_sha256"], doc["requested_at_us"]
    if not isinstance(sha, str) or not _SHA_RE.match(sha):
        raise MalformedEnvelope("content digest")
    if not isinstance(digest, str) or not _SHA_RE.match(digest):
        raise MalformedEnvelope("envelope digest")
    if not isinstance(at, int) or isinstance(at, bool) or not 0 < at < 10**17:
        raise MalformedEnvelope("requested_at_us")
    env = WorkEnvelope(
        request_id=_uuid(doc["request_id"]),
        tenant_id=_uuid(doc["tenant_id"]),
        dataset_id=_uuid(doc["dataset_id"]),
        version_id=_uuid(doc["version_id"]),
        content_sha256=sha,
        requested_at_us=at,
        envelope_sha256=digest,
    )
    if env.recomputed_digest() != digest:
        raise TamperedEnvelope("envelope digest does not match its fields")
    return env


def check_fresh(env: WorkEnvelope, *, now_us: int, max_age_s: int = MAX_ENVELOPE_AGE_S) -> None:
    if env.requested_at_us > now_us + MAX_CLOCK_SKEW_S * 1_000_000:
        raise StaleEnvelope("envelope is from the future")
    if now_us - env.requested_at_us > max_age_s * 1_000_000:
        raise StaleEnvelope("envelope is older than the maximum age")


class _Broker(Protocol):
    def enqueue(self, message: Any, *, delay: int | None = None) -> Any: ...


def enqueue_envelope(broker: _Broker, env: WorkEnvelope) -> None:
    """Send one work envelope to the ingest queue AFTER its request committed.
    Transport only: the consumer re-verifies it against the database."""
    import dramatiq

    broker.enqueue(
        dramatiq.Message(
            queue_name=QUEUE_NAME,
            actor_name=ACTOR_NAME,
            args=(env.to_json(),),
            kwargs={},
            options={},
        )
    )
