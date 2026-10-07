"""Pure, deterministic dataset lifecycle rules (ADR-029).

The database enforces the same rules for every role (migrations
``0024_dataset_lifecycle`` and ``0025_dataset_ingestion``); this module lets the
service refuse an invalid request before touching the database and gives tests
one source of truth. Unit tests assert these tables equal the migrations'.
"""

from __future__ import annotations

import enum
import re
import unicodedata

NAME_MAX_CHARS = 100
DESCRIPTION_MAX_CHARS = 500
FILENAME_MAX_CHARS = 255
MAX_DECLARED_SIZE_BYTES = 25_000_000  # the nlw.ingest profiler's byte cap
MEDIA_TYPES = frozenset({"text/csv"})


class DatasetStatus(enum.StrEnum):
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"
    DELETED = "DELETED"


class VersionStatus(enum.StrEnum):
    QUARANTINED = "QUARANTINED"
    PROFILING = "PROFILING"
    PROFILED = "PROFILED"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    REJECTED = "REJECTED"
    DELETING = "DELETING"
    DELETED = "DELETED"


DATASET_TRANSITIONS: dict[DatasetStatus, frozenset[DatasetStatus]] = {
    DatasetStatus.ACTIVE: frozenset({DatasetStatus.DELETING}),
    DatasetStatus.DELETING: frozenset({DatasetStatus.DELETED}),
    DatasetStatus.DELETED: frozenset(),
}

VERSION_TRANSITIONS: dict[VersionStatus, frozenset[VersionStatus]] = {
    VersionStatus.QUARANTINED: frozenset(
        {VersionStatus.PROFILING, VersionStatus.REJECTED, VersionStatus.DELETING}
    ),
    VersionStatus.PROFILING: frozenset(
        {VersionStatus.PROFILED, VersionStatus.REJECTED, VersionStatus.DELETING}
    ),
    VersionStatus.PROFILED: frozenset(
        {VersionStatus.ACTIVE, VersionStatus.REJECTED, VersionStatus.DELETING}
    ),
    VersionStatus.ACTIVE: frozenset({VersionStatus.SUPERSEDED, VersionStatus.DELETING}),
    VersionStatus.SUPERSEDED: frozenset({VersionStatus.DELETING}),
    VersionStatus.REJECTED: frozenset({VersionStatus.DELETING}),
    VersionStatus.DELETING: frozenset({VersionStatus.DELETED}),
    VersionStatus.DELETED: frozenset(),
}

# States from which a deletion request moves a version to DELETING.
DELETABLE_VERSION_STATES = frozenset(
    s for s, targets in VERSION_TRANSITIONS.items() if VersionStatus.DELETING in targets
)


class RejectionCode(enum.StrEnum):
    """The nlw.ingest reject codes plus a human review rejection."""

    FILE_TYPE = "FILE_TYPE"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    FILE_EMPTY = "FILE_EMPTY"
    CONTENT_BINARY = "CONTENT_BINARY"
    ENCODING_UNSUPPORTED = "ENCODING_UNSUPPORTED"
    TOO_MANY_ROWS = "TOO_MANY_ROWS"
    TOO_MANY_COLUMNS = "TOO_MANY_COLUMNS"
    FIELD_TOO_LARGE = "FIELD_TOO_LARGE"
    PARSE_TIMEOUT = "PARSE_TIMEOUT"
    PARSE_ERROR = "PARSE_ERROR"
    REVIEW_REJECTED = "REVIEW_REJECTED"
    # 0025: strict pilot CSV policy (nlw.ingest.strict) and processing outcomes.
    HEADER_INVALID = "HEADER_INVALID"
    HEADER_DUPLICATE = "HEADER_DUPLICATE"
    NO_DATA_ROWS = "NO_DATA_ROWS"
    ROW_WIDTH_MISMATCH = "ROW_WIDTH_MISMATCH"
    CONTENT_MISMATCH = "CONTENT_MISMATCH"
    PROCESSING_FAILED = "PROCESSING_FAILED"


class EventType(enum.StrEnum):
    DATASET_CREATED = "DATASET_CREATED"
    DATASET_DELETION_REQUESTED = "DATASET_DELETION_REQUESTED"
    DATASET_TOMBSTONED = "DATASET_TOMBSTONED"
    VERSION_CREATED = "VERSION_CREATED"
    VERSION_PROFILING_STARTED = "VERSION_PROFILING_STARTED"
    VERSION_PROFILED = "VERSION_PROFILED"
    VERSION_ACTIVATED = "VERSION_ACTIVATED"
    VERSION_SUPERSEDED = "VERSION_SUPERSEDED"
    VERSION_REJECTED = "VERSION_REJECTED"
    VERSION_DELETION_REQUESTED = "VERSION_DELETION_REQUESTED"
    VERSION_TOMBSTONED = "VERSION_TOMBSTONED"
    # 0025: operator evidence that a DELETING version's stored objects were
    # physically deleted and verified absent (DELETING -> DELETING; not a
    # transition). Runtime roles can never write it.
    VERSION_OBJECT_PURGED = "VERSION_OBJECT_PURGED"


class ReasonCode(enum.StrEnum):
    USER_REQUEST = "USER_REQUEST"
    DATASET_DELETION = "DATASET_DELETION"
    OPERATOR_TOMBSTONE = "OPERATOR_TOMBSTONE"
    OPERATOR_PURGE = "OPERATOR_PURGE"


class ActorKind(enum.StrEnum):
    USER = "user"
    SERVICE = "service"
    OPERATOR = "operator"


# The event recorded for each version transition (target state).
VERSION_EVENT_FOR: dict[VersionStatus, EventType] = {
    VersionStatus.PROFILING: EventType.VERSION_PROFILING_STARTED,
    VersionStatus.PROFILED: EventType.VERSION_PROFILED,
    VersionStatus.ACTIVE: EventType.VERSION_ACTIVATED,
    VersionStatus.SUPERSEDED: EventType.VERSION_SUPERSEDED,
    VersionStatus.REJECTED: EventType.VERSION_REJECTED,
    VersionStatus.DELETING: EventType.VERSION_DELETION_REQUESTED,
    VersionStatus.DELETED: EventType.VERSION_TOMBSTONED,
}


class MetadataError(ValueError):
    """A metadata value is outside its contract. ``code`` is a stable slug."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def version_transition_allowed(src: VersionStatus, dst: VersionStatus) -> bool:
    return dst in VERSION_TRANSITIONS[src]


def dataset_transition_allowed(src: DatasetStatus, dst: DatasetStatus) -> bool:
    return dst in DATASET_TRANSITIONS[src]


def _has_unsafe_chars(text: str) -> bool:
    """Control (Cc) and format (Cf: zero-width, bidi overrides) characters."""
    return any(unicodedata.category(ch) in ("Cc", "Cf") for ch in text)


_WS = re.compile(r"\s+")


def normalize_name(raw: str) -> tuple[str, str]:
    """Return (display_name, uniqueness_key). NFKC, trimmed, internal whitespace
    collapsed to one space; 1..100 characters; no control or format characters.
    The uniqueness key is the case-folded display name."""
    if not isinstance(raw, str):
        raise MetadataError("DATASET_NAME_INVALID", "name must be text")
    if _has_unsafe_chars(raw.replace("\t", " ").replace("\n", " ").replace("\r", " ")):
        raise MetadataError("DATASET_NAME_INVALID", "name contains unsupported characters")
    name = _WS.sub(" ", unicodedata.normalize("NFKC", raw)).strip()
    if not name or len(name) > NAME_MAX_CHARS:
        raise MetadataError(
            "DATASET_NAME_INVALID", f"name must be 1 to {NAME_MAX_CHARS} characters"
        )
    if _has_unsafe_chars(name):
        raise MetadataError("DATASET_NAME_INVALID", "name contains unsupported characters")
    return name, name.casefold()


def normalize_description(raw: str | None) -> str | None:
    """Optional; NFKC, trimmed; at most 500 characters; tab/newline allowed,
    no other control or format characters. Empty becomes ``None``."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise MetadataError("DATASET_DESCRIPTION_INVALID", "description must be text")
    text = unicodedata.normalize("NFKC", raw).strip()
    if not text:
        return None
    if len(text) > DESCRIPTION_MAX_CHARS:
        raise MetadataError(
            "DATASET_DESCRIPTION_INVALID",
            f"description must be at most {DESCRIPTION_MAX_CHARS} characters",
        )
    if _has_unsafe_chars(text.replace("\t", "").replace("\n", "").replace("\r", "")):
        raise MetadataError(
            "DATASET_DESCRIPTION_INVALID", "description contains unsupported characters"
        )
    return text


def sanitize_filename(raw: str) -> str:
    """A bounded base name, never a path. NFC, trimmed; rejects path separators,
    traversal names and control/format characters (no silent stripping)."""
    if not isinstance(raw, str):
        raise MetadataError("DATASET_FILENAME_INVALID", "filename must be text")
    name = unicodedata.normalize("NFC", raw).strip()
    if not name or len(name) > FILENAME_MAX_CHARS:
        raise MetadataError(
            "DATASET_FILENAME_INVALID", f"filename must be 1 to {FILENAME_MAX_CHARS} characters"
        )
    if "/" in name or "\\" in name or name in (".", "..") or _has_unsafe_chars(name):
        raise MetadataError("DATASET_FILENAME_INVALID", "filename must be a plain file name")
    return name


def validate_declared_size(size: object) -> int:
    """A finite, positive integer no larger than the profiler cap."""
    if isinstance(size, bool) or not isinstance(size, int):
        raise MetadataError("DATASET_SIZE_INVALID", "declared size must be an integer")
    if not 1 <= size <= MAX_DECLARED_SIZE_BYTES:
        raise MetadataError(
            "DATASET_SIZE_INVALID", f"declared size must be 1 to {MAX_DECLARED_SIZE_BYTES} bytes"
        )
    return size


def validate_media_type(media_type: str) -> str:
    if media_type not in MEDIA_TYPES:
        raise MetadataError("DATASET_MEDIA_TYPE_UNSUPPORTED", "only text/csv is supported")
    return media_type


_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


def validate_idempotency_key(value: str) -> str:
    """An opaque client retry key: 16-128 of ``[A-Za-z0-9_-]`` (the 0025 CHECK)."""
    if not isinstance(value, str) or not _IDEMPOTENCY_KEY.match(value):
        raise MetadataError("IDEMPOTENCY_KEY_INVALID", "invalid idempotency key")
    return value
