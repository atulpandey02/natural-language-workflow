"""Semantic confirmation contract ``semantics-1`` (ADR-030): pure and deterministic.

An admin confirms, per profiled column, a short business label, a semantic type
and an analytical role from CLOSED vocabularies, and whether the column may be
used for future analysis. Nothing here is executable: there is no expression,
formula, SQL or free-form instruction, and labels are inert display text (never
sent to a model in this phase; no planner integration exists).

``validate_mapping`` checks a mapping against the version's ``profile-2``:
exactly the profiled columns, each once, in position order, with a semantic type
and role compatible with the inferred type, and the hard rules for columns that
carry sensitivity indicators.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

SEMANTICS_CONTRACT: Literal["semantics-1"] = "semantics-1"
LABEL_MAX_CHARS = 80
DESCRIPTION_MAX_CHARS = 200

SemanticType = Literal[
    "category",
    "text",
    "count",
    "amount",
    "currency",
    "percentage",
    "ratio",
    "date",
    "timestamp",
    "boolean",
    "identifier",
    "contact",
]
Role = Literal["dimension", "measure", "identifier", "timestamp", "attribute"]

# Which semantic types fit each inferred primitive type.
COMPATIBLE_TYPES: dict[str, frozenset[str]] = {
    "integer": frozenset(
        {"count", "amount", "currency", "percentage", "ratio", "identifier", "category"}
    ),
    "decimal": frozenset({"amount", "currency", "percentage", "ratio"}),
    "date": frozenset({"date"}),
    "timestamp": frozenset({"timestamp"}),
    "boolean": frozenset({"boolean", "category"}),
    "string": frozenset({"category", "text", "identifier", "contact"}),
}
# Which roles fit each semantic type.
COMPATIBLE_ROLES: dict[str, frozenset[str]] = {
    "category": frozenset({"dimension", "attribute"}),
    "text": frozenset({"attribute"}),
    "count": frozenset({"measure", "attribute"}),
    "amount": frozenset({"measure", "attribute"}),
    "currency": frozenset({"measure", "attribute"}),
    "percentage": frozenset({"measure", "attribute"}),
    "ratio": frozenset({"measure", "attribute"}),
    "date": frozenset({"timestamp", "dimension", "attribute"}),
    "timestamp": frozenset({"timestamp", "dimension", "attribute"}),
    "boolean": frozenset({"dimension", "attribute"}),
    "identifier": frozenset({"identifier"}),
    "contact": frozenset({"identifier", "attribute"}),
}
# Indicators that forbid analysis outright (never downgradable by a label).
HARD_EXCLUDE = frozenset({"possible_national_id", "possible_payment_card"})
# Indicators whose column may be analysed only as an identifier.
IDENTIFIER_ONLY = frozenset({"possible_email", "possible_phone"})
_FORMULA = ("=", "+", "-", "@")


class SemanticMappingError(ValueError):
    """The mapping is invalid. ``code`` is stable; the message is safe to show."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _clean_text(value: str, max_chars: int) -> str:
    # Checked on the RAW input, before whitespace is collapsed: \s also matches
    # C1 controls such as U+0085, which must be refused, never normalized away.
    if any(unicodedata.category(c).startswith("C") for c in value):
        raise ValueError("control characters are not allowed")
    text = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", value)).strip()
    if not text or len(text) > max_chars:
        raise ValueError(f"must be 1-{max_chars} characters")
    if any(unicodedata.category(c).startswith("C") for c in text):
        raise ValueError("control characters are not allowed")
    if text.startswith(_FORMULA):
        raise ValueError("must not start with a formula character")
    return text


class ColumnSemantics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z_][a-z0-9_]{0,62}$")
    label: str
    semantic_type: SemanticType
    role: Role
    analysis_allowed: bool
    description: str | None = None

    @field_validator("label")
    @classmethod
    def _label(cls, v: str) -> str:
        return _clean_text(v, LABEL_MAX_CHARS)

    @field_validator("description")
    @classmethod
    def _description(cls, v: str | None) -> str | None:
        return None if v is None or not v.strip() else _clean_text(v, DESCRIPTION_MAX_CHARS)


class SemanticMapping(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["semantics-1"] = SEMANTICS_CONTRACT
    columns: list[ColumnSemantics] = Field(min_length=1, max_length=200)


def parse_mapping(raw: Any) -> SemanticMapping:
    try:
        return SemanticMapping.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first.get("loc", ()))
        raise SemanticMappingError("SEMANTICS_INVALID", f"invalid mapping at {where}") from None


def validate_mapping(raw: Any, profile: dict[str, Any]) -> SemanticMapping:
    """Parse ``raw`` and check it against ``profile`` (a ``profile-2`` dict)."""
    mapping = parse_mapping(raw)
    columns = profile.get("columns") or []
    if [c.name for c in mapping.columns] != [c["name"] for c in columns]:
        raise SemanticMappingError(
            "SEMANTICS_COLUMNS_MISMATCH",
            "the mapping must list exactly the profiled columns, in order",
        )
    for sem, col in zip(mapping.columns, columns, strict=True):
        inferred = col["inferred_type"]
        indicators = set(col.get("indicators") or [])
        if sem.semantic_type not in COMPATIBLE_TYPES[inferred]:
            raise SemanticMappingError(
                "SEMANTICS_TYPE_INCOMPATIBLE",
                f"column {sem.name}: {sem.semantic_type} does not fit a {inferred} column",
            )
        if sem.role not in COMPATIBLE_ROLES[sem.semantic_type]:
            raise SemanticMappingError(
                "SEMANTICS_ROLE_INCOMPATIBLE",
                f"column {sem.name}: role {sem.role} does not fit {sem.semantic_type}",
            )
        if indicators & HARD_EXCLUDE and sem.analysis_allowed:
            raise SemanticMappingError(
                "SEMANTICS_SENSITIVE_COLUMN",
                f"column {sem.name} may hold national-id or card data and cannot be analysed",
            )
        if indicators & IDENTIFIER_ONLY and sem.analysis_allowed and sem.role != "identifier":
            raise SemanticMappingError(
                "SEMANTICS_SENSITIVE_COLUMN",
                f"column {sem.name} may hold contact data: analyse it only as an identifier",
            )
    return mapping


def canonical_json(mapping: SemanticMapping) -> str:
    """Deterministic serialization for storage."""
    return mapping.model_dump_json()
