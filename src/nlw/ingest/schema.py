"""``profile-1``: the bounded, redaction-safe description of an uploaded CSV.

This is the only artefact of an upload that leaves the ingestion boundary
(stored in ``dataset_profiles`` and shown to workspace admins). It never holds
rows. Sample values exist only for low-cardinality columns with no sensitivity
flag; a flagged column carries no sample at all, which the validator enforces.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

PROFILE_CONTRACT_VERSION: Literal["profile-1"] = "profile-1"
MAX_SAMPLES = 10
MAX_SAMPLE_CHARS = 32
SAMPLE_MAX_DISTINCT = 50

ColumnType = Literal["boolean", "integer", "decimal", "date", "timestamp", "string"]
SensitivityKind = Literal[
    "ssn",
    "card_number",
    "email",
    "phone",
    "postal_code",
    "person_name",
    "date_of_birth",
    "medical_record",
    "provider_id",
    "license",
    "address",
    "free_text",
]
Treatment = Literal["EXCLUDE", "IDENTIFIER", "REVIEW"]
Source = Literal["header", "values"]


class SensitivityFlag(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: SensitivityKind
    source: Source
    treatment: Treatment
    # SSN and card numbers can never be downgraded by an owner (plan 9.2 step 14).
    hard: bool = False


class ColumnProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    position: int = Field(ge=0)
    raw_header: str = Field(max_length=256)
    name: str = Field(pattern=r"^[a-z_][a-z0-9_]{0,62}$")
    inferred_type: ColumnType
    null_count: int = Field(ge=0)
    non_null_count: int = Field(ge=0)
    distinct_count: int | None = Field(default=None, ge=0)  # None when > DISTINCT_EXACT_LIMIT
    distinct_over_limit: bool = False
    min_value: str | None = Field(default=None, max_length=64)
    max_value: str | None = Field(default=None, max_length=64)
    type_failures: int = Field(default=0, ge=0)
    sensitivity: list[SensitivityFlag] = Field(default_factory=list, max_length=12)
    sample_values: list[str] = Field(default_factory=list, max_length=MAX_SAMPLES)
    warnings: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def _no_samples_for_flagged_or_wide_columns(self) -> ColumnProfile:
        if self.sample_values and self.sensitivity:
            raise ValueError("flagged columns must not carry sample values")
        if self.sample_values and (
            self.distinct_count is None or self.distinct_count > SAMPLE_MAX_DISTINCT
        ):
            raise ValueError("samples only for low-cardinality columns")
        if any(len(v) > MAX_SAMPLE_CHARS for v in self.sample_values):
            raise ValueError("sample value too long")
        # min/max are shown in the review table: never for a flagged column.
        if self.sensitivity and (self.min_value is not None or self.max_value is not None):
            raise ValueError("flagged columns must not carry min/max values")
        return self


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["profile-1"] = PROFILE_CONTRACT_VERSION
    encoding: Literal["utf-8", "utf-8-sig", "utf-16", "cp1252"]
    encoding_needs_confirmation: bool = False
    delimiter: Literal[",", ";", "\t", "|"]
    header_row: bool
    row_count: int = Field(ge=0)
    column_count: int = Field(ge=1)
    columns: list[ColumnProfile]
    formula_prefix_count: int = Field(ge=0)
    warnings: list[str] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def _consistent(self) -> Profile:
        if len(self.columns) != self.column_count:
            raise ValueError("column_count does not match columns")
        if len({c.name for c in self.columns}) != len(self.columns):
            raise ValueError("normalised column names must be unique")
        return self
