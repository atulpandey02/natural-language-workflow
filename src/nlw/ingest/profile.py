"""Deterministic, bounded CSV profiling (plan 9.2 steps 6-14) -> ``profile-1``.

Implementation note: the plan specifies DuckDB ``read_csv`` in a sandboxed
connection. DuckDB is not an approved dependency yet (plan section 22), so this
profiler uses the standard library ``csv`` module under the same limits. It is a
single entry point, :func:`profile_csv`, so the engine can be swapped after the
dependency decision without changing the contract or its golden tests.

Guarantees:
- bounded: byte, row, column, field-size and wall-clock limits, each a stable
  reject code;
- deterministic: same bytes -> byte-identical profile JSON;
- no I/O beyond the bytes handed in, no network, no model call;
- no raw rows leave: only counts, types, flags and (for unflagged columns with
  <= 50 distinct values) up to 10 truncated sample values.
"""

from __future__ import annotations

import csv
import io
import re
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime

from nlw.ingest.schema import (
    MAX_SAMPLE_CHARS,
    MAX_SAMPLES,
    SAMPLE_MAX_DISTINCT,
    ColumnProfile,
    Profile,
    SensitivityFlag,
)
from nlw.ingest.validate import (
    FileRejected,
    RejectCode,
    check_signature,
    check_text,
    detect_encoding,
)

NULL_TOKENS = frozenset({"", "null", "na", "n/a", "-", "#n/a", "none"})
DELIMITERS = (",", ";", "\t", "|")
TYPE_THRESHOLD = 0.98
DISTINCT_EXACT_LIMIT = 1000
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
SNIFF_CHARS = 16 * 1024


@dataclass(frozen=True)
class Limits:
    max_bytes: int = 25_000_000
    max_rows: int = 1_000_000
    max_columns: int = 200
    max_field_chars: int = 32 * 1024
    timeout_s: float = 120.0


# ---------------------------------------------------------------- normalisation
def normalise_header(raw: str, position: int) -> str:
    folded = unicodedata.normalize("NFKD", raw).encode("ascii", "ignore").decode()
    s = re.sub(r"[^a-z0-9]+", "_", folded.lower()).strip("_")
    if not s:
        return f"col_{position + 1}"
    if s[0].isdigit():
        s = "_" + s
    return s[:63].rstrip("_") or f"col_{position + 1}"


def dedupe_names(names: list[str]) -> tuple[list[str], list[str]]:
    seen: dict[str, int] = {}
    out: list[str] = []
    warnings: list[str] = []
    for n in names:
        if n in seen:
            seen[n] += 1
            new = f"{n[:59]}_{seen[n]}"
            while new in seen:
                seen[n] += 1
                new = f"{n[:59]}_{seen[n]}"
            seen[new] = 1
            out.append(new)
            warnings.append("DUPLICATE_HEADER_RENAMED")
        else:
            seen[n] = 1
            out.append(n)
    return out, warnings


# ------------------------------------------------------------------- typing
_BOOL = frozenset({"true", "false", "yes", "no", "y", "n", "t", "f"})
_INT = re.compile(r"^[+-]?\d{1,18}$")
_DEC = re.compile(r"^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?$")
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SLASH_DATE = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})$")
_ISO_TS = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:?\d{2})?$"
)


def _is_bool(v: str) -> bool:
    return v.lower() in _BOOL


def _is_int(v: str) -> bool:
    return bool(_INT.match(v))


def _is_dec(v: str) -> bool:
    return bool(_DEC.match(v))


def _is_iso_date(v: str) -> bool:
    if not _ISO_DATE.match(v):
        return False
    try:
        date.fromisoformat(v)
    except ValueError:
        return False
    return True


def _is_ts(v: str) -> bool:
    if not _ISO_TS.match(v):
        return False
    try:
        datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


_CHECKS: tuple[tuple[str, Callable[[str], bool]], ...] = (
    ("boolean", _is_bool),
    ("integer", _is_int),
    ("decimal", _is_dec),
    ("date", _is_iso_date),
    ("timestamp", _is_ts),
)


def _slash_date_ambiguity(values: list[str]) -> bool:
    """True if values look like dates but MM/DD vs DD/MM cannot be decided."""
    parsed = [_SLASH_DATE.match(v) for v in values]
    if not values or not all(parsed):
        return False
    first_over_12 = any(int(m.group(1)) > 12 for m in parsed if m)
    second_over_12 = any(int(m.group(2)) > 12 for m in parsed if m)
    return not (first_over_12 or second_over_12)


def infer_type(values: list[str]) -> tuple[str, int, list[str]]:
    """(type, failure count, warnings). A type is accepted only if >= 98% of the
    non-null values parse; slash dates are never guessed (always string)."""
    if not values:
        return "string", 0, ["ALL_NULL"]
    n = len(values)
    for name, check in _CHECKS:
        ok = sum(1 for v in values if check(v))
        if ok == n or (ok / n >= TYPE_THRESHOLD and name != "boolean"):
            warnings = ["TYPE_PARTIAL_PARSE"] if ok < n else []
            return name, n - ok, warnings
    if _SLASH_DATE.match(values[0]):
        return (
            "string",
            0,
            [
                "DATE_FORMAT_AMBIGUOUS"
                if _slash_date_ambiguity(values)
                else "DATE_FORMAT_UNCONFIRMED"
            ],
        )
    return "string", 0, []


# ---------------------------------------------------------------- sensitivity
_HEADER_KEYWORDS: tuple[tuple[re.Pattern[str], str, str, bool], ...] = (
    (re.compile(r"(^|_)(ssn|social_security)"), "ssn", "EXCLUDE", True),
    (re.compile(r"(^|_)(card|cc|credit_card|pan)(_|$)"), "card_number", "EXCLUDE", True),
    (re.compile(r"(^|_)e?mail"), "email", "IDENTIFIER", False),
    (re.compile(r"(^|_)(phone|mobile|cell|tel)"), "phone", "IDENTIFIER", False),
    (re.compile(r"(^|_)(dob|birth|date_of_birth)"), "date_of_birth", "REVIEW", False),
    (re.compile(r"(^|_)mrn|medical_record"), "medical_record", "IDENTIFIER", False),
    (re.compile(r"(^|_)npi(_|$)"), "provider_id", "IDENTIFIER", False),
    (re.compile(r"(^|_)licen[cs]e"), "license", "IDENTIFIER", False),
    (re.compile(r"(^|_)(address|street)"), "address", "REVIEW", False),
    (
        re.compile(r"(^|_)(first|last|full|given|family|patient|member)_?name|^name$"),
        "person_name",
        "REVIEW",
        False,
    ),  # fmt: skip
)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_PHONE = re.compile(r"^\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$|^\+\d{8,15}$")
_SSN = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_ZIP4 = re.compile(r"^\d{5}-\d{4}$")
_CARD = re.compile(r"^\d(?:[ -]?\d){12,18}$")
_VALUE_SHARE = 0.8


def _luhn(v: str) -> bool:
    digits = [int(c) for c in v if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _share(values: list[str], pred: Callable[[str], bool]) -> float:
    return sum(1 for v in values if pred(v)) / len(values) if values else 0.0


def _flag(kind: str, source: str, treatment: str, hard: bool) -> SensitivityFlag:
    return SensitivityFlag.model_validate(
        {"kind": kind, "source": source, "treatment": treatment, "hard": hard}
    )


def detect_sensitivity(name: str, values: list[str], distinct: int | None) -> list[SensitivityFlag]:
    flags: dict[str, SensitivityFlag] = {}
    for pattern, kind, treatment, hard in _HEADER_KEYWORDS:
        if pattern.search(name):
            flags[kind] = _flag(kind, "header", treatment, hard)
    sample = values[:10_000]
    value_rules: tuple[tuple[str, Callable[[str], bool], str, bool], ...] = (
        ("ssn", lambda v: bool(_SSN.match(v)), "EXCLUDE", True),
        ("card_number", lambda v: bool(_CARD.match(v)) and _luhn(v), "EXCLUDE", True),
        ("email", lambda v: bool(_EMAIL.match(v)), "IDENTIFIER", False),
        ("phone", lambda v: bool(_PHONE.match(v)), "IDENTIFIER", False),
        ("postal_code", lambda v: bool(_ZIP4.match(v)), "REVIEW", False),
    )
    for kind, pred, treatment, hard in value_rules:
        if kind not in flags and sample and _share(sample, pred) >= _VALUE_SHARE:
            flags[kind] = _flag(kind, "values", treatment, hard)
    if sample and "free_text" not in flags:
        unique_ratio = (distinct or len(set(sample))) / max(len(values), 1)
        avg_len = sum(len(v) for v in sample) / len(sample)
        if (distinct is None or unique_ratio > 0.8) and avg_len > 40:
            flags["free_text"] = _flag("free_text", "values", "REVIEW", False)
    return [flags[k] for k in sorted(flags)]


# ------------------------------------------------------------------ parsing
def _sniff_delimiter(text: str) -> tuple[str, list[str]]:
    # csv.Sniffer's quote regex is quadratic in its input and runs before any
    # timeout check can interrupt it, so it only ever sees a bounded prefix.
    head = "\n".join(text[:SNIFF_CHARS].splitlines()[:50])
    try:
        found = csv.Sniffer().sniff(head, delimiters="".join(DELIMITERS)).delimiter
        return found, []
    except csv.Error:
        counts = {d: head.count(d) for d in DELIMITERS}
        best = max(DELIMITERS, key=lambda d: (counts[d], -DELIMITERS.index(d)))
        return (best if counts[best] else ","), ["DELIMITER_GUESSED"]


def _looks_like_header(first: list[str]) -> bool:
    """A header row has no empty cell and no cell that parses as a number, date
    or timestamp. Otherwise the first row is data and columns become col_n."""
    cells = [c.strip() for c in first]
    return (
        bool(cells)
        and all(cells)
        and not any(_is_dec(c) or _is_iso_date(c) or _is_ts(c) for c in cells)
    )


def profile_csv(data: bytes, *, limits: Limits | None = None) -> Profile:
    """Profile raw CSV bytes. Raises :class:`FileRejected` with a stable code."""
    limits = limits or Limits()
    started = time.monotonic()
    if len(data) > limits.max_bytes:
        raise FileRejected(RejectCode.FILE_TOO_LARGE)
    check_signature(data[:65536])
    enc = detect_encoding(data)
    text = data.decode(enc.name)
    if enc.name == "utf-16":
        text = text.lstrip("﻿")
    check_text(text)
    # Newline pre-pass rejects a too-long file before full parsing.
    if text.count("\n") > limits.max_rows + 2:
        raise FileRejected(RejectCode.TOO_MANY_ROWS)
    delimiter, warnings = _sniff_delimiter(text)
    if time.monotonic() - started > limits.timeout_s:
        raise FileRejected(RejectCode.PARSE_TIMEOUT)
    csv.field_size_limit(limits.max_field_chars + 1)
    # strict: an unterminated quote is a PARSE_ERROR, never the rest of the file
    # silently folded into one field.
    reader = csv.reader(
        io.StringIO(text, newline=""), delimiter=delimiter, quotechar='"', strict=True
    )
    rows: list[list[str]] = []
    try:
        for i, row in enumerate(reader):
            if i % 10_000 == 0 and time.monotonic() - started > limits.timeout_s:
                raise FileRejected(RejectCode.PARSE_TIMEOUT)
            if len(row) > limits.max_columns:
                raise FileRejected(RejectCode.TOO_MANY_COLUMNS)
            if any(len(c) > limits.max_field_chars for c in row):
                raise FileRejected(RejectCode.FIELD_TOO_LARGE)
            if not row or all(not c.strip() for c in row):
                continue
            rows.append(row)
            if len(rows) > limits.max_rows + 1:
                raise FileRejected(RejectCode.TOO_MANY_ROWS)
    except csv.Error as exc:
        if "field larger than field limit" in str(exc):
            raise FileRejected(RejectCode.FIELD_TOO_LARGE) from exc
        raise FileRejected(RejectCode.PARSE_ERROR) from exc
    if not rows:
        raise FileRejected(RejectCode.FILE_EMPTY)

    header = _looks_like_header(rows[0])
    width = max(len(r) for r in rows)
    if width > limits.max_columns:
        raise FileRejected(RejectCode.TOO_MANY_COLUMNS)
    raw_headers = (
        [(rows[0][i] if i < len(rows[0]) else "") for i in range(width)]
        if header
        else ["" for _ in range(width)]
    )
    body = rows[1:] if header else rows
    if len(body) > limits.max_rows:
        raise FileRejected(RejectCode.TOO_MANY_ROWS)
    if not header:
        warnings.append("NO_HEADER_DETECTED")
    if any(len(r) != width for r in body):
        warnings.append("RAGGED_ROWS")
    names, dup_warnings = dedupe_names(
        [normalise_header(h, i) if h.strip() else f"col_{i + 1}" for i, h in enumerate(raw_headers)]
    )
    warnings.extend(sorted(set(dup_warnings)))

    formula_count = 0
    columns: list[ColumnProfile] = []
    for i in range(width):
        if time.monotonic() - started > limits.timeout_s:
            raise FileRejected(RejectCode.PARSE_TIMEOUT)
        cells = [(r[i] if i < len(r) else "") for r in body]
        formula_count += sum(
            1
            for c in cells
            if c.strip().lower() not in NULL_TOKENS
            and c.startswith(FORMULA_PREFIXES)
            and not _is_dec(c)
        )
        values = [c.strip() for c in cells if c.strip().lower() not in NULL_TOKENS]
        distinct_set: set[str] = set()
        over = False
        for v in values:
            distinct_set.add(v)
            if len(distinct_set) > DISTINCT_EXACT_LIMIT:
                over = True
                break
        distinct = None if over else len(distinct_set)
        col_type, failures, col_warnings = infer_type(values)
        flags = detect_sensitivity(names[i], values, distinct)
        min_v = max_v = None
        if not flags and values and col_type in ("integer", "decimal", "date", "timestamp"):
            parsed = [v for v in values if dict(_CHECKS)[col_type](v)]
            if col_type in ("integer", "decimal"):
                nums = sorted(parsed, key=float)
                min_v, max_v = nums[0][:64], nums[-1][:64]
            else:
                ordered = sorted(parsed)
                min_v, max_v = ordered[0][:64], ordered[-1][:64]
        samples: list[str] = []
        if not flags and distinct is not None and 0 < distinct <= SAMPLE_MAX_DISTINCT:
            samples = sorted(v[:MAX_SAMPLE_CHARS] for v in distinct_set)[:MAX_SAMPLES]
        columns.append(
            ColumnProfile(
                position=i,
                raw_header=raw_headers[i][:256],
                name=names[i],
                inferred_type=col_type,  # type: ignore[arg-type]
                null_count=len(cells) - len(values),
                non_null_count=len(values),
                distinct_count=distinct,
                distinct_over_limit=over,
                min_value=min_v,
                max_value=max_v,
                type_failures=failures,
                sensitivity=flags,
                sample_values=samples,
                warnings=col_warnings,
            )
        )
    if enc.needs_confirmation:
        warnings.append("ENCODING_NEEDS_CONFIRMATION")
    if formula_count:
        warnings.append("FORMULA_PREFIX_CELLS")
    return Profile(
        encoding=enc.name,  # type: ignore[arg-type]
        encoding_needs_confirmation=enc.needs_confirmation,
        delimiter=delimiter,  # type: ignore[arg-type]
        header_row=header,
        row_count=len(body),
        column_count=width,
        columns=columns,
        formula_prefix_count=formula_count,
        warnings=warnings,
    )
