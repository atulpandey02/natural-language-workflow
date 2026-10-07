"""Strict, streaming, deterministic CSV validation and profiling -> ``profile-2``.

This is the pilot upload policy (ADR-030). It is deliberately stricter than the
``profile-1`` library profiler (``nlw.ingest.profile``), which stays unchanged:

- bytes: non-empty, at most ``max_bytes``; no archive/binary signature; no NUL
  byte; UTF-8 (a UTF-8 BOM is allowed) and nothing else; no control characters
  other than tab, CR and LF;
- shape: comma-delimited, ``"`` quoting, strict parsing (an unterminated quote
  or data after a closing quote is ``PARSE_ERROR``); EXACTLY one header row;
  every row exactly as wide as the header; at least one data row;
- header: every cell non-empty, at most 256 characters, not a number, date or
  timestamp (that would be a data row, not a header), and unique after
  normalization (no silent renaming);
- bounds: rows, columns, field length and wall clock, each a stable reject code.

Memory is bounded by per-column accumulators, never by the file: exact distinct
counting keeps 16-byte digests up to ``DISTINCT_LIMIT`` per column and then
reports "over limit"; min/max/sum are scalars; indicator detection looks at the
first ``INDICATOR_SAMPLE`` non-null values by counting, not storing.

Deterministic: the same bytes and limits give a byte-identical profile JSON.
There is no I/O beyond the stream handed in, no network and no model call. The
profile holds NO sample values; min/max/mean exist only for numeric and temporal
columns that carry no sensitivity indicator.

Type inference (documented contract): a value is null if, after trimming, it is
empty or one of ``NULL_TOKENS`` (case-insensitive). Over the non-null values the
first type in the order boolean, integer, decimal, date, timestamp whose parse
rate is 100 % (boolean) or at least 98 % (the others) is chosen; otherwise
``string``. ``parse_error_count`` is the number of non-null values that do not
parse as the chosen type. Only ISO dates (``YYYY-MM-DD``) and ISO timestamps are
recognized; slash dates are never guessed.
"""

from __future__ import annotations

import codecs
import csv
import hashlib
import io
import re
import time
import unicodedata
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import BinaryIO, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nlw.ingest.profile import normalise_header
from nlw.ingest.validate import _MAGIC, FileRejected, RejectCode

CONTRACT: Literal["profile-2"] = "profile-2"

# Hard ceilings: configuration can lower a limit, never raise it past these.
CEILING_BYTES = 25_000_000
CEILING_ROWS = 1_000_000
CEILING_COLUMNS = 200
CEILING_FIELD_CHARS = 32_768
CEILING_TIMEOUT_S = 300.0
MAX_HEADER_CHARS = 256
DISTINCT_LIMIT = 1_000
INDICATOR_SAMPLE = 10_000
INDICATOR_SHARE = 0.8
TYPE_THRESHOLD = 0.98
IDENTIFIER_MIN_VALUES = 20
NULL_TOKENS = frozenset({"", "null", "na", "n/a", "-", "#n/a", "none"})
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_CHUNK = 1 << 16
_TIME_CHECK_ROWS = 1_000
_HEAD = 64  # bytes inspected for signatures and BOMs before parsing


class PolicyReject(FileRejected):
    """A strict-policy refusal. ``code`` is a lifecycle rejection-code string
    (a superset of ``nlw.ingest.validate.RejectCode``)."""

    def __init__(self, code: str) -> None:
        ValueError.__init__(self, code)
        self.code = code  # type: ignore[assignment]


def _reject(code: str | RejectCode) -> PolicyReject:
    return PolicyReject(code.value if isinstance(code, RejectCode) else code)


@dataclass(frozen=True)
class StrictLimits:
    max_bytes: int = 25_000_000
    max_rows: int = 250_000
    max_columns: int = 200
    max_field_chars: int = 8_192
    timeout_s: float = 60.0

    def __post_init__(self) -> None:
        bounds = (
            ("max_bytes", self.max_bytes, CEILING_BYTES),
            ("max_rows", self.max_rows, CEILING_ROWS),
            ("max_columns", self.max_columns, CEILING_COLUMNS),
            ("max_field_chars", self.max_field_chars, CEILING_FIELD_CHARS),
            ("timeout_s", self.timeout_s, CEILING_TIMEOUT_S),
        )
        for name, value, ceiling in bounds:
            if not (0 < value <= ceiling):
                raise ValueError(f"{name} must be within 1..{ceiling}")


# ------------------------------------------------------------------ contract
ColumnType = Literal["boolean", "integer", "decimal", "date", "timestamp", "string"]
Indicator = Literal[
    "possible_email",
    "possible_phone",
    "possible_national_id",
    "possible_payment_card",
    "identifier_like",
]
ColumnWarning = Literal[
    "ALL_NULL", "TYPE_PARTIAL_PARSE", "FORMULA_LIKE_VALUES", "HEADER_NEUTRALIZED"
]
ProfileWarning = Literal["FORMULA_LIKE_CELLS", "UTF8_BOM"]


class ColumnProfile2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    position: int = Field(ge=0, lt=CEILING_COLUMNS)
    header: str = Field(min_length=1, max_length=MAX_HEADER_CHARS + 1)
    name: str = Field(pattern=r"^[a-z_][a-z0-9_]{0,62}$")
    inferred_type: ColumnType
    non_null_count: int = Field(ge=0)
    null_count: int = Field(ge=0)
    null_fraction: float = Field(ge=0.0, le=1.0)
    distinct_count: int | None = Field(default=None, ge=0, le=DISTINCT_LIMIT)
    distinct_over_limit: bool = False
    min_value: str | None = Field(default=None, max_length=64)
    max_value: str | None = Field(default=None, max_length=64)
    mean: float | None = None
    min_length: int | None = Field(default=None, ge=0)
    max_length: int | None = Field(default=None, ge=0)
    parse_error_count: int = Field(default=0, ge=0)
    formula_like_count: int = Field(default=0, ge=0)
    indicators: list[Indicator] = Field(default_factory=list, max_length=5)
    warnings: list[ColumnWarning] = Field(default_factory=list, max_length=4)

    @model_validator(mode="after")
    def _bounded_disclosure(self) -> ColumnProfile2:
        if self.indicators and (
            self.min_value is not None or self.max_value is not None or self.mean is not None
        ):
            raise ValueError("a column with a sensitivity indicator carries no values")
        if self.inferred_type not in ("integer", "decimal", "date", "timestamp") and (
            self.min_value is not None or self.max_value is not None
        ):
            raise ValueError("min/max only for numeric and temporal columns")
        if self.inferred_type not in ("integer", "decimal") and self.mean is not None:
            raise ValueError("mean only for numeric columns")
        if (self.distinct_count is None) != self.distinct_over_limit:
            raise ValueError("distinct_count is exact or explicitly over the limit")
        return self


class Profile2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["profile-2"] = CONTRACT
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1, le=CEILING_BYTES)
    encoding: Literal["utf-8", "utf-8-sig"]
    delimiter: Literal[","] = ","
    header_rows: Literal[1] = 1
    row_count: int = Field(ge=1, le=CEILING_ROWS)
    column_count: int = Field(ge=1, le=CEILING_COLUMNS)
    columns: list[ColumnProfile2]
    formula_like_cells: int = Field(ge=0)
    distinct_limit: int = DISTINCT_LIMIT
    warnings: list[ProfileWarning] = Field(default_factory=list, max_length=2)

    @model_validator(mode="after")
    def _consistent(self) -> Profile2:
        if len(self.columns) != self.column_count:
            raise ValueError("column_count does not match columns")
        if [c.position for c in self.columns] != list(range(self.column_count)):
            raise ValueError("columns must be in position order")
        if len({c.name for c in self.columns}) != self.column_count:
            raise ValueError("column names must be unique")
        for c in self.columns:
            if c.non_null_count + c.null_count != self.row_count:
                raise ValueError("per-column counts must add up to the row count")
        return self


# ------------------------------------------------------------------ parsing helpers
_BOOL = frozenset({"true", "false", "yes", "no", "y", "n", "t", "f"})
_INT = re.compile(r"^[+-]?\d{1,18}$")
_DEC = re.compile(r"^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d{1,3})?$")
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ISO_TS = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:?\d{2})?$"
)
# Control-character rule (one rule for every user-controlled field of this
# feature): Unicode Cc -- C0 (U+0000-U+001F), DEL (U+007F) and C1
# (U+0080-U+009F) -- is refused everywhere. In data cells, TAB, LF and CR are
# the only exceptions (CSV structure / quoted line breaks). Header cells, like
# the metadata fields (names, filenames, semantic labels), additionally refuse
# TAB/LF/CR and format characters (Cf: zero-width, bidi overrides).
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_PHONE = re.compile(r"^\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$|^\+\d{8,15}$")
_SSN = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_CARD = re.compile(r"^\d(?:[ -]?\d){12,18}$")
_HEADER_INDICATORS: tuple[tuple[re.Pattern[str], Indicator], ...] = (
    (re.compile(r"(^|_)e?mail"), "possible_email"),
    (re.compile(r"(^|_)(phone|mobile|cell|tel|fax)"), "possible_phone"),
    (re.compile(r"(^|_)(ssn|social_security|national_id|nin|passport)"), "possible_national_id"),
    (re.compile(r"(^|_)(card|cc|credit_card|pan)(_|$)"), "possible_payment_card"),
    (
        re.compile(r"(^|_)(id|uuid|guid|key|account|acct|mrn|npi|number|num|no)(_|$)"),
        "identifier_like",
    ),
)


def _parse_date(v: str) -> date | None:
    if not _ISO_DATE.match(v):
        return None
    try:
        return date.fromisoformat(v)
    except ValueError:
        return None


def _parse_ts(v: str) -> datetime | None:
    if not _ISO_TS.match(v):
        return None
    try:
        ts = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    # Aware timestamps compare in UTC; naive ones are compared as written.
    return ts.astimezone(UTC).replace(tzinfo=None) if ts.tzinfo else ts


def _parse_int(v: str) -> int | None:
    return int(v) if _INT.match(v) else None


def _parse_dec(v: str) -> float | None:
    if not _DEC.match(v):
        return None
    f = float(v)
    return f if f not in (float("inf"), float("-inf")) else None


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


def neutralize_formula(text: str) -> str:
    """Display/export-safe text: a leading formula marker is prefixed with ``'``
    so no spreadsheet ever evaluates it. Nothing is ever executed here."""
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def _is_number(v: str) -> bool:
    return bool(_DEC.match(v))


# ------------------------------------------------------------------ accumulators
class _Range:
    """Running min/max of parsed values, keeping the source text of each."""

    __slots__ = ("hi", "hi_text", "lo", "lo_text", "ok")

    def __init__(self) -> None:
        self.ok = 0
        self.lo: object = None
        self.hi: object = None
        self.lo_text = ""
        self.hi_text = ""

    def add(self, parsed: object, text: str) -> None:
        self.ok += 1
        if self.lo is None or parsed < self.lo:  # type: ignore[operator]
            self.lo, self.lo_text = parsed, text
        if self.hi is None or parsed > self.hi:  # type: ignore[operator]
            self.hi, self.hi_text = parsed, text


class _Column:
    __slots__ = (
        "bool_ok",
        "dates",
        "dec",
        "dec_sum",
        "distinct",
        "formula",
        "ints",
        "int_sum",
        "max_len",
        "min_len",
        "non_null",
        "nulls",
        "over",
        "pattern_counts",
        "pattern_seen",
        "ts",
    )

    def __init__(self) -> None:
        self.nulls = 0
        self.non_null = 0
        self.bool_ok = 0
        self.ints = _Range()
        self.dec = _Range()
        self.dates = _Range()
        self.ts = _Range()
        self.int_sum = 0
        self.dec_sum = 0.0
        self.distinct: set[bytes] | None = set()
        self.over = False
        self.min_len: int | None = None
        self.max_len: int | None = None
        self.formula = 0
        self.pattern_seen = 0
        self.pattern_counts = [0, 0, 0, 0]  # email, phone, ssn, card

    def add(self, raw: str) -> None:
        if raw.startswith(FORMULA_PREFIXES) and not _is_number(raw.strip()):
            self.formula += 1
        v = raw.strip()
        if v.lower() in NULL_TOKENS:
            self.nulls += 1
            return
        self.non_null += 1
        n = len(v)
        if self.min_len is None or n < self.min_len:
            self.min_len = n
        if self.max_len is None or n > self.max_len:
            self.max_len = n
        if self.distinct is not None:
            self.distinct.add(hashlib.blake2b(v.encode(), digest_size=16).digest())
            if len(self.distinct) > DISTINCT_LIMIT:
                self.distinct = None  # free it: from here the count is "over limit"
                self.over = True
        if v.lower() in _BOOL:
            self.bool_ok += 1
        i = _parse_int(v)
        if i is not None:
            self.ints.add(i, v)
            self.int_sum += i
        d = _parse_dec(v)
        if d is not None:
            self.dec.add(d, v)
            self.dec_sum += d
        if (dt := _parse_date(v)) is not None:
            self.dates.add(dt, v)
        if (ts := _parse_ts(v)) is not None:
            self.ts.add(ts, v)
        if self.pattern_seen < INDICATOR_SAMPLE:
            self.pattern_seen += 1
            pc = self.pattern_counts
            if _EMAIL.match(v):
                pc[0] += 1
            if _PHONE.match(v):
                pc[1] += 1
            if _SSN.match(v):
                pc[2] += 1
            if _CARD.match(v) and _luhn(v):
                pc[3] += 1

    def _choose_type(self) -> tuple[ColumnType, _Range | None, int]:
        n = self.non_null
        if n == 0:
            return "string", None, 0
        if self.bool_ok == n:
            return "boolean", None, 0
        candidates: tuple[tuple[ColumnType, _Range], ...] = (
            ("integer", self.ints),
            ("decimal", self.dec),
            ("date", self.dates),
            ("timestamp", self.ts),
        )
        for name, rng in candidates:
            if rng.ok == n or rng.ok / n >= TYPE_THRESHOLD:
                return name, rng, n - rng.ok
        return "string", None, 0

    def _indicators(self, name: str, col_type: ColumnType) -> list[Indicator]:
        found: set[Indicator] = set()
        for pattern, indicator in _HEADER_INDICATORS:
            if pattern.search(name):
                found.add(indicator)
        if self.pattern_seen:
            value_indicators: tuple[Indicator, ...] = (
                "possible_email",
                "possible_phone",
                "possible_national_id",
                "possible_payment_card",
            )
            for count, value_indicator in zip(self.pattern_counts, value_indicators, strict=True):
                if count / self.pattern_seen >= INDICATOR_SHARE:
                    found.add(value_indicator)
        if (
            col_type in ("integer", "string")
            and not self.over
            and self.non_null >= IDENTIFIER_MIN_VALUES
            and self.distinct is not None
            and len(self.distinct) == self.non_null
        ):
            found.add("identifier_like")
        order: tuple[Indicator, ...] = (
            "possible_email",
            "possible_phone",
            "possible_national_id",
            "possible_payment_card",
            "identifier_like",
        )
        return [i for i in order if i in found]

    def finish(self, position: int, header: str, name: str, rows: int) -> ColumnProfile2:
        col_type, rng, failures = self._choose_type()
        indicators = self._indicators(name, col_type)
        warnings: list[ColumnWarning] = []
        if self.non_null == 0:
            warnings.append("ALL_NULL")
        if failures:
            warnings.append("TYPE_PARTIAL_PARSE")
        if self.formula:
            warnings.append("FORMULA_LIKE_VALUES")
        shown = neutralize_formula(header)
        if shown != header:
            warnings.append("HEADER_NEUTRALIZED")
        min_v = max_v = None
        mean: float | None = None
        if rng is not None and not indicators:
            min_v, max_v = rng.lo_text[:64], rng.hi_text[:64]
            if col_type == "integer" and rng.ok:
                mean = round(self.int_sum / rng.ok, 6)
            elif col_type == "decimal" and rng.ok:
                mean = round(self.dec_sum / rng.ok, 6)
        return ColumnProfile2(
            position=position,
            header=shown,
            name=name,
            inferred_type=col_type,
            non_null_count=self.non_null,
            null_count=self.nulls,
            null_fraction=round(self.nulls / rows, 6) if rows else 0.0,
            distinct_count=None if self.over else len(self.distinct or ()),
            distinct_over_limit=self.over,
            min_value=min_v,
            max_value=max_v,
            mean=mean,
            min_length=self.min_len,
            max_length=self.max_len,
            parse_error_count=failures,
            formula_like_count=self.formula,
            indicators=indicators,
            warnings=warnings,
        )


# ------------------------------------------------------------------ byte stream
class _GuardedBytes(io.RawIOBase):
    """Counts, hashes and polices the raw bytes as the parser pulls them.

    The first ``_HEAD`` bytes are assembled BEFORE anything is released to the
    decoder, so signature and BOM detection (and the reported encoding) never
    depend on how the underlying stream happens to chunk its reads."""

    def __init__(self, stream: BinaryIO, max_bytes: int) -> None:
        self._stream = stream
        self._max = max_bytes
        self.size = 0
        self.sha = hashlib.sha256()
        self.head = b""
        self._started = False
        self._pending = b""

    def readable(self) -> bool:
        return True

    def _read_head(self) -> None:
        self._started = True
        head = b""
        while len(head) < _HEAD:
            part = self._stream.read(_HEAD - len(head))
            if not part:
                break
            head += part
        self.head = head
        if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            raise _reject(RejectCode.ENCODING_UNSUPPORTED)  # UTF-16/32: not UTF-8
        if any(head.startswith(m) for m in _MAGIC):
            raise _reject(RejectCode.FILE_TYPE)
        self._pending = head

    def readinto(self, buffer: memoryview) -> int:  # type: ignore[override]
        if not self._started:
            self._read_head()
        want = min(len(buffer), _CHUNK)
        if self._pending:
            chunk, self._pending = self._pending[:want], self._pending[want:]
        else:
            chunk = self._stream.read(want)
        if not chunk:
            return 0
        self.size += len(chunk)
        if self.size > self._max:
            raise _reject(RejectCode.FILE_TOO_LARGE)
        if b"\x00" in chunk:
            raise _reject(RejectCode.CONTENT_BINARY)
        self.sha.update(chunk)
        n = len(chunk)
        buffer[:n] = chunk
        return n

    def drain(self) -> None:
        """Hash any trailing bytes the parser did not need (so the digest always
        covers the whole object) while still enforcing the byte cap."""
        buf = bytearray(_CHUNK)
        while self.readinto(memoryview(buf)):
            pass


def _rows(text: io.TextIOBase, max_field_chars: int) -> Iterator[list[str]]:
    reader = csv.reader(text, delimiter=",", quotechar='"', strict=True)
    try:
        yield from reader
    except csv.Error as exc:
        if "field larger than field limit" in str(exc):
            raise _reject(RejectCode.FIELD_TOO_LARGE) from None
        raise _reject(RejectCode.PARSE_ERROR) from None
    except UnicodeDecodeError:
        raise _reject(RejectCode.ENCODING_UNSUPPORTED) from None


def _check_cells(row: list[str], max_field_chars: int) -> None:
    for cell in row:
        if len(cell) > max_field_chars:
            raise _reject(RejectCode.FIELD_TOO_LARGE)
        if _CONTROL.search(cell):
            raise _reject(RejectCode.CONTENT_BINARY)


def _header(row: list[str], limits: StrictLimits) -> tuple[list[str], list[str]]:
    if not row:
        raise _reject("HEADER_INVALID")
    if len(row) > limits.max_columns:
        raise _reject(RejectCode.TOO_MANY_COLUMNS)
    headers = [c.strip() for c in row]
    for h in headers:
        if not h or len(h) > MAX_HEADER_CHARS:
            raise _reject("HEADER_INVALID")
        if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in h):
            raise _reject("HEADER_INVALID")
        if _is_number(h) or _parse_date(h) is not None or _parse_ts(h) is not None:
            raise _reject("HEADER_INVALID")  # a data row, not a header row
    names = [normalise_header(h, i) for i, h in enumerate(headers)]
    if len(set(names)) != len(names):
        raise _reject("HEADER_DUPLICATE")
    return headers, names


def profile_stream(
    stream: BinaryIO,
    limits: StrictLimits | None = None,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> Profile2:
    """Validate and profile a CSV byte stream under the strict pilot policy.

    Raises :class:`PolicyReject` (``.code`` is a lifecycle rejection code). The
    process-global ``csv.field_size_limit`` is set for the call and restored.
    """
    limits = limits or StrictLimits()
    started = clock()
    raw = _GuardedBytes(stream, limits.max_bytes)
    buffered = io.BufferedReader(raw, buffer_size=_CHUNK)
    text = io.TextIOWrapper(buffered, encoding="utf-8-sig", errors="strict", newline="")
    previous = csv.field_size_limit(limits.max_field_chars + 1)
    try:
        rows = _rows(text, limits.max_field_chars)
        try:
            first = next(rows)
        except StopIteration:
            raise _reject(RejectCode.FILE_EMPTY) from None
        _check_cells(first, limits.max_field_chars)
        headers, names = _header(first, limits)
        width = len(headers)
        cols = [_Column() for _ in range(width)]
        count = 0
        for row in rows:
            count += 1
            if count > limits.max_rows:
                raise _reject(RejectCode.TOO_MANY_ROWS)
            if count % _TIME_CHECK_ROWS == 0 and clock() - started > limits.timeout_s:
                raise _reject(RejectCode.PARSE_TIMEOUT)
            if len(row) != width:
                raise _reject("ROW_WIDTH_MISMATCH")
            _check_cells(row, limits.max_field_chars)
            for col, cell in zip(cols, row, strict=True):
                col.add(cell)
        raw.drain()
    finally:
        csv.field_size_limit(previous)
    if raw.size == 0:
        raise _reject(RejectCode.FILE_EMPTY)
    if count == 0:
        raise _reject("NO_DATA_ROWS")
    if clock() - started > limits.timeout_s:
        raise _reject(RejectCode.PARSE_TIMEOUT)
    columns = [cols[i].finish(i, headers[i], names[i], count) for i in range(width)]
    formula = sum(c.formula_like_count for c in columns)
    warnings: list[ProfileWarning] = []
    if formula:
        warnings.append("FORMULA_LIKE_CELLS")
    bom = raw.head.startswith(codecs.BOM_UTF8)
    if bom:
        warnings.append("UTF8_BOM")
    return Profile2(
        content_sha256=raw.sha.hexdigest(),
        size_bytes=raw.size,
        encoding="utf-8-sig" if bom else "utf-8",
        row_count=count,
        column_count=width,
        columns=columns,
        formula_like_cells=formula,
        warnings=warnings,
    )


def profile_bytes(data: bytes, limits: StrictLimits | None = None) -> Profile2:
    """Convenience for tests and small inputs."""
    return profile_stream(io.BytesIO(data), limits)
