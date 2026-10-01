"""Deterministic file checks before any parsing (plan 9.2 steps 2, 3 and 7).

Pure functions over bytes: no filesystem, network, database or model access.
Every refusal is a stable reject code the UI can name.
"""

from __future__ import annotations

import codecs
from dataclasses import dataclass
from enum import StrEnum

SNIFF_BYTES = 64 * 1024
MAX_LINE_BYTES = 1024 * 1024


class RejectCode(StrEnum):
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


class FileRejected(ValueError):
    def __init__(self, code: RejectCode) -> None:
        super().__init__(code.value)
        self.code = code


# Container / executable / document signatures that must never be parsed as text.
_MAGIC: tuple[bytes, ...] = (
    b"PK\x03\x04",  # zip (xlsx, docx, jar, ...)
    b"PK\x05\x06",  # empty zip
    b"PK\x07\x08",  # spanned zip
    b"%PDF",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # OLE2 (xls, doc, msi)
    b"\x7fELF",
    b"MZ",  # PE / DOS executable
    b"\x1f\x8b",  # gzip
    b"BZh",  # bzip2
    b"\xfd7zXZ\x00",  # xz
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
    b"\x89PNG",
    b"\xff\xd8\xff",  # jpeg
    b"GIF8",
    b"PAR1",  # parquet: customer-supplied parquet is refused (plan 9.2 step 21)
    b"ARROW1",
    b"SQLite format 3\x00",
)


@dataclass(frozen=True)
class Encoding:
    name: str  # python codec: utf-8, utf-8-sig, utf-16, cp1252
    needs_confirmation: bool


def check_signature(head: bytes) -> None:
    """Refuse known binary formats and NUL bytes (unless a UTF-16 BOM)."""
    if not head:
        raise FileRejected(RejectCode.FILE_EMPTY)
    if any(head.startswith(m) for m in _MAGIC):
        raise FileRejected(RejectCode.FILE_TYPE)
    utf16 = head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE))
    if b"\x00" in head[:SNIFF_BYTES] and not utf16:
        raise FileRejected(RejectCode.FILE_TYPE)


def detect_encoding(data: bytes) -> Encoding:
    """UTF-8 (with/without BOM) and UTF-16 with BOM are accepted as-is; anything
    else that decodes as Windows-1252 is accepted only with user confirmation."""
    if data.startswith(codecs.BOM_UTF32_LE) or data.startswith(codecs.BOM_UTF32_BE):
        raise FileRejected(RejectCode.ENCODING_UNSUPPORTED)
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        try:
            data.decode("utf-16")
        except UnicodeDecodeError as exc:
            raise FileRejected(RejectCode.ENCODING_UNSUPPORTED) from exc
        return Encoding("utf-16", False)
    if data.startswith(codecs.BOM_UTF8):
        try:
            data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise FileRejected(RejectCode.ENCODING_UNSUPPORTED) from exc
        return Encoding("utf-8-sig", False)
    try:
        data.decode("utf-8")
        return Encoding("utf-8", False)
    except UnicodeDecodeError:
        pass
    try:
        data.decode("cp1252")
    except UnicodeDecodeError as exc:
        raise FileRejected(RejectCode.ENCODING_UNSUPPORTED) from exc
    return Encoding("cp1252", True)


def check_text(text: str) -> None:
    """Text-only content: no control characters other than tab/CR/LF, and no
    absurd physical line (a binary blob masquerading as one line)."""
    for ch in text:
        o = ord(ch)
        if (o < 32 and ch not in "\t\r\n") or o == 0x7F:
            raise FileRejected(RejectCode.CONTENT_BINARY)
    longest = max((len(line) for line in text.splitlines()), default=0)
    if longest > MAX_LINE_BYTES:
        raise FileRejected(RejectCode.CONTENT_BINARY)
