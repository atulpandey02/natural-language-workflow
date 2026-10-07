"""Review (adversarial): the strict profiler must give the SAME answer however
the byte stream is chunked. Chunk boundaries may split a BOM, a file signature,
a multi-byte UTF-8 character, a quoted field or a row; none of that may change
the profile or the rejection code."""

import codecs
import io

import pytest

from nlw.ingest.strict import PolicyReject, StrictLimits, profile_stream


class Chunked(io.RawIOBase):
    """A stream that never returns more than ``step`` bytes per read."""

    def __init__(self, data: bytes, step: int) -> None:
        self._data = data
        self._pos = 0
        self._step = step

    def readable(self) -> bool:
        return True

    def read(self, n: int | None = -1) -> bytes:
        size = self._step if n is None or n < 0 else min(n, self._step)
        out = self._data[self._pos : self._pos + size]
        self._pos += len(out)
        return out


STEPS = (1, 2, 3, 5, 7, 64, 1 << 20)


def _outcome(data: bytes, step: int, limits: StrictLimits | None = None) -> str:
    try:
        return profile_stream(Chunked(data, step), limits).model_dump_json()  # type: ignore[arg-type]
    except PolicyReject as exc:
        return f"REJECT:{exc.code}"


def _same_everywhere(data: bytes, limits: StrictLimits | None = None) -> str:
    outcomes = {step: _outcome(data, step, limits) for step in STEPS}
    assert len(set(outcomes.values())) == 1, outcomes
    return outcomes[STEPS[-1]]


def test_a_valid_file_profiles_identically_for_every_chunking() -> None:
    body = "région,montant,note\n" + "".join(
        f"Zürich-{i},{i}.5,{'=1+1' if i % 5 == 0 else 'ok'}\n" for i in range(200)
    )
    for data in (body.encode(), codecs.BOM_UTF8 + body.encode()):
        out = _same_everywhere(data)
        assert out.startswith("{")
    assert '"encoding":"utf-8-sig"' in _same_everywhere(codecs.BOM_UTF8 + body.encode())


@pytest.mark.parametrize(
    "data,code",
    [
        (b"PK\x03\x04" + b"\x00" * 64, "FILE_TYPE"),
        (b"SQLite format 3\x00" + b"x" * 64, "FILE_TYPE"),
        (b"%PDF-1.7\n" + b"x" * 64, "FILE_TYPE"),
        (codecs.BOM_UTF16_LE + "a,b\n1,2\n".encode("utf-16-le"), "ENCODING_UNSUPPORTED"),
        (codecs.BOM_UTF16_BE + "a,b\n1,2\n".encode("utf-16-be"), "ENCODING_UNSUPPORTED"),
    ],
)
def test_signatures_and_boms_are_detected_whatever_the_chunking(data: bytes, code: str) -> None:
    assert _same_everywhere(data) == f"REJECT:{code}"


def test_multibyte_characters_split_across_chunks_are_accepted() -> None:
    # 2-, 3- and 4-byte characters at every possible split position.
    data = ("a,b\n" + "".join(f"é{i},€{i}𝄞\n" for i in range(50))).encode()
    assert _same_everywhere(data).startswith("{")


@pytest.mark.parametrize(
    "bad",
    [
        b"\xc3",  # truncated 2-byte sequence at EOF
        b"\xe2\x82",  # truncated 3-byte sequence at EOF
        b"\xc3\x28",  # invalid continuation byte
        b"\xed\xa0\x80",  # UTF-16 surrogate encoded in UTF-8
        b"\xf8\x88\x80\x80\x80",  # 5-byte form
    ],
)
def test_malformed_utf8_is_refused_across_chunk_boundaries(bad: bytes) -> None:
    for where in (b"a,b\n" + bad + b",1\n", b"a,b\nx,1\n" + bad):
        assert _same_everywhere(where) == "REJECT:ENCODING_UNSUPPORTED"


def test_field_length_limit_is_exact_across_chunks() -> None:
    limits = StrictLimits(max_field_chars=10)
    ok = b"a,b\n" + b"x" * 10 + b",1\n"
    quoted_ok = b'a,b\n"' + b"y" * 10 + b'",1\n'
    over = b"a,b\n" + b"x" * 11 + b",1\n"
    quoted_over = b'a,b\n"' + b"y\n" * 5 + b'z",1\n'  # 11 characters incl. newlines
    assert _same_everywhere(ok, limits).startswith("{")
    assert _same_everywhere(quoted_ok, limits).startswith("{")
    assert _same_everywhere(over, limits) == "REJECT:FIELD_TOO_LARGE"
    assert _same_everywhere(quoted_over, limits) == "REJECT:FIELD_TOO_LARGE"


def test_row_column_and_byte_limits_are_exact_across_chunks() -> None:
    rows = b"a\n" + b"1\n" * 5
    assert _same_everywhere(rows, StrictLimits(max_rows=5)).startswith("{")
    assert _same_everywhere(rows, StrictLimits(max_rows=4)) == "REJECT:TOO_MANY_ROWS"
    cols = (",".join(f"c{i}" for i in range(4)) + "\n1,2,3,4\n").encode()
    assert _same_everywhere(cols, StrictLimits(max_columns=4)).startswith("{")
    assert _same_everywhere(cols, StrictLimits(max_columns=3)) == "REJECT:TOO_MANY_COLUMNS"
    assert _same_everywhere(rows, StrictLimits(max_bytes=len(rows))).startswith("{")
    assert _same_everywhere(rows, StrictLimits(max_bytes=len(rows) - 1)) == (
        "REJECT:FILE_TOO_LARGE"
    )


def test_a_nul_byte_in_any_chunk_is_refused() -> None:
    data = b"a,b\n" + b"1,2\n" * 30 + b"3,\x004\n"
    assert _same_everywhere(data) == "REJECT:CONTENT_BINARY"


# --- control characters (one rule; see nlw.ingest.strict._CONTROL) -----------------------


@pytest.mark.parametrize("ch", ["\u0080", "\u0085", "\u009f", "\x07", "\x1b", "\x7f"])
def test_c0_c1_and_del_are_refused_in_cells_and_headers_across_chunks(ch: str) -> None:
    cell = f"a,b\nx{ch}y,1\n".encode()
    header = f"a{ch}b,c\n1,2\n".encode()
    assert _same_everywhere(cell) == "REJECT:CONTENT_BINARY"
    assert _same_everywhere(header) == "REJECT:CONTENT_BINARY"


@pytest.mark.parametrize("ch", ["\t", "\n", "\r", "​", "‮", "﻿"])
def test_headers_refuse_structure_and_format_characters(ch: str) -> None:
    data = f'"a{ch}b",c\n1,2\n'.encode()
    assert _same_everywhere(data) == "REJECT:HEADER_INVALID"


def test_cells_keep_tab_and_quoted_line_breaks_and_ordinary_unicode() -> None:
    data = 'name,note\n"Zoë\tN.","line1\r\nline2"\n中文名,😀 ok\n'.encode()
    out = _same_everywhere(data)
    assert out.startswith("{") and '"row_count":2' in out
    headers = "Größe,Ünïcödé 名前,emoji😀\n1,2,3\n".encode()
    assert _same_everywhere(headers).startswith("{")
