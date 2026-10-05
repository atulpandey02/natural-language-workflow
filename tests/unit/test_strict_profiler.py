"""Strict pilot CSV policy and ``profile-2`` (ADR-030): pure, deterministic, bounded.

Every refusal is a stable lifecycle rejection code; boundaries are tested at
exactly the limit and one past it; the profile carries no sample values and no
values at all for columns with a sensitivity indicator.
"""

import codecs
import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import tracemalloc

import pytest

from nlw.ingest.strict import (
    DISTINCT_LIMIT,
    PolicyReject,
    Profile2,
    StrictLimits,
    neutralize_formula,
    profile_bytes,
    profile_stream,
)


def _code(data: bytes, limits: StrictLimits | None = None) -> str:
    with pytest.raises(PolicyReject) as exc:
        profile_bytes(data, limits)
    return str(exc.value.code)


def _csv(header: str, rows: list[str]) -> bytes:
    return ("\n".join([header, *rows]) + "\n").encode()


# --- refusals --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data,code",
    [
        (b"", "FILE_EMPTY"),
        (codecs.BOM_UTF8, "FILE_EMPTY"),
        (b"a,b\n", "NO_DATA_ROWS"),
        (b"a,b\r\n", "NO_DATA_ROWS"),
        (b"\n1,2\n", "HEADER_INVALID"),  # a blank first line is not a header
        (b"a,\n1,2\n", "HEADER_INVALID"),
        (b"a, \n1,2\n", "HEADER_INVALID"),
        (b"1,2\n3,4\n", "HEADER_INVALID"),  # numbers: a data row, not a header
        (b"name,2024-01-01\nx,1\n", "HEADER_INVALID"),
        (b"a,A\n1,2\n", "HEADER_DUPLICATE"),
        (b"Order ID,order-id\n1,2\n", "HEADER_DUPLICATE"),  # equal after normalization
        (b"a,b\n1\n", "ROW_WIDTH_MISMATCH"),
        (b"a,b\n1,2,3\n", "ROW_WIDTH_MISMATCH"),
        (b"a,b\n1,2\n\n3,4\n", "ROW_WIDTH_MISMATCH"),  # blank lines are not rows
        (b'a,b\n1,"x\n', "PARSE_ERROR"),  # unterminated quote
        (b'a,b\n1,"x"y\n', "PARSE_ERROR"),  # data after a closing quote
        (b"a,b\n1,\x002\n", "CONTENT_BINARY"),
        (b"a,b\n1,\x072\n", "CONTENT_BINARY"),
        (b"a,b\n1,\x7f\n", "CONTENT_BINARY"),
        (codecs.BOM_UTF16_LE + "a,b\n1,2\n".encode("utf-16-le"), "ENCODING_UNSUPPORTED"),
        (codecs.BOM_UTF16_BE + "a,b\n1,2\n".encode("utf-16-be"), "ENCODING_UNSUPPORTED"),
        ("a,b\n\u00e9,1\n".encode("cp1252"), "ENCODING_UNSUPPORTED"),
        (b"a,b\n\xc3\x28,1\n", "ENCODING_UNSUPPORTED"),  # invalid UTF-8
        (b"PK\x03\x04" + b"\x00" * 20, "FILE_TYPE"),  # zip / xlsx
        (b"\x1f\x8b\x08" + b"\x00" * 20, "FILE_TYPE"),  # gzip
        (b"%PDF-1.7\n", "FILE_TYPE"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "FILE_TYPE"),  # xls
        (b"PAR1" + b"\x00" * 8, "FILE_TYPE"),  # parquet
        (b"SQLite format 3\x00", "FILE_TYPE"),
    ],
)
def test_policy_violations_are_refused_with_stable_codes(data: bytes, code: str) -> None:
    assert _code(data) == code


def test_header_cells_are_bounded() -> None:
    assert profile_bytes(_csv("x" * 256, ["1"])).columns[0].name.startswith("x")
    assert _code(_csv("x" * 257, ["1"])) == "HEADER_INVALID"


def test_byte_limit_is_exact() -> None:
    data = _csv("a", ["1"] * 10)
    assert profile_bytes(data, StrictLimits(max_bytes=len(data))).row_count == 10
    assert _code(data, StrictLimits(max_bytes=len(data) - 1)) == "FILE_TOO_LARGE"


def test_row_limit_is_exact() -> None:
    data = _csv("a", ["1"] * 5)
    assert profile_bytes(data, StrictLimits(max_rows=5)).row_count == 5
    assert _code(data, StrictLimits(max_rows=4)) == "TOO_MANY_ROWS"


def test_column_limit_is_exact() -> None:
    header = ",".join(f"c{i}" for i in range(7))
    data = _csv(header, [",".join("1" * 7)])
    assert profile_bytes(data, StrictLimits(max_columns=7)).column_count == 7
    assert _code(data, StrictLimits(max_columns=6)) == "TOO_MANY_COLUMNS"


def test_field_limit_is_exact_and_the_global_csv_limit_is_restored() -> None:
    before = csv.field_size_limit()
    ok = _csv("a", ["x" * 100])
    assert profile_bytes(ok, StrictLimits(max_field_chars=100)).row_count == 1
    assert _code(_csv("a", ["x" * 101]), StrictLimits(max_field_chars=100)) == "FIELD_TOO_LARGE"
    assert _code(_csv("a", ['"' + "x" * 101 + '"']), StrictLimits(max_field_chars=100)) == (
        "FIELD_TOO_LARGE"
    )
    assert csv.field_size_limit() == before


def test_the_wall_clock_is_enforced() -> None:
    ticks = iter(range(0, 10_000_000, 1))

    def clock() -> float:
        return float(next(ticks)) * 10.0  # every call advances 10 s

    data = _csv("a", ["1"] * 3000)
    with pytest.raises(PolicyReject) as exc:
        profile_stream(io.BytesIO(data), StrictLimits(timeout_s=5), clock=clock)
    assert exc.value.code == "PARSE_TIMEOUT"


# --- accepted shapes -------------------------------------------------------------------


def test_utf8_bom_crlf_and_quoted_fields_are_accepted() -> None:
    data = codecs.BOM_UTF8 + b'name,note\r\n"Smith, J","line1\nline2"\r\nLee,ok\r\n'
    p = profile_bytes(data)
    assert (p.encoding, p.row_count, p.column_count) == ("utf-8-sig", 2, 2)
    assert "UTF8_BOM" in p.warnings
    assert p.columns[0].header == "name" and p.columns[0].name == "name"


def test_header_normalization_is_deterministic() -> None:
    p = profile_bytes(_csv(" Order ID ,Café Name,2nd Value", ["1,x,2"]))
    assert [c.name for c in p.columns] == ["order_id", "cafe_name", "_2nd_value"]
    assert [c.header for c in p.columns] == ["Order ID", "Café Name", "2nd Value"]


def test_type_inference_follows_the_documented_order_and_threshold() -> None:
    rows = [f"{i},{i}.5,2024-01-{(i % 28) + 1:02d},2024-01-01T10:{i % 60:02d}:00Z,yes,x{i}"
            for i in range(100)]  # fmt: skip
    p = profile_bytes(_csv("i,d,dt,ts,b,s", rows))
    assert [c.inferred_type for c in p.columns] == [
        "integer", "decimal", "date", "timestamp", "boolean", "string",
    ]  # fmt: skip
    # 98 % threshold: 2 bad values in 100 still infer integer with 2 parse errors.
    mixed = profile_bytes(_csv("n", [str(i) for i in range(98)] + ["x", "y"]))
    col = mixed.columns[0]
    assert (col.inferred_type, col.parse_error_count) == ("integer", 2)
    assert "TYPE_PARTIAL_PARSE" in col.warnings
    # 3 bad values in 100: below the threshold -> string, no parse errors.
    assert (
        profile_bytes(_csv("n", [str(i) for i in range(97)] + ["x", "y", "z"]))
        .columns[0]
        .inferred_type
        == "string"
    )
    # Slash dates are never guessed.
    assert profile_bytes(_csv("d", ["01/02/2024", "03/04/2024"])).columns[0].inferred_type == (
        "string"
    )


def test_nulls_lengths_and_bounded_statistics() -> None:
    p = profile_bytes(_csv("amount,label", ["10,a", ",bb", "NULL,ccc", "20,", "30,dddd"]))
    amount, label = p.columns
    assert (amount.non_null_count, amount.null_count, amount.null_fraction) == (3, 2, 0.4)
    assert (amount.min_value, amount.max_value, amount.mean) == ("10", "30", 20.0)
    assert (label.min_length, label.max_length) == (1, 4)
    assert label.min_value is None and label.mean is None  # strings: no values at all


def test_distinct_counts_are_exact_up_to_the_limit_then_explicitly_over() -> None:
    exact = profile_bytes(_csv("v", [f"x{i}" for i in range(DISTINCT_LIMIT)]))
    assert (exact.columns[0].distinct_count, exact.columns[0].distinct_over_limit) == (
        DISTINCT_LIMIT,
        False,
    )
    over = profile_bytes(_csv("v", [f"x{i}" for i in range(DISTINCT_LIMIT + 1)]))
    assert (over.columns[0].distinct_count, over.columns[0].distinct_over_limit) == (None, True)


def test_sensitive_columns_carry_indicators_and_no_values() -> None:
    rows = [
        f"user{i}@example.test,+1 555 010 {i:04d},4111 1111 1111 1111,"
        f"123-45-{i:04d},{i},{(i % 10) * 3}"
        for i in range(30)
    ]
    p = profile_bytes(_csv("contact,tel,payment,national,customer_id,score", rows))
    by = {c.name: c for c in p.columns}
    assert "possible_email" in by["contact"].indicators
    assert "possible_phone" in by["tel"].indicators
    assert "possible_payment_card" in by["payment"].indicators
    assert "possible_national_id" in by["national"].indicators
    assert "identifier_like" in by["customer_id"].indicators
    for name in ("contact", "tel", "payment", "national", "customer_id"):
        c = by[name]
        assert (c.min_value, c.max_value, c.mean) == (None, None, None), name
    # Repeating values: no indicator, so its numeric bounds are shown.
    assert by["score"].indicators == [] and by["score"].max_value == "27"


def test_formula_like_cells_are_counted_and_headers_neutralized_never_evaluated() -> None:
    p = profile_bytes(_csv("=cmd|' /C calc'!A0,n", ["=1+1,-5", "@SUM(A1),+3", "ok,7"]))
    first, n = p.columns
    assert first.header == "'=cmd|' /C calc'!A0" and "HEADER_NEUTRALIZED" in first.warnings
    assert first.formula_like_count == 2 and "FORMULA_LIKE_VALUES" in first.warnings
    assert n.formula_like_count == 0  # signed numbers are numbers, not formulas
    assert p.formula_like_cells == 2 and "FORMULA_LIKE_CELLS" in p.warnings
    assert neutralize_formula("=A1") == "'=A1" and neutralize_formula("A1") == "A1"


def test_the_profile_holds_no_cell_values_beyond_numeric_and_temporal_bounds() -> None:
    secret = "zz-canary-value-7a1f"
    rows = [f"{secret}{i},{i}" for i in range(10)]
    dumped = profile_bytes(_csv("note,n", rows)).model_dump_json()
    assert secret not in dumped
    assert "sample" not in dumped


def test_the_same_bytes_give_a_byte_identical_profile() -> None:
    rows = [f"{i},{i * 1.25},r{i % 7},2024-02-{(i % 28) + 1:02d}" for i in range(500)]
    data = _csv("id,amount,region,day", rows)
    a, b = profile_bytes(data).model_dump_json(), profile_bytes(data).model_dump_json()
    assert a == b
    assert json.loads(a)["content_sha256"] == hashlib.sha256(data).hexdigest()
    assert json.loads(a)["size_bytes"] == len(data)


def test_golden_profile_is_stable() -> None:
    data = _csv("region,amount,day", ["north,1.50,2024-01-01", "south,2.25,2024-01-02", "north,,"])
    digest = hashlib.sha256(profile_bytes(data).model_dump_json().encode()).hexdigest()
    assert digest == GOLDEN


GOLDEN = "d24544d6a55333a49fcb062a0bee92e78d2b096db919daaf44e6f2aea49968bc"


def test_profile_contract_rejects_values_for_flagged_columns() -> None:
    p = profile_bytes(_csv("email", ["a@example.test"] * 3)).model_dump()
    p["columns"][0]["max_value"] = "a@example.test"
    with pytest.raises(ValueError):
        Profile2.model_validate(p)


def test_memory_is_bounded_by_accumulators_not_by_the_file() -> None:
    def peak(rows: int) -> int:
        data = _csv("a,b,c", [f"{i},v{i},{i * 0.5}" for i in range(rows)])
        tracemalloc.start()
        profile_stream(io.BytesIO(data))
        _, top = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return top

    small, large = peak(2_000), peak(60_000)
    # 30x the rows: the peak grows by far less (distinct sets cap at 1,000).
    assert large < small * 4


# --- the isolated process ----------------------------------------------------------------


def _run(data: bytes, extra_env: dict[str, str] | None = None, **cfg: object) -> dict[str, object]:
    limits = {
        "max_bytes": 25_000_000,
        "max_rows": 250_000,
        "max_columns": 200,
        "max_field_chars": 8192,
        "timeout_s": 30,
        "memory_mb": 768,
        **cfg,
    }
    env = {"PATH": os.environ.get("PATH", ""), **(extra_env or {})}
    proc = subprocess.run(
        [sys.executable, "-I", "-m", "nlw.ingest.runner", json.dumps(limits)],
        input=data,
        capture_output=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert proc.stderr == b""
    out: dict[str, object] = json.loads(proc.stdout.decode())
    return out


def test_runner_profiles_rejects_and_fails_without_content() -> None:
    ok = _run(_csv("a,b", ["1,x", "2,y"]))
    assert ok["status"] == "profiled"
    assert Profile2.model_validate(ok["profile"]).row_count == 2
    assert _run(b"a,a\n1,2\n") == {"status": "rejected", "code": "HEADER_DUPLICATE"}
    assert _run(b"a\n1\n", max_rows=0)["status"] == "failed"  # invalid limits: no detail


def test_runner_never_echoes_content_on_rejection() -> None:
    secret = b"zz-canary-in-a-bad-row"
    out = _run(b"a,b\n" + secret + b"\n")
    assert out == {"status": "rejected", "code": "ROW_WIDTH_MISMATCH"}


@pytest.mark.parametrize(
    "probe",
    [
        "socket.socket()",
        "socket.create_connection(('192.0.2.1', 80))",
        "socket.getaddrinfo('example.invalid', 80)",
    ],
)
def test_runner_process_has_no_network(probe: str) -> None:
    code = (
        "import socket, json, sys\n"
        "from nlw.ingest import runner\n"
        "runner._disable_network()\n"
        "try:\n"
        f"    {probe}\n"
        "    print('open')\n"
        "except OSError as e:\n"
        "    print('refused' if 'disabled' in str(e) else 'other')\n"
    )
    out = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=30, check=True
    )
    assert out.stdout.strip() == "refused"


def test_runner_rejects_oversized_input_from_the_stream() -> None:
    assert _run(_csv("a", ["1"] * 100), max_bytes=50) == {
        "status": "rejected",
        "code": "FILE_TOO_LARGE",
    }
