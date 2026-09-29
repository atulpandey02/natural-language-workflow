"""B04 library layer: hostile-file refusal, bounded deterministic profiling,
sensitivity detection and the profile-1 redaction contract."""

import codecs

import pytest
from pydantic import ValidationError

from nlw.ingest.profile import Limits, dedupe_names, infer_type, normalise_header, profile_csv
from nlw.ingest.schema import ColumnProfile, SensitivityFlag
from nlw.ingest.validate import FileRejected, RejectCode


def _code(data: bytes, limits: Limits | None = None) -> RejectCode:
    with pytest.raises(FileRejected) as exc:
        profile_csv(data, limits=limits)
    return exc.value.code


@pytest.mark.parametrize(
    "data",
    [
        b"PK\x03\x04" + b"\x00" * 40,  # zip / xlsx
        b"%PDF-1.7\n1 0 obj",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 20,  # OLE / xls
        b"MZ\x90\x00\x03\x00\x00\x00",  # PE
        b"\x7fELF\x02\x01\x01",
        b"\x1f\x8b\x08\x00",
        b"PAR1" + b"\x00" * 10,
        b"a,b\n1,\x002\n",  # NUL byte without a UTF-16 BOM
    ],
)
def test_hostile_files_are_refused_as_file_type(data: bytes) -> None:
    assert _code(data) == RejectCode.FILE_TYPE


def test_control_characters_are_content_binary() -> None:
    assert _code(b"a,b\n1,\x07bell\n") == RejectCode.CONTENT_BINARY


def test_empty_and_too_large() -> None:
    assert _code(b"") == RejectCode.FILE_EMPTY
    assert _code(b"a\n" * 10, Limits(max_bytes=5)) == RejectCode.FILE_TOO_LARGE


def test_row_column_and_field_limits() -> None:
    assert _code(b"a\n" + b"1\n" * 20, Limits(max_rows=10)) == RejectCode.TOO_MANY_ROWS
    wide = (",".join(f"c{i}" for i in range(6)) + "\n").encode()
    assert _code(wide + wide, Limits(max_columns=5)) == RejectCode.TOO_MANY_COLUMNS
    assert (
        _code(b"a\n" + b"x" * 100 + b"\n", Limits(max_field_chars=50)) == RejectCode.FIELD_TOO_LARGE
    )


def test_utf16_with_bom_is_accepted_and_utf32_refused() -> None:
    data = codecs.BOM_UTF16_LE + "name,count\nx,1\n".encode("utf-16-le")
    p = profile_csv(data)
    assert p.encoding == "utf-16" and p.row_count == 1
    assert _code(codecs.BOM_UTF32_LE + b"a\x00\x00\x00") == RejectCode.ENCODING_UNSUPPORTED


def test_windows_1252_needs_confirmation() -> None:
    p = profile_csv("site,label\nA,caf\xe9\n".encode("cp1252"))
    assert p.encoding == "cp1252" and p.encoding_needs_confirmation
    assert "ENCODING_NEEDS_CONFIRMATION" in p.warnings


@pytest.mark.parametrize(("sep", "name"), [(b";", ";"), (b"\t", "\t"), (b"|", "|")])
def test_delimiter_sniffing(sep: bytes, name: str) -> None:
    data = sep.join([b"a", b"b"]) + b"\n" + sep.join([b"1", b"2"]) + b"\n"
    assert profile_csv(data * 1).delimiter == name


def test_header_normalisation_and_duplicates() -> None:
    assert normalise_header("  Open Shifts (#) ", 0) == "open_shifts"
    assert normalise_header("2024 Q1", 3) == "_2024_q1"
    assert normalise_header("Café Område", 0) == "cafe_omrade"
    assert normalise_header("!!!", 4) == "col_5"
    assert dedupe_names(["a", "a", "b", "a"])[0] == ["a", "a_2", "b", "a_3"]
    p = profile_csv(b"Site,site,SITE\nx,y,z\n")
    assert [c.name for c in p.columns] == ["site", "site_2", "site_3"]
    assert "DUPLICATE_HEADER_RENAMED" in p.warnings


def test_no_header_detected_when_first_row_is_data() -> None:
    p = profile_csv(b"1,2026-01-01\n2,2026-01-02\n")
    assert not p.header_row and p.row_count == 2
    assert [c.name for c in p.columns] == ["col_1", "col_2"]


def test_type_inference_goldens() -> None:
    assert infer_type(["1", "2", "-3"])[0] == "integer"
    assert infer_type(["1.5", "2", "3e2"])[0] == "decimal"
    assert infer_type(["true", "no", "Y"])[0] == "boolean"
    assert infer_type(["2026-01-01", "2026-02-28"])[0] == "date"
    assert infer_type(["2026-01-01T10:00:00Z", "2026-01-01 11:30"])[0] == "timestamp"
    # 03/04/2026 cannot be told apart: string, with a warning, never guessed.
    t, _, w = infer_type(["03/04/2026", "05/06/2026"])
    assert (t, w) == ("string", ["DATE_FORMAT_AMBIGUOUS"])
    t2, _, w2 = infer_type(["13/04/2026", "05/06/2026"])
    assert (t2, w2) == ("string", ["DATE_FORMAT_UNCONFIRMED"])
    values = [str(i) for i in range(99)] + ["n/a-ish"]
    assert infer_type(values)[:2] == ("integer", 1)


def test_nulls_and_formula_census() -> None:
    p = profile_csv(b"a,b\nNULL,=SUM(A1)\nN/A,+1+1\n,-\n4,@cmd\n")
    a, b = p.columns
    assert (a.null_count, a.non_null_count) == (3, 1)
    assert p.formula_prefix_count == 3  # "-" alone is a null token
    assert "FORMULA_PREFIX_CELLS" in p.warnings


def test_sensitivity_detectors_and_redaction() -> None:
    rows = [b"ssn,card,contact,phone,zip,notes,site"]
    long_note = "x" * 45
    for i in range(20):
        rows.append(
            f"123-45-{6000 + i},4111 1111 1111 1111,p{i}@clinic.org,+1 415 555 {1000 + i},"
            f"94107-{1000 + i},{long_note}{i},S{i % 3}".encode()
        )
    p = profile_csv(b"\n".join(rows) + b"\n")
    by = {c.name: c for c in p.columns}
    assert {(f.kind, f.treatment, f.hard) for f in by["ssn"].sensitivity} == {
        ("ssn", "EXCLUDE", True)
    }
    assert any(f.kind == "card_number" and f.hard for f in by["card"].sensitivity)
    assert [f.kind for f in by["contact"].sensitivity] == ["email"]
    assert [f.kind for f in by["phone"].sensitivity] == ["phone"]
    assert [f.kind for f in by["zip"].sensitivity] == ["postal_code"]
    assert [f.kind for f in by["notes"].sensitivity] == ["free_text"]
    assert by["site"].sensitivity == [] and by["site"].sample_values == ["S0", "S1", "S2"]
    for name in ("ssn", "card", "contact", "phone", "zip", "notes"):
        c = by[name]
        assert c.sample_values == [] and c.min_value is None and c.max_value is None
    blob = p.model_dump_json()
    for fragment in ("123-45-", "4111", "@clinic.org", "555", "94107", "xxxxx"):
        assert fragment not in blob


def test_high_cardinality_columns_carry_no_samples() -> None:
    body = b"\n".join(f"{i},site{i}".encode() for i in range(60))
    p = profile_csv(b"id,site\n" + body + b"\n")
    assert all(c.sample_values == [] for c in p.columns)


def test_profile_is_deterministic() -> None:
    data = b"Facility,Date,Open\nMercy,2026-09-01,3\nWest,2026-09-02,5\n"
    assert profile_csv(data).model_dump_json() == profile_csv(data).model_dump_json()


def test_contract_rejects_extra_fields_and_samples_on_flagged_columns() -> None:
    flag = SensitivityFlag(kind="email", source="header", treatment="IDENTIFIER")
    base = {
        "position": 0,
        "raw_header": "Email",
        "name": "email",
        "inferred_type": "string",
        "null_count": 0,
        "non_null_count": 1,
        "distinct_count": 1,
    }
    with pytest.raises(ValidationError):
        ColumnProfile.model_validate({**base, "sensitivity": [flag], "sample_values": ["a@b.co"]})
    with pytest.raises(ValidationError):
        ColumnProfile.model_validate({**base, "sensitivity": [flag], "min_value": "a"})
    with pytest.raises(ValidationError):
        ColumnProfile.model_validate({**base, "rows": [["a"]]})
    with pytest.raises(ValidationError):
        ColumnProfile.model_validate({**base, "distinct_count": 51, "sample_values": ["x"]})
