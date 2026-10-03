"""Dataset lifecycle rules (ADR-029): pure, deterministic, no database.

The Python tables must equal the migration's (the database enforces the same
rules for every role); metadata normalization refuses hostile input with stable
codes; the API contract cannot carry server-owned fields; the flag that mounts
the metadata routes is refused in staging and production.
"""

import importlib.util
import math
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from nlw.api.schemas import DatasetCreate, DatasetVersionOut
from nlw.core.config import Settings
from nlw.datasets import lifecycle as lc
from nlw.ingest.validate import RejectCode

ROOT = Path(__file__).resolve().parents[2]


def _migration() -> Any:
    path = ROOT / "migrations/versions/0024_dataset_lifecycle.py"
    spec = importlib.util.spec_from_file_location("m0024", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["m0024"] = module
    spec.loader.exec_module(module)
    return module


# --- the Python rules equal the database rules --------------------------------


def test_state_vocabularies_match_the_migration() -> None:
    m = _migration()
    assert tuple(s.value for s in lc.DatasetStatus) == m.DATASET_STATES
    assert tuple(s.value for s in lc.VersionStatus) == m.VERSION_STATES
    assert tuple(c.value for c in lc.RejectionCode) == m.REJECTION_CODES
    assert tuple(e.value for e in lc.EventType) == m.EVENT_TYPES
    assert {r.value for r in lc.ReasonCode} | {c.value for c in lc.RejectionCode} == set(
        m.REASON_CODES
    )
    assert m.MAX_DECLARED_SIZE_BYTES == lc.MAX_DECLARED_SIZE_BYTES


def test_version_transition_table_matches_the_migration_trigger() -> None:
    m = _migration()
    db = {src: set(dsts) for src, dsts in m._VERSION_TRANSITIONS.items()}
    py = {src.value: {d.value for d in dsts} for src, dsts in lc.VERSION_TRANSITIONS.items()}
    assert py == db


def test_every_state_pair_is_decided_by_the_table() -> None:
    allowed = {
        ("QUARANTINED", "PROFILING"),
        ("QUARANTINED", "REJECTED"),
        ("QUARANTINED", "DELETING"),
        ("PROFILING", "PROFILED"),
        ("PROFILING", "REJECTED"),
        ("PROFILING", "DELETING"),
        ("PROFILED", "ACTIVE"),
        ("PROFILED", "REJECTED"),
        ("PROFILED", "DELETING"),
        ("ACTIVE", "SUPERSEDED"),
        ("ACTIVE", "DELETING"),
        ("SUPERSEDED", "DELETING"),
        ("REJECTED", "DELETING"),
        ("DELETING", "DELETED"),
    }
    for src in lc.VersionStatus:
        for dst in lc.VersionStatus:
            assert lc.version_transition_allowed(src, dst) == ((src.value, dst.value) in allowed)
    assert lc.VERSION_TRANSITIONS[lc.VersionStatus.DELETED] == frozenset()


def test_dataset_transitions_are_one_way() -> None:
    S = lc.DatasetStatus
    assert lc.dataset_transition_allowed(S.ACTIVE, S.DELETING)
    assert lc.dataset_transition_allowed(S.DELETING, S.DELETED)
    for src, dst in [
        (S.DELETING, S.ACTIVE),
        (S.DELETED, S.ACTIVE),
        (S.DELETED, S.DELETING),
        (S.ACTIVE, S.DELETED),
    ]:
        assert not lc.dataset_transition_allowed(src, dst)


def test_every_transition_target_has_an_event() -> None:
    targets = {d for dsts in lc.VERSION_TRANSITIONS.values() for d in dsts}
    assert targets == set(lc.VERSION_EVENT_FOR)


def test_rejection_codes_cover_every_ingest_reject_code() -> None:
    assert {c.value for c in RejectCode} <= {c.value for c in lc.RejectionCode}


# --- names --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "display", "key"),
    [
        ("Sales", "Sales", "sales"),
        ("  Sales   2026  ", "Sales 2026", "sales 2026"),
        ("Ｓａｌｅｓ", "Sales", "sales"),  # fullwidth -> NFKC
        ("Straße", "Straße", "strasse"),  # case-fold for uniqueness
        ("a" * 100, "a" * 100, "a" * 100),
        ("Sales\tQ1", "Sales Q1", "sales q1"),  # whitespace collapses
    ],
)
def test_names_are_normalized(raw: str, display: str, key: str) -> None:
    assert lc.normalize_name(raw) == (display, key)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "a" * 101,
        "evil\x00name",
        "bell\x07",
        "rtl\u202eoverride",  # bidi override
        "zero\u200bwidth",  # zero-width space
        "del\x7f",
    ],
)
def test_hostile_names_are_refused_with_a_stable_code(raw: str) -> None:
    with pytest.raises(lc.MetadataError) as exc:
        lc.normalize_name(raw)
    assert exc.value.code == "DATASET_NAME_INVALID"


def test_descriptions_are_bounded_and_may_hold_newlines() -> None:
    assert lc.normalize_description(None) is None
    assert lc.normalize_description("   ") is None
    assert lc.normalize_description(" line one\nline two ") == "line one\nline two"
    assert lc.normalize_description("x" * 500) == "x" * 500
    for bad in ("x" * 501, "a\x00b", "a\u202eb"):
        with pytest.raises(lc.MetadataError) as exc:
            lc.normalize_description(bad)
        assert exc.value.code == "DATASET_DESCRIPTION_INVALID"


# --- filenames ----------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "../../etc/passwd",
        "..",
        ".",
        "dir/file.csv",
        "C:\\Users\\x.csv",
        "\\\\server\\share.csv",
        "file\x00.csv",
        "new\nline.csv",
        "spoof\u202evsc.csv",
        "",
        "   ",
        "a" * 256,
    ],
)
def test_hostile_filenames_are_refused(raw: str) -> None:
    with pytest.raises(lc.MetadataError) as exc:
        lc.sanitize_filename(raw)
    assert exc.value.code == "DATASET_FILENAME_INVALID"


def test_plain_filenames_are_kept_and_nfc_normalized() -> None:
    assert lc.sanitize_filename("  sales 2026.csv ") == "sales 2026.csv"
    decomposed = "cafe\u0301.csv"
    assert lc.sanitize_filename(decomposed) == "caf\u00e9.csv"
    assert lc.sanitize_filename("a" * 255) == "a" * 255


# --- sizes and media types ----------------------------------------------------


@pytest.mark.parametrize("size", [1, 25_000_000])
def test_declared_size_bounds_accept(size: int) -> None:
    assert lc.validate_declared_size(size) == size


@pytest.mark.parametrize("size", [0, -1, 25_000_001, 10**30, True, 1.5, math.inf, math.nan, "10"])
def test_declared_size_rejects_out_of_contract_values(size: object) -> None:
    with pytest.raises(lc.MetadataError) as exc:
        lc.validate_declared_size(size)
    assert exc.value.code == "DATASET_SIZE_INVALID"


def test_only_csv_media_type() -> None:
    assert lc.validate_media_type("text/csv") == "text/csv"
    for bad in ("text/plain", "application/vnd.ms-excel", "TEXT/CSV", "text/csv; charset=x"):
        with pytest.raises(lc.MetadataError):
            lc.validate_media_type(bad)


# --- API contracts --------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        {"tenant_id": "00000000-0000-0000-0000-000000000001"},
        {"created_by": "00000000-0000-0000-0000-000000000001"},
        {"status": "ACTIVE"},
        {"active_version_id": "00000000-0000-0000-0000-000000000001"},
        {"metadata": {"anything": "goes"}},
    ],
)
def test_create_contract_refuses_server_owned_fields(extra: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        DatasetCreate.model_validate({"name": "Sales", **extra})


def test_create_contract_bounds_raw_input() -> None:
    DatasetCreate(name="a" * 200, description="d" * 1000)
    for bad in ({"name": ""}, {"name": "a" * 201}, {"name": "x", "description": "d" * 1001}):
        with pytest.raises(ValidationError):
            DatasetCreate.model_validate(bad)


def test_version_output_never_carries_a_storage_location() -> None:
    fields = set(DatasetVersionOut.model_fields)
    assert not {f for f in fields if "storage" in f or "url" in f or "path" in f or "key" in f}


# --- configuration ------------------------------------------------------------


@pytest.mark.parametrize("env", ["staging", "production"])
def test_metadata_api_flag_is_refused_where_customers_are(env: str) -> None:
    with pytest.raises(ValidationError, match="DATASETS_API_ENABLED is not allowed"):
        Settings(_env_file=None, app_env=env, datasets_api_enabled=True)  # type: ignore[call-arg, arg-type]


def test_metadata_api_flag_defaults_off_and_is_allowed_locally() -> None:
    assert Settings(_env_file=None).datasets_api_enabled is False  # type: ignore[call-arg]
    assert Settings(_env_file=None, app_env="local", datasets_api_enabled=True).datasets_api_enabled  # type: ignore[call-arg]
