"""``semantics-1`` (ADR-030): closed vocabularies, no executable content, and
validation against the version's profile."""

from typing import Any

import pytest

from nlw.datasets.semantics import (
    COMPATIBLE_ROLES,
    COMPATIBLE_TYPES,
    SemanticMappingError,
    canonical_json,
    validate_mapping,
)

PROFILE = {
    "columns": [
        {"name": "region", "inferred_type": "string", "indicators": []},
        {"name": "amount", "inferred_type": "decimal", "indicators": []},
        {"name": "order_date", "inferred_type": "date", "indicators": []},
        {"name": "email", "inferred_type": "string", "indicators": ["possible_email"]},
        {"name": "card", "inferred_type": "string", "indicators": ["possible_payment_card"]},
    ]
}


def _col(
    name: str, semantic_type: str, role: str, allowed: bool = True, **kw: Any
) -> dict[str, Any]:
    return {
        "name": name,
        "label": kw.pop("label", name.title()),
        "semantic_type": semantic_type,
        "role": role,
        "analysis_allowed": allowed,
        **kw,
    }


def _good() -> dict[str, Any]:
    return {
        "columns": [
            _col("region", "category", "dimension"),
            _col("amount", "currency", "measure"),
            _col("order_date", "date", "timestamp"),
            _col("email", "contact", "identifier"),
            _col("card", "identifier", "identifier", allowed=False),
        ]
    }


def test_a_valid_mapping_is_accepted_and_serialized_deterministically() -> None:
    a = validate_mapping(_good(), PROFILE)
    b = validate_mapping(_good(), PROFILE)
    assert canonical_json(a) == canonical_json(b)
    assert '"contract_version":"semantics-1"' in canonical_json(a)


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda m: m["columns"].pop(), "SEMANTICS_COLUMNS_MISMATCH"),
        (lambda m: m["columns"].reverse(), "SEMANTICS_COLUMNS_MISMATCH"),
        (
            lambda m: m["columns"].append(_col("extra", "text", "attribute")),
            "SEMANTICS_COLUMNS_MISMATCH",
        ),
        (lambda m: m["columns"][1].update(semantic_type="date"), "SEMANTICS_TYPE_INCOMPATIBLE"),
        (lambda m: m["columns"][0].update(role="measure"), "SEMANTICS_ROLE_INCOMPATIBLE"),
        (lambda m: m["columns"][4].update(analysis_allowed=True), "SEMANTICS_SENSITIVE_COLUMN"),
        (lambda m: m["columns"][3].update(role="attribute"), "SEMANTICS_SENSITIVE_COLUMN"),
        (lambda m: m["columns"][0].update(semantic_type="sql"), "SEMANTICS_INVALID"),
        (lambda m: m["columns"][0].update(expression="SELECT 1"), "SEMANTICS_INVALID"),
        (lambda m: m["columns"][0].update(label="=HYPERLINK(1)"), "SEMANTICS_INVALID"),
        (lambda m: m["columns"][0].update(label="a\x07b"), "SEMANTICS_INVALID"),
        (lambda m: m["columns"][0].update(label="x" * 81), "SEMANTICS_INVALID"),
        (lambda m: m["columns"][0].update(label="   "), "SEMANTICS_INVALID"),
        (lambda m: m.update(columns=[]), "SEMANTICS_INVALID"),
        (lambda m: m.update(contract_version="semantics-9"), "SEMANTICS_INVALID"),
    ],
)
def test_invalid_mappings_are_refused_with_stable_codes(mutate: Any, code: str) -> None:
    m = _good()
    mutate(m)
    with pytest.raises(SemanticMappingError) as exc:
        validate_mapping(m, PROFILE)
    assert exc.value.code == code


def test_hard_excluded_columns_can_never_be_analysed_whatever_the_label() -> None:
    m = _good()
    m["columns"][4].update(label="Totally safe column", analysis_allowed=True)
    with pytest.raises(SemanticMappingError, match="cannot be analysed"):
        validate_mapping(m, PROFILE)


def test_labels_are_normalized_inert_text() -> None:
    m = _good()
    m["columns"][0]["label"] = "  Sales   Region  "
    out = validate_mapping(m, PROFILE)
    assert out.columns[0].label == "Sales Region"


def test_every_semantic_type_has_roles_and_fits_some_primitive_type() -> None:
    reachable = set().union(*COMPATIBLE_TYPES.values())
    assert reachable == set(COMPATIBLE_ROLES)
    assert all(COMPATIBLE_ROLES[t] for t in COMPATIBLE_ROLES)


@pytest.mark.parametrize("ch", ["\u0080", "\u0085", "\u009f", "\x07", "‮", "​"])
def test_c0_c1_and_format_characters_are_refused_in_labels_and_descriptions(ch: str) -> None:
    for field in ("label", "description"):
        m = _good()
        m["columns"][0][field] = f"Sales{ch}Region"
        with pytest.raises(SemanticMappingError):
            validate_mapping(m, PROFILE)


def test_ordinary_unicode_labels_are_accepted() -> None:
    m = _good()
    m["columns"][0]["label"] = "Région 地域 😀"
    assert validate_mapping(m, PROFILE).columns[0].label == "Région 地域 😀"
