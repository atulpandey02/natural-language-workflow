"""Pin the web dataset journey to the API's dataset contracts.

The browser types (web/src/lib/api/types.ts) and the client rules
(web/src/lib/datasets.ts) restate the API's response fields, status literals,
closed semantic vocabularies, profile literals and rejection codes. A drift on
either side fails here instead of silently mis-rendering a state.
"""

from __future__ import annotations

import re
import typing
from pathlib import Path

from nlw.api import schemas
from nlw.datasets import semantics
from nlw.datasets.lifecycle import RejectionCode
from nlw.ingest import strict

ROOT = Path(__file__).resolve().parents[2]
TYPES = (ROOT / "web/src/lib/api/types.ts").read_text()
RULES = (ROOT / "web/src/lib/datasets.ts").read_text()


def _block(src: str, start: str) -> str:
    """The text from ``start`` to the end of its first ``{...}`` or ``;``."""
    i = src.index(start)
    brace = src.find("{", i)
    semi = src.find(";", i)
    if semi != -1 and (brace == -1 or semi < brace):
        return src[i:semi]
    depth = 0
    for j in range(brace, len(src)):
        depth += {"{": 1, "}": -1}.get(src[j], 0)
        if depth == 0:
            return src[i : j + 1]
    raise AssertionError(f"unterminated block {start!r}")


def _interface_fields(name: str) -> set[str]:
    body = _block(TYPES, f"export interface {name} ")
    return set(re.findall(r"^\s+([a-z0-9_]+)\??:", body, re.M))


def _union(name: str) -> set[str]:
    return set(re.findall(r'"([^"]+)"', _block(TYPES, f"export type {name} =")))


def _ts_set(src: str, name: str) -> set[str]:
    return set(re.findall(r'"([^"]+)"', _block(src, f"const {name} = new Set(")))


def _literal(tp: object) -> set[str]:
    return {str(a) for a in typing.get_args(tp)}


def test_response_fields_match_the_api_schemas() -> None:
    assert _interface_fields("DatasetOut") == set(schemas.DatasetOut.model_fields)
    assert _interface_fields("DatasetVersionOut") == set(schemas.DatasetVersionOut.model_fields)
    assert _interface_fields("SemanticRevisionOut") == set(schemas.SemanticRevisionOut.model_fields)
    assert _interface_fields("SemanticColumn") == set(schemas.SemanticColumnIn.model_fields)


def test_status_literals_match() -> None:
    assert _union("DatasetStatus") == _literal(schemas.DatasetOut.model_fields["status"].annotation)
    assert _union("VersionStatus") == _literal(
        schemas.DatasetVersionOut.model_fields["status"].annotation
    )


def test_semantic_vocabularies_match() -> None:
    assert _union("SemanticType") == _literal(semantics.SemanticType)
    assert _union("SemanticRole") == _literal(semantics.Role)
    for inferred, allowed in semantics.COMPATIBLE_TYPES.items():
        ts = _block(RULES, "export const COMPATIBLE_TYPES")
        row = re.search(rf"^\s+{inferred}: \[([^\]]*)\]", ts, re.M)
        assert row, inferred
        assert set(re.findall(r'"([^"]+)"', row.group(1))) == allowed, inferred
    roles = _block(RULES, "export const COMPATIBLE_ROLES")
    for sem_type, allowed in semantics.COMPATIBLE_ROLES.items():
        row = re.search(rf"^\s+{sem_type}: \[([^\]]*)\]", roles, re.M)
        assert row, sem_type
        assert set(re.findall(r'"([^"]+)"', row.group(1))) == allowed, sem_type
    assert _ts_set(RULES, "HARD_EXCLUDE") == set(semantics.HARD_EXCLUDE)
    assert _ts_set(RULES, "IDENTIFIER_ONLY") == set(semantics.IDENTIFIER_ONLY)


def test_profile_literals_match_profile_2() -> None:
    assert strict.CONTRACT == "profile-2"
    assert '"profile-2"' in RULES
    assert _ts_set(RULES, "COLUMN_TYPES") == _literal(strict.ColumnType)
    assert _ts_set(RULES, "INDICATORS") == _literal(strict.Indicator)
    assert _ts_set(RULES, "COLUMN_WARNINGS") == _literal(strict.ColumnWarning)
    assert _ts_set(RULES, "PROFILE_WARNINGS") == _literal(strict.ProfileWarning)


def test_the_profile_view_never_carries_value_fields() -> None:
    """profile-2 still has value-derived fields; the browser view must not."""
    value_fields = {"min_value", "max_value", "mean", "min_length", "max_length"}
    assert value_fields <= set(strict.ColumnProfile2.model_fields)
    view = _block(TYPES, "export interface ProfileColumnView ")
    for field in (*value_fields, "content_sha256", "minValue", "maxValue"):
        assert field not in view
    body = _block(RULES, "export function profileView(")
    for field in (*value_fields, "content_sha256"):
        assert field not in body


def test_every_rejection_code_has_plain_copy() -> None:
    copy = set(re.findall(r"^\s+([A-Z_]+):", _block(RULES, "const REJECTION_COPY"), re.M))
    assert copy == {c.value for c in RejectionCode}


def test_the_journey_waits_on_state_never_on_time() -> None:
    """Polling and the browser journey wait for an observed state; a sleep or a
    fixed timer would hide a stuck version instead of surfacing it."""
    sources = [
        ROOT / "web/e2e/pilot-datasets.spec.ts",
        ROOT / "web/src/lib/datasets.ts",
        ROOT / "web/src/lib/api/dataset-hooks.ts",
        *sorted((ROOT / "web/src/components/datasets").glob("*.tsx")),
    ]
    for path in sources:
        if path.name.endswith(".test.tsx"):
            continue
        text = path.read_text()
        for banned in ("waitForTimeout", "setTimeout(", "setInterval(", "sleep("):
            assert banned not in text, f"{path.name}: {banned}"
    spec = sources[0].read_text()
    # The only explicit bound is the ingest ceiling, and only on a state wait.
    state_waits = re.findall(
        r'toHaveText\("(?:Profiled|Rejected)", \{ timeout: INGEST_MS \}\)', spec
    )
    assert len(state_waits) == spec.count("timeout:") == 4
