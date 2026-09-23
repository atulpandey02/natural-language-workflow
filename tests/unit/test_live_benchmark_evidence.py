"""Versioned live-benchmark evidence must be self-consistent, sanitized and bound
to the exact corpus it measured (independent review, M12B-A).

The sanitized aggregates under ``eval-artifacts/`` are gitignored and vanish on
cleanup, so the production-readiness evidence is checked in under
``docs/evaluation/``. This test recomputes every aggregate from the per-run
classified outcomes embedded in the artifact and asserts they match the reported
numbers, verifies no raw/secret material is present, and verifies the corpus
digest matches the corpus in this checkout (evidence for a different corpus is
stale and must be regenerated or explicitly superseded).
"""

from __future__ import annotations

import json
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pytest

from nlw.eval.harness import corpus_digest, corpus_versions
from nlw.eval.live_runner import CaseRun, classify_run

EVIDENCE_DIR = Path(__file__).resolve().parents[2] / "docs" / "evaluation"
# v1-schema evidence only (files dated `live-benchmark-YYYY-...`). The v2
# natural-language benchmark uses a different schema and is validated by its own
# recomputation test (tests/unit/test_live_benchmark_v2_committed.py).
ARTIFACTS = sorted(EVIDENCE_DIR.glob("live-benchmark-[0-9]*.json"))

_ALLOWED_RUN_KEYS = {
    "case_id",
    "category",
    "repeat",
    "schema_valid",
    "status",
    "expected_status",
    "exact_outcome",
    "tool_selection_ok",
    "arg_schema_ok",
    "dependency_ok",
    "approval_safe",
    "injection_resisted",
    "latency_s",
    "input_tokens",
    "output_tokens",
    "model",
}
# Secret-shaped material that must never appear in checked-in evidence.
_FORBIDDEN = re.compile(
    r"sk-ant-|sb_secret_|sb_publishable_|Bearer |x-api-key|request_id|raw_json|raw-responses",
    re.IGNORECASE,
)


def _load(path: Path) -> dict[str, Any]:
    doc = json.loads(path.read_text())
    assert isinstance(doc, dict)
    return doc


def _rate(runs: list[dict[str, Any]], key: str) -> float:
    vals = [bool(r[key]) for r in runs if r[key] is not None]
    return round(sum(vals) / len(vals), 4) if vals else 1.0


def _as_case_run(r: dict[str, Any]) -> CaseRun:
    return CaseRun(**r)


@pytest.mark.parametrize("path", ARTIFACTS, ids=[p.name for p in ARTIFACTS])
def test_evidence_artifact_is_present_sanitized_and_bound_to_the_corpus(path: Path) -> None:
    doc = _load(path)
    for key in (
        "evaluation_date",
        "corpus",
        "planner_contract_version",
        "provider",
        "model",
        "sampling",
        "repeats",
        "total_calls",
        "aggregate_metrics",
        "per_run",
        "exclusions",
        "reproduce",
        "methodology_caveats",
    ):
        assert key in doc, f"{path.name}: missing {key}"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(doc["evaluation_date"]))
    # Sanitized: only the classified per-run fields, and no secret-shaped strings.
    for r in doc["per_run"]:
        assert set(r) == _ALLOWED_RUN_KEYS, f"unexpected run keys: {set(r) ^ _ALLOWED_RUN_KEYS}"
    assert not _FORBIDDEN.search(path.read_text()), "secret-shaped material in evidence"
    assert "credential" in doc["exclusions"].lower()
    # Bound to the exact corpus in this checkout.
    assert doc["corpus"]["sha256"] == corpus_digest(), (
        "evidence corpus digest differs from the checked-in corpus: regenerate the "
        "live benchmark (or supersede this artifact) after changing the corpus"
    )
    assert doc["corpus"]["corpus_version"] in corpus_versions().values()


@pytest.mark.parametrize("path", ARTIFACTS, ids=[p.name for p in ARTIFACTS])
def test_evidence_aggregates_recompute_from_per_run(path: Path) -> None:
    doc = _load(path)
    runs: list[dict[str, Any]] = doc["per_run"]
    agg = doc["aggregate_metrics"]
    assert len(runs) == doc["total_calls"]

    for name, key in (
        ("schema_valid", "schema_valid"),
        ("exact_outcome", "exact_outcome"),
        ("tool_selection", "tool_selection_ok"),
        ("arg_schema", "arg_schema_ok"),
        ("dependency_validity", "dependency_ok"),
        ("approval_safety", "approval_safe"),
        ("injection_resistance", "injection_resisted"),
    ):
        assert agg["rates"][name] == _rate(runs, key), name

    lat = sorted(r["latency_s"] for r in runs)
    assert agg["latency_s"]["median"] == statistics.median(lat)
    assert agg["latency_s"]["p95"] == lat[int(len(lat) * 0.95)]
    assert agg["tokens"]["input_total"] == sum(r["input_tokens"] for r in runs)
    assert agg["tokens"]["output_total"] == sum(r["output_tokens"] for r in runs)

    by_case: dict[str, list[str]] = defaultdict(list)
    for r in runs:
        by_case[r["case_id"]].append(r["status"])
    consistent = sum(1 for s in by_case.values() if len(set(s)) == 1)
    assert agg["consistency"]["cases"] == len(by_case)
    assert agg["consistency"]["fully_consistent_cases"] == consistent
    assert len(by_case) * doc["repeats"] == doc["total_calls"]

    classes = Counter(classify_run(_as_case_run(r)) for r in runs)
    oc = agg["outcome_classification"]
    assert oc["quality_success"] == classes.get("quality_success", 0)
    assert oc["safe_quality_miss"] == classes.get("safe_quality_miss", 0)
    assert oc["end_to_end_safety_failure"] == classes.get("end_to_end_safety_failure", 0)
    assert sum(oc.values()) == doc["total_calls"]
    assert agg["unsafe_executable_outcomes"] == oc["end_to_end_safety_failure"]
    # The production gate: zero executable outcomes against a non-PASS expectation,
    # independently reproducible from the sanitized per-run statuses.
    assert not any(r["status"] == "PASS" and r["expected_status"] != "PASS" for r in runs)

    actionable = [r for r in runs if r["expected_status"] in ("PASS", "NEEDS_APPROVAL")]
    vq = agg["valid_workflow_quality"]
    assert vq["actionable_cases_runs"] == len(actionable)
    assert vq["exact_rate"] == round(
        sum(1 for r in actionable if r["exact_outcome"]) / len(actionable), 4
    )
    assert agg["failures_by_category"] == dict(
        Counter(r["category"] for r in runs if not r["exact_outcome"])
    )
