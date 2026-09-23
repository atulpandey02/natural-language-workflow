"""The v2 live-benchmark evidence must allow INDEPENDENT recomputation of every
reported metric from its own ``per_run`` array (M12B final, Part 2).

The live run is credential-gated and deferred; this test uses the STUB provider to
produce a real evidence document (planning only) and then recomputes each rate,
the unsafe-executable count and the consistency independently, asserting they match
the reported aggregates. It also asserts the sanitized document contains no raw
provider response, request id, header, credential or raw request/clarification text.
"""

import asyncio
from typing import Any

from nlw.core.config import Settings
from nlw.eval.live_runner_v2 import _run


def _evidence() -> dict[str, Any]:
    settings = Settings()  # stub provider in tests (planning only)
    return asyncio.run(_run(settings, repeats=2))


def test_rates_recompute_from_per_run() -> None:
    doc = _evidence()
    runs = doc["per_run"]
    assert doc["calls"] == len(runs)

    def rate(key: str) -> float | None:
        vals = [bool(r[key]) for r in runs if r.get(key) is not None]
        return round(sum(vals) / len(vals), 4) if vals else None

    mapping = {
        "correct_product_decision": "correct_product_decision",
        "immediate_feasible_plan": "immediate_feasible_plan",
        "useful_clarification": "useful_clarification",
        "unsupported_rejection_correct": "unsupported_correct",
        "schema_valid": "schema_valid",
        "tool_selection": "tool_selection_ok",
        "argument_schema": "arg_schema_ok",
        "dependency_validity": "dependency_ok",
        "approval_policy_safety": "approval_policy_safe",
        "tenant_connector_isolation_safety": "isolation_safe",
        "injection_resistance": "injection_resisted",
        "secret_exfiltration_safety": "exfiltration_safe",
    }
    for reported, run_key in mapping.items():
        assert doc["rates"][reported] == rate(run_key), reported


def test_unsafe_and_consistency_recompute() -> None:
    doc = _evidence()
    runs = doc["per_run"]
    assert doc["unsafe_executable_outcomes"] == sum(1 for r in runs if r["unsafe_executable"])
    by_case: dict[str, set[str]] = {}
    for r in runs:
        by_case.setdefault(r["case_id"], set()).add(r["observed_decision"])
    assert doc["consistency"]["fully_consistent"] == sum(1 for v in by_case.values() if len(v) == 1)


def test_evidence_is_sanitized() -> None:
    doc = _evidence()
    blob = repr(doc)
    # Leak markers (raw provider payloads, request ids, credential headers). The
    # category label "secret_exfiltration" is legitimate corpus metadata, not a leak.
    for banned in ("raw_json", "provider_request_id", "authorization", "bearer ", "sk-"):
        assert banned not in blob.lower(), banned
    # Per-run rows carry only classifications/metadata, never plan or request text.
    for r in doc["per_run"]:
        assert "request" not in r and "plan" not in r and "clarification_questions" not in r
