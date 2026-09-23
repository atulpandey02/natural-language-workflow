"""Credential-gated live-model benchmark over the NATURAL-LANGUAGE corpus v2
(M12B final correction, Part 2). PLANNING ONLY — it calls the planner provider and
grades the structured result deterministically; it never materializes/executes a
plan, resolves a connector secret, or performs any external side effect.

    # Operator command (real provider credential supplied via .env.eval.local):
    set -a; source .env.eval.local; set +a
    uv run python -m nlw.eval.live_runner_v2 --repeats 3 \
        --out docs/evaluation/live-benchmark-v2-<date>.json

The output is a sanitized, versioned evidence file from which every metric can be
independently recomputed (see tests/unit/test_live_benchmark_v2_evidence.py). It
NEVER contains raw provider responses, provider request ids, headers, credentials,
or raw request text — clarification is recorded as extracted concept hits only.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from nlw.core.config import Settings
from nlw.eval.corpus_v2 import (
    V2Case,
    grade_live,
    load_v2,
    v2_digest,
    v2_version,
)
from nlw.feasibility.engine import FeasibilityStatus, Severity
from nlw.feasibility.limits import DEFAULT_LIMITS
from nlw.planner.capabilities import build_capability_view
from nlw.planner.planner import plan_and_check
from nlw.planner.provider import build_llm_provider
from nlw.planner.schema import PLANNER_CONTRACT_VERSION
from nlw.registry.registry import REGISTRY


def _view(case: V2Case) -> Any:
    return build_capability_view(REGISTRY.all(), [c.to_safe() for c in case.connectors])


async def _run(settings: Settings, repeats: int) -> dict[str, Any]:
    provider = build_llm_provider(settings)
    cases = load_v2()
    runs: list[dict[str, Any]] = []
    latencies: list[float] = []
    in_tok = 0
    out_tok = 0
    calls = 0
    import time

    for case in cases:
        view = _view(case)
        all_names = {t.name for t in REGISTRY.all()}
        for r in range(repeats):
            start = time.perf_counter()
            result = await plan_and_check(
                provider=provider,
                view=view,
                all_tool_names=all_names,
                limits=DEFAULT_LIMITS,
                user_request=case.request,
                max_output_tokens=settings.llm_max_output_tokens,
                timeout_s=settings.llm_timeout_s,
            )
            latency = time.perf_counter() - start
            calls += 1
            latencies.append(latency)
            if result.input_tokens:
                in_tok += result.input_tokens
            if result.output_tokens:
                out_tok += result.output_tokens
            report = result.report
            reject_codes = {f.code.value for f in report.findings if f.severity == Severity.REJECT}
            grade = grade_live(
                case,
                FeasibilityStatus(report.status),
                result.output,
                report.clarification_questions,
                reject_codes,
            )
            runs.append(
                {
                    **grade.model_dump(mode="json"),
                    "repeat": r,
                    "latency_s": round(latency, 3),
                    "input_tokens": result.input_tokens,
                    "output_tokens": result.output_tokens,
                    "model": result.model,
                }
            )
    return _summarize(settings, repeats, calls, runs, latencies, in_tok, out_tok)


def _rate(runs: list[dict[str, Any]], key: str) -> float | None:
    vals = [bool(r[key]) for r in runs if r.get(key) is not None]
    return round(sum(vals) / len(vals), 4) if vals else None


def _summarize(
    settings: Settings,
    repeats: int,
    calls: int,
    runs: list[dict[str, Any]],
    latencies: list[float],
    in_tok: int,
    out_tok: int,
) -> dict[str, Any]:
    lat = sorted(latencies)
    by_case: dict[str, set[str]] = defaultdict(set)
    for r in runs:
        by_case[r["case_id"]].add(r["observed_decision"])
    consistent = sum(1 for v in by_case.values() if len(v) == 1)
    unsafe = sum(1 for r in runs if r["unsafe_executable"])
    per_cat: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "correct": 0})
    for r in runs:
        per_cat[r["category"]]["n"] += 1
        per_cat[r["category"]]["correct"] += int(r["correct_product_decision"])
    return {
        "evaluation_date": _dt.datetime.now(_dt.UTC).date().isoformat(),
        "corpus_version": v2_version(),
        "corpus_sha256": v2_digest(),
        "planner_contract_version": PLANNER_CONTRACT_VERSION,
        "provider": settings.llm_provider,
        "model": settings.llm_model,
        "parameters": {
            "max_output_tokens": settings.llm_max_output_tokens,
            "timeout_s": settings.llm_timeout_s,
            "sampling": "provider-default (temperature/top_p not set by nlw)",
            "repeats": repeats,
        },
        "calls": calls,
        "rates": {
            "correct_product_decision": _rate(runs, "correct_product_decision"),
            "immediate_feasible_plan": _rate(runs, "immediate_feasible_plan"),
            "useful_clarification": _rate(runs, "useful_clarification"),
            "unsupported_rejection_correct": _rate(runs, "unsupported_correct"),
            "schema_valid": _rate(runs, "schema_valid"),
            "tool_selection": _rate(runs, "tool_selection_ok"),
            "argument_schema": _rate(runs, "arg_schema_ok"),
            "dependency_validity": _rate(runs, "dependency_ok"),
            "approval_policy_safety": _rate(runs, "approval_policy_safe"),
            "tenant_connector_isolation_safety": _rate(runs, "isolation_safe"),
            "injection_resistance": _rate(runs, "injection_resisted"),
            "secret_exfiltration_safety": _rate(runs, "exfiltration_safe"),
        },
        "unsafe_executable_outcomes": unsafe,
        "consistency": {"cases": len(by_case), "fully_consistent": consistent},
        "latency_s": {
            "median": statistics.median(lat) if lat else None,
            "p95": lat[int(len(lat) * 0.95)] if lat else None,
        },
        "tokens": {"input_total": in_tok, "output_total": out_tok},
        "per_category": {k: v for k, v in sorted(per_cat.items())},
        "per_run": runs,
        "excluded": (
            "No raw provider responses, provider request ids, headers, credentials, or raw "
            "request/clarification text are retained; clarification is recorded as concept hits."
        ),
        "repro_command": (
            "set -a; source .env.eval.local; set +a; "
            "uv run python -m nlw.eval.live_runner_v2 --repeats 3 --out <path>"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.eval.live_runner_v2")
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--allow-stub", action="store_true", help="permit the stub provider (dev only)")
    a = p.parse_args(argv)
    settings = Settings()
    if settings.llm_provider == "stub" and not a.allow_stub:
        print(
            "Refusing to run: NLW_LLM_PROVIDER=stub. Supply the real provider credential:\n"
            "  set -a; source .env.eval.local; set +a\n"
            "  uv run python -m nlw.eval.live_runner_v2 --repeats 3 --out <path>\n"
            "(planning only; never executes a plan). No credential is configured now.",
            file=sys.stderr,
        )
        return 2
    doc = asyncio.run(_run(settings, a.repeats))
    text = json.dumps(doc, indent=1)
    if a.out is not None:
        a.out.write_text(text)
    print(
        json.dumps({k: doc[k] for k in ("rates", "unsafe_executable_outcomes", "calls")}, indent=1)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
