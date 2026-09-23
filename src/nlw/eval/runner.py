"""Evaluation runner (M12B-A, Part B): machine-readable JSON + Markdown summary.

    python -m nlw.eval.runner [--json OUT.json] [--md OUT.md]

Runs the deterministic replay over the whole corpus and writes results. It does
NOT run the live model and never executes a plan. Live-model evaluation is a
separate, credential-gated path (tests/eval/test_eval_live_model.py); a single
run never establishes model quality, so this report is a contract check, not a
benchmark.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from nlw.eval.harness import GradeResult, load_all_cases, replay_case


def run_replay() -> list[GradeResult]:
    return [replay_case(c) for c in load_all_cases()]


def to_json(results: list[GradeResult]) -> dict[str, object]:
    passed = sum(1 for r in results if r.passed)
    by_cat: Counter[str] = Counter(r.category for r in results)
    cat_pass: Counter[str] = Counter(r.category for r in results if r.passed)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": "deterministic-replay",
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "categories": {
            cat: {"total": by_cat[cat], "passed": cat_pass[cat]} for cat in sorted(by_cat)
        },
        "cases": [asdict(r) for r in results],
    }


def to_markdown(doc: dict[str, object]) -> str:
    lines = [
        "# AI evaluation — deterministic replay",
        "",
        f"- generated: {doc['generated_at']}",
        f"- result: **{doc['passed']}/{doc['total']} passed**, {doc['failed']} failed",
        "",
        "Deterministic replay against the real registry + feasibility engine. No",
        "LLM, no network, no execution. A single run is a contract check, not a",
        "model-quality benchmark.",
        "",
        "## By category",
        "",
        "| category | passed / total |",
        "|---|---|",
    ]
    cats = doc["categories"]
    assert isinstance(cats, dict)
    for cat in cats:
        c = cats[cat]
        lines.append(f"| {cat} | {c['passed']} / {c['total']} |")
    all_cases = doc["cases"]
    assert isinstance(all_cases, list)
    failed = [c for c in all_cases if not c["passed"]]
    if failed:
        lines += ["", "## Failures", ""]
        for fc in failed:
            lines.append(f"- **{fc['case_id']}** ({fc['category']}): {fc['failures']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.eval.runner")
    p.add_argument("--json", type=Path, default=None, help="write JSON results here")
    p.add_argument("--md", type=Path, default=None, help="write a Markdown summary here")
    a = p.parse_args(argv)
    results = run_replay()
    doc = to_json(results)
    if a.json:
        a.json.write_text(json.dumps(doc, indent=2) + "\n")
    if a.md:
        a.md.write_text(to_markdown(doc))
    print(json.dumps({k: doc[k] for k in ("mode", "total", "passed", "failed")}, indent=2))
    return 0 if doc["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
