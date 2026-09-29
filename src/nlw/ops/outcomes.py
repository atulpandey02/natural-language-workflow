"""Operator report over redacted plan outcome events (Phase 2 B02).

    DATABASE_MIGRATION_URL=... python -m nlw.ops.outcomes report --days 7 [--json]

Cross-tenant and aggregate-only: counts by outcome, category, finding code,
model and request-shape tag, plus the first-pass PASS rate. No tenant id, user
id, proposal id or text is printed. A request-shape tag is shown for a category
only when it occurs in at least ``MIN_TENANTS`` distinct workspaces, so a single
customer's habits cannot be singled out.

This reads the owner-credential view of ``plan_outcome_events``; it is an
operator tool, never a tenant API.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from typing import Any

import psycopg

MIN_TENANTS = 3
_OUTCOMES = ("PASS", "APPROVAL", "CLARIFY", "REJECT", "INVALID_OUTPUT", "INFRA_FAIL")

# (tenant_id, outcome, category, finding_codes, request_shape, model)
Row = tuple[Any, str, str | None, Sequence[str], Sequence[str], str]


def build_report(rows: Iterable[Row], *, days: int) -> dict[str, Any]:
    outcomes: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    codes: Counter[str] = Counter()
    per_model: dict[str, Counter[str]] = defaultdict(Counter)
    shape_tenants: dict[tuple[str, str], set[Any]] = defaultdict(set)
    shape_counts: Counter[tuple[str, str]] = Counter()
    tenants: set[Any] = set()
    total = 0
    for tenant, outcome, category, finding_codes, shape, model in rows:
        total += 1
        tenants.add(tenant)
        outcomes[outcome] += 1
        per_model[model][outcome] += 1
        if category:
            categories[category] += 1
            for tag in shape:
                shape_tenants[(category, tag)].add(tenant)
                shape_counts[(category, tag)] += 1
        codes.update(finding_codes)
    planned = sum(outcomes[o] for o in ("PASS", "APPROVAL"))
    attempted = total - outcomes["INFRA_FAIL"]
    shapes: dict[str, dict[str, int]] = defaultdict(dict)
    for (category, tag), n in sorted(shape_counts.items()):
        if len(shape_tenants[(category, tag)]) >= MIN_TENANTS:
            shapes[category][tag] = n
    return {
        "window_days": days,
        "events": total,
        "workspaces": len(tenants),
        "outcomes": {o: outcomes[o] for o in _OUTCOMES},
        "first_pass_plan_rate": round(planned / attempted, 4) if attempted else None,
        "categories": dict(categories.most_common()),
        "finding_codes": dict(codes.most_common()),
        "by_model": {m: {o: c[o] for o in _OUTCOMES if c[o]} for m, c in sorted(per_model.items())},
        "request_shapes_by_category": dict(shapes),
        "shape_min_workspaces": MIN_TENANTS,
    }


def fetch_rows(conn: psycopg.Connection[Any], *, days: int) -> list[Row]:
    return conn.execute(
        "SELECT tenant_id, outcome, category, finding_codes, request_shape, model "
        "FROM plan_outcome_events WHERE created_at >= now() - make_interval(days => %s)",
        (days,),
    ).fetchall()


def render_text(report: dict[str, Any]) -> str:
    lines = [
        f"Plan outcomes, last {report['window_days']} days: {report['events']} events "
        f"across {report['workspaces']} workspaces",
        f"First-pass plan rate (PASS+APPROVAL / non-infra attempts): "
        f"{report['first_pass_plan_rate']}",
        "Outcomes: " + ", ".join(f"{k}={v}" for k, v in report["outcomes"].items()),
        "Categories: " + (", ".join(f"{k}={v}" for k, v in report["categories"].items()) or "-"),
        "Finding codes: "
        + (", ".join(f"{k}={v}" for k, v in report["finding_codes"].items()) or "-"),
    ]
    for model, counts in report["by_model"].items():
        lines.append(f"Model {model}: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    for category, tags in report["request_shapes_by_category"].items():
        lines.append(f"Shapes in {category}: " + ", ".join(f"{k}={v}" for k, v in tags.items()))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ops.outcomes")
    sub = p.add_subparsers(dest="cmd", required=True)
    rep = sub.add_parser("report")
    rep.add_argument("--days", type=int, default=7)
    rep.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if not 1 <= args.days <= 400:
        print("error: --days must be within 1..400", file=sys.stderr)
        return 2
    url = os.environ.get("DATABASE_MIGRATION_URL")
    if not url:
        raise SystemExit("DATABASE_MIGRATION_URL (owner credential) is required")
    with psycopg.connect(url.replace("+psycopg", "", 1)) as conn:
        report = build_report(fetch_rows(conn, days=args.days), days=args.days)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render_text(report))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
