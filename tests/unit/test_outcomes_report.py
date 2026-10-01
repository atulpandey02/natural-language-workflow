"""B02: the operator outcome report is aggregate-only and k-anonymous for shapes."""

import json
import uuid

from nlw.ops.outcomes import MIN_TENANTS, build_report, render_text


def test_report_aggregates_and_hides_rare_shapes() -> None:
    t = [uuid.uuid4() for _ in range(4)]
    rows = [
        (t[0], "PASS", None, [], ["has_top_n"], "m"),
        (t[1], "REJECT", "MISSING_CAPABILITY", ["UNKNOWN_TOOL"], ["asks_export"], "m"),
        (t[2], "REJECT", "MISSING_CAPABILITY", ["UNKNOWN_TOOL"], ["asks_export"], "m"),
        (t[3], "REJECT", "MISSING_CAPABILITY", ["UNKNOWN_TOOL"], ["asks_export", "asks_why"], "m"),
        (t[0], "CLARIFY", "UNDERSPECIFIED_REQUEST", ["CLARIFICATION_REQUIRED"], ["asks_why"], "m"),
        (t[0], "INFRA_FAIL", "INFRA_FAILURE", [], [], "m"),
    ]
    r = build_report(rows, days=7)
    assert r["events"] == 6 and r["workspaces"] == 4
    assert r["outcomes"]["REJECT"] == 3 and r["outcomes"]["INFRA_FAIL"] == 1
    assert r["first_pass_plan_rate"] == round(1 / 5, 4)
    assert r["finding_codes"]["UNKNOWN_TOOL"] == 3
    # asks_export reached MIN_TENANTS workspaces in MISSING_CAPABILITY; asks_why did not.
    assert MIN_TENANTS == 3
    assert r["request_shapes_by_category"] == {"MISSING_CAPABILITY": {"asks_export": 3}}
    text = render_text(r) + json.dumps(r, default=str)
    for tenant in t:
        assert str(tenant) not in text


def test_empty_window() -> None:
    r = build_report([], days=7)
    assert r["events"] == 0 and r["first_pass_plan_rate"] is None
