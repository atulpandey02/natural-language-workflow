"""AI-core observability (M12B-A, Part I).

The new planner/feasibility/summary metrics exist, are low-cardinality (bounded
label vocabularies only — never tenant/run/step ids, prompt text or tool
output), and their typed recording helpers increment/observe correctly.
"""

from prometheus_client import REGISTRY

from nlw.observability import metrics


def _value(name: str, labels: dict[str, str] | None = None) -> float:
    v = REGISTRY.get_sample_value(name, labels or {})
    return v if v is not None else 0.0


def test_new_ai_metrics_are_registered() -> None:
    names = {m.name for m in REGISTRY.collect()}
    for expected in (
        "nlw_planner_invalid_output",
        "nlw_feasibility_reject",
        "nlw_plan_steps",
        "nlw_plan_bytes",
        "nlw_planner_tokens",
        "nlw_run_summary",
        "nlw_stale_plan",
        "nlw_run_queue_to_start_seconds",
        "nlw_approval_wait_seconds",
    ):
        assert expected in names, f"missing metric family {expected}"


def test_stale_and_latency_metrics_record() -> None:
    metrics.record_stale_plan("STALE_PLAN", "TOOL_NOT_AVAILABLE")
    metrics.observe_queue_to_start(1.5)
    metrics.observe_approval_wait(42.0)
    # stale label vocabulary is bounded (outcome + FeasibilityCode reason).
    for family in REGISTRY.collect():
        if family.name == "nlw_stale_plan":
            for sample in family.samples:
                assert sample.labels["outcome"] in {
                    "STALE_PLAN",
                    "POLICY_DENIED",
                    "INVALID_PLAN",
                }
    assert _value("nlw_run_queue_to_start_seconds_count") >= 1
    assert _value("nlw_approval_wait_seconds_count") >= 1


def test_labels_are_bounded_vocabularies_only() -> None:
    # Exercise the helpers, then assert every label value is from a bounded set.
    metrics.record_feasibility_reject("UNKNOWN_TOOL")
    metrics.record_planner_invalid_output()
    metrics.observe_plan_shape(3, 512)
    metrics.observe_planner_tokens(100, 200)
    metrics.record_run_summary("COMPLETED")
    for family in REGISTRY.collect():
        if family.name in ("nlw_feasibility_reject", "nlw_run_summary", "nlw_planner_tokens"):
            for sample in family.samples:
                for key, val in sample.labels.items():
                    # A label value must never look like an id / free text.
                    assert len(val) <= 40 and "-" not in val.replace("_", "")
                    if key == "direction":
                        assert val in {"input", "output"}


def test_helpers_increment_and_observe() -> None:
    before_reject = _value("nlw_feasibility_reject_total", {"code": "SQL_REJECTED"})
    metrics.record_feasibility_reject("SQL_REJECTED")
    assert _value("nlw_feasibility_reject_total", {"code": "SQL_REJECTED"}) == before_reject + 1

    before_sum = _value("nlw_run_summary_total", {"outcome": "FAILED_WITH_UNKNOWN"})
    metrics.record_run_summary("FAILED_WITH_UNKNOWN")
    assert _value("nlw_run_summary_total", {"outcome": "FAILED_WITH_UNKNOWN"}) == before_sum + 1

    before_invalid = _value("nlw_planner_invalid_output_total")
    metrics.record_planner_invalid_output()
    assert _value("nlw_planner_invalid_output_total") == before_invalid + 1

    # Histograms observe without raising; count increments.
    before_steps = _value("nlw_plan_steps_count")
    metrics.observe_plan_shape(5, 2048)
    assert _value("nlw_plan_steps_count") == before_steps + 1
    metrics.observe_planner_tokens(None, None)  # tolerated: no-op, no raise
