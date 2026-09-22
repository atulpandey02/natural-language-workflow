"""Signed-context metrics stay low-cardinality (M11.5 P3B, section O)."""

from prometheus_client import REGISTRY

from nlw.observability import metrics


def _value(name: str, **labels: str) -> float | None:
    return REGISTRY.get_sample_value(name, labels)


def test_verification_counter_uses_bounded_labels_only() -> None:
    before = (
        _value(
            "nlw_ctx_verification_total",
            purpose="api_request",
            result="invalid",
            reason="not_verified",
        )
        or 0.0
    )
    # An arbitrary caller-supplied reason (e.g. an error message, a key id, a
    # nonce) is coerced into the fixed vocabulary — it can never become a label.
    metrics.record_ctx_verification("api_request", False, "key id dev-api-7 nonce 0xdeadbeef")
    after = _value(
        "nlw_ctx_verification_total", purpose="api_request", result="invalid", reason="not_verified"
    )
    assert after == before + 1
    assert (
        _value(
            "nlw_ctx_verification_total",
            purpose="api_request",
            result="invalid",
            reason="key id dev-api-7 nonce 0xdeadbeef",
        )
        is None
    )


def test_valid_verification_has_reason_none() -> None:
    before = (
        _value(
            "nlw_ctx_verification_total", purpose="worker_execution", result="valid", reason="none"
        )
        or 0.0
    )
    metrics.record_ctx_verification("worker_execution", True, "db_error")  # reason ignored when ok
    assert (
        _value(
            "nlw_ctx_verification_total", purpose="worker_execution", result="valid", reason="none"
        )
        == before + 1
    )


def test_signer_configured_gauge() -> None:
    metrics.set_ctx_signer_configured("scheduler_reconcile", True)
    assert _value("nlw_ctx_signer_configured", purpose="scheduler_reconcile") == 1.0
    metrics.set_ctx_signer_configured("scheduler_reconcile", False)
    assert _value("nlw_ctx_signer_configured", purpose="scheduler_reconcile") == 0.0
