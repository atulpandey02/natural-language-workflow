"""Prometheus metrics: recording, render, and the internal scrape server (M9)."""

import urllib.request

from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.core.config import Settings
from nlw.observability import metrics


def test_render_exposes_recorded_series() -> None:
    metrics.record_plan("PASS")
    metrics.observe_tool("fake.echo", "success", 0.01)
    metrics.record_advance("completed", 0.02)
    metrics.set_runs_beyond_horizon(3)
    payload, content_type = metrics.render()
    text = payload.decode()
    assert content_type.startswith("text/plain")
    assert "nlw_plans_total" in text
    assert "nlw_tool_latency_seconds" in text
    assert "nlw_advance_total" in text
    assert "nlw_scheduler_runs_beyond_horizon 3.0" in text


def test_low_cardinality_labels_only() -> None:
    # A defensive guard: identifiers must never appear as metric label names.
    payload, _ = metrics.render()
    text = payload.decode()
    for forbidden in ("tenant_id=", "run_id=", "step_id=", "connector_id="):
        assert forbidden not in text


def test_metrics_server_serves_scrape() -> None:
    settings = Settings(_env_file=None, metrics_port=9187)  # type: ignore[call-arg]
    assert metrics.start_metrics_server(settings, role="test") is True
    metrics.record_error("Boom")
    with urllib.request.urlopen("http://127.0.0.1:9187/metrics", timeout=5) as resp:
        assert resp.status == 200
        body = resp.read().decode()
    assert "nlw_errors_total" in body


def test_metrics_disabled_returns_false() -> None:
    # Disabled short-circuits before the idempotent guard: always False, no bind.
    settings = Settings(_env_file=None, metrics_enabled=False)  # type: ignore[call-arg]
    assert metrics.start_metrics_server(settings, role="test") is False


def test_api_records_http_metrics_via_middleware() -> None:
    # The API's ObservabilityMiddleware records per-route HTTP metrics; /health
    # needs no external dependency.
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    with TestClient(create_app(settings)) as client:
        assert client.get("/health").status_code == 200
    text = metrics.render()[0].decode()
    assert "nlw_http_requests_total" in text
    assert "/health" in text  # low-cardinality route template label
