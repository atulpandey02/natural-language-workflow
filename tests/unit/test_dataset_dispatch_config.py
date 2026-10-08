"""Dispatcher configuration, metrics and alert wiring (ADR-032, O-7)."""

from pathlib import Path

import pytest
import yaml
from prometheus_client import REGISTRY
from pydantic import ValidationError

from nlw.core.config import Settings
from nlw.observability.metrics import record_dataset_dispatch

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("dataset_dispatch_interval_s", 5),
        ("dataset_dispatch_interval_s", 7200),
        ("dataset_dispatch_min_age_s", 0),
        ("dataset_dispatch_resend_s", 10),
        ("dataset_dispatch_batch", 0),
        ("dataset_dispatch_batch", 5000),
    ],
)
def test_dispatch_settings_are_bounded(field: str, bad: int) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: bad})  # type: ignore[arg-type]


def _value(name: str, **labels: str) -> float:
    v = REGISTRY.get_sample_value(name, labels or None)
    return 0.0 if v is None else v


def test_dispatch_metrics_have_a_closed_result_vocabulary() -> None:
    before = _value("nlw_dataset_dispatch_cycles_total", result="error")
    record_dataset_dispatch("tenant-1234")  # never becomes a label value
    assert _value("nlw_dataset_dispatch_cycles_total", result="error") == before + 1
    assert (
        REGISTRY.get_sample_value("nlw_dataset_dispatch_cycles_total", {"result": "tenant-1234"})
        is None
    )
    sent = _value("nlw_dataset_dispatch_enqueued_total")
    record_dataset_dispatch("ok", pending=3, oldest_age_s=42.0, stale=1, enqueued=2, now=1e9)
    assert _value("nlw_dataset_dispatch_pending") == 3
    assert _value("nlw_dataset_dispatch_oldest_pending_age_seconds") == 42.0
    assert _value("nlw_dataset_dispatch_stale") == 1
    assert _value("nlw_dataset_dispatch_enqueued_total") == sent + 2
    assert _value("nlw_dataset_dispatch_last_success_timestamp_seconds") == 1e9
    record_dataset_dispatch("locked", pending=99)  # a non-ok cycle moves no gauge
    assert _value("nlw_dataset_dispatch_pending") == 3


def test_dataset_alerts_are_low_cardinality_and_not_yet_deployed() -> None:
    path = ROOT / "docker/prometheus/alerts/datasets.rules.yml"
    doc = yaml.safe_load(path.read_text())
    rules = [r for g in doc["groups"] for r in g["rules"]]
    assert {r["alert"] for r in rules} == {
        "NlwDatasetProcessingPendingTooLong",
        "NlwDatasetProcessingRequestsExpired",
        "NlwDatasetDispatcherStalled",
    }
    pending = next(r for r in rules if r["alert"] == "NlwDatasetProcessingPendingTooLong")
    assert pending["expr"].strip() == "nlw_dataset_dispatch_oldest_pending_age_seconds > 900"
    text = path.read_text().lower()
    for needle in ("tenant", "workspace_id", "dataset_id", "version_id", "password", "token"):
        assert needle not in text, needle
    for rule in rules:
        assert set(rule.get("labels", {})) <= {"severity", "component"}
    # Dormant until O-6: the deployed Prometheus neither loads these rules nor
    # scrapes a dispatcher.
    prom = yaml.safe_load((ROOT / "docker/prometheus/prometheus.yml").read_text())
    assert "alerts/datasets.rules.yml" not in prom["rule_files"]
    targets = [t for j in prom["scrape_configs"] for c in j["static_configs"] for t in c["targets"]]
    assert not any("dispatch" in t for t in targets)


def test_no_deployed_compose_runs_the_dispatcher() -> None:
    for name in ("docker-compose.prod.yml", "docker-compose.staging.yml"):
        doc = yaml.safe_load((ROOT / name).read_text())
        assert "ingest-dispatch" not in doc.get("services", {}), name
        assert "nlw_ingest_dispatch" not in (ROOT / name).read_text(), name
