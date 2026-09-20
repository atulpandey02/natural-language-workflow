"""M11 capacity metrics: scrape-time gauges + run-completion/lag/checkout wait."""

from nlw.observability import metrics


def test_capacity_collector_reports_pool_and_queue() -> None:
    metrics.register_pool_provider(lambda: (7, 2))
    metrics.register_queue_provider(lambda: 5)
    metrics.register_capacity_collector()

    text = metrics.render()[0].decode()
    assert "nlw_db_pool_checked_out 7.0" in text
    assert "nlw_db_pool_overflow 2.0" in text
    assert "nlw_queue_ready_depth 5.0" in text


def test_capacity_collector_scrape_is_live() -> None:
    # Providers are read at scrape time, so a new value shows without re-register.
    state = {"co": 1, "ov": 0}
    metrics.register_pool_provider(lambda: (state["co"], state["ov"]))
    metrics.register_capacity_collector()
    assert "nlw_db_pool_checked_out 1.0" in metrics.render()[0].decode()
    state["co"] = 9
    assert "nlw_db_pool_checked_out 9.0" in metrics.render()[0].decode()


def test_provider_error_does_not_break_scrape() -> None:
    def _boom() -> tuple[int, int]:
        raise RuntimeError("pool gone")

    metrics.register_pool_provider(_boom)
    metrics.register_capacity_collector()
    # render must not raise even if a provider fails.
    assert isinstance(metrics.render()[0], bytes)


def test_run_completion_lag_and_checkout_wait_recorded() -> None:
    metrics.observe_run_completion("completed", 1.5)
    metrics.observe_run_completion("failed", 0.25)
    metrics.set_scheduler_lag(12.0)
    metrics.observe_db_checkout_wait(0.003)

    # Presence/label checks only — these are process-cumulative and other tests
    # in the same process may also emit them, so do not assert exact counts here.
    text = metrics.render()[0].decode()
    assert 'nlw_run_completion_seconds_count{result="completed"}' in text
    assert 'nlw_run_completion_seconds_count{result="failed"}' in text
    assert "nlw_scheduler_lag_seconds" in text
    assert "nlw_db_pool_checkout_wait_seconds_count" in text
