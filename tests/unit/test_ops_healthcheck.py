"""Container healthcheck helper (M9)."""

import pytest

from nlw.ops import healthcheck


def test_libpq_url_strips_driver() -> None:
    assert (
        healthcheck._libpq_url("postgresql+psycopg://u:p@h:5432/db") == "postgresql://u:p@h:5432/db"
    )


def test_main_returns_zero_when_all_checks_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(healthcheck, "_check_postgres", lambda s: None)
    monkeypatch.setattr(healthcheck, "_check_redis", lambda s: None)
    monkeypatch.setattr(healthcheck, "_check_metrics_port", lambda s: None)
    monkeypatch.setattr(healthcheck, "_check_signed_context", lambda s: None)
    assert healthcheck.main() == 0


def test_main_returns_one_when_a_check_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(healthcheck, "_check_postgres", lambda s: None)

    def _boom(_s: object) -> None:
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr(healthcheck, "_check_redis", _boom)
    monkeypatch.setattr(healthcheck, "_check_metrics_port", lambda s: None)
    monkeypatch.setattr(healthcheck, "_check_signed_context", lambda s: None)
    assert healthcheck.main() == 1
