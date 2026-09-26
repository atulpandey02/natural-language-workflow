"""Container healthcheck helper (M9)."""

import pytest

from nlw.ops import healthcheck


def test_libpq_url_strips_driver() -> None:
    assert (
        healthcheck._libpq_url("postgresql+psycopg://u:p@h:5432/db") == "postgresql://u:p@h:5432/db"
    )


def _all_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(healthcheck, "_check_postgres", lambda s: None)
    monkeypatch.setattr(healthcheck, "_check_recovery_lock", lambda s: None)
    monkeypatch.setattr(healthcheck, "_check_redis", lambda s: None)
    monkeypatch.setattr(healthcheck, "_check_metrics_port", lambda s: None)
    monkeypatch.setattr(healthcheck, "_check_signed_context", lambda s: None)


def test_main_returns_zero_when_all_checks_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    _all_pass(monkeypatch)
    assert healthcheck.main() == 0


def test_main_returns_one_when_a_check_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _all_pass(monkeypatch)

    def _boom(_s: object) -> None:
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr(healthcheck, "_check_redis", _boom)
    assert healthcheck.main() == 1


def test_recovery_lock_is_a_mandatory_health_check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A locked / indeterminate DR recovery state must fail the container
    healthcheck (reason class only, never a secret), independent of the metrics
    port — so a worker restart-looping on the lock is never reported healthy."""
    from nlw.backup.recovery_lock import RecoveryLocked

    _all_pass(monkeypatch)

    def _locked(_s: object) -> None:
        raise RecoveryLocked("newest restore generation is validated but not operator-enabled")

    monkeypatch.setattr(healthcheck, "_check_recovery_lock", _locked)
    assert healthcheck.main() == 1
    err = capsys.readouterr().err
    assert "healthcheck recovery_lock failed: RecoveryLocked" in err
    assert "postgresql" not in err


def test_recovery_lock_check_uses_the_authoritative_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The health probe reuses ``assert_startup_allowed_sync`` (the same authority
    the worker/scheduler boot preflight uses) and always disposes its engine."""
    import nlw.backup.recovery_lock as rl
    import nlw.db.session as dbs

    calls: list[str] = []

    class _Engine:
        def dispose(self) -> None:
            calls.append("dispose")

    monkeypatch.setattr(dbs, "create_sync_engine", lambda s: _Engine())

    def _assert(engine: object) -> None:
        calls.append("assert")
        raise rl.RecoveryStateUnknown("cannot read authoritative recovery-lock state")

    monkeypatch.setattr(rl, "assert_startup_allowed_sync", _assert)
    with pytest.raises(rl.RecoveryStateUnknown):
        healthcheck._check_recovery_lock(object())  # type: ignore[arg-type]
    assert calls == ["assert", "dispose"]
