"""The worker recovery lock must ABORT Dramatiq worker boot — proven through the
real ``dramatiq.Worker.start()`` sequence with the real middleware (no external
service, no message processing, no database).

Background (the reproduced defect): ``RecoveryLockMiddleware.before_worker_boot``
raised ``RecoveryLocked`` / ``RecoveryStateUnknown`` — plain ``RuntimeError``s.
The pinned dramatiq 2.2.1 ``Broker.emit_before`` re-raises only ``MiddlewareError``
and logs-and-swallows everything else, so ``Worker.start()`` continued, installed
the consumer middleware, and started worker threads against a locked database.
The fix raises ``WorkerBootRefused(MiddlewareError)``, the framework's own fatal
path, so boot stops before any consumer or worker thread exists.
"""

from collections.abc import Iterator

import pytest
from dramatiq import Worker
from dramatiq.brokers.stub import StubBroker
from dramatiq.middleware import Middleware, MiddlewareError

import nlw.backup.recovery_lock as rl
import nlw.db.session as dbs
from nlw.worker.broker import RecoveryLockMiddleware, WorkerBootRefused


class _Engine:
    """Stand-in for the sync engine; the preflight itself is monkeypatched."""

    disposed = 0

    def dispose(self) -> None:
        _Engine.disposed += 1


class _AfterBootSpy(Middleware):
    """Records whether the post-boot hook (where metrics bind) ever ran."""

    def __init__(self) -> None:
        self.after_boot_calls = 0

    def after_worker_boot(self, broker: object, worker: object) -> None:
        self.after_boot_calls += 1


@pytest.fixture
def worker_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, object]]:
    """A StubBroker + real RecoveryLockMiddleware whose DB preflight outcome is
    controlled by ``env["outcome"]`` (None = allowed, or an exception to raise)."""
    env: dict[str, object] = {"outcome": None}
    _Engine.disposed = 0
    monkeypatch.setattr(dbs, "create_sync_engine", lambda settings: _Engine())

    def _preflight(engine: object) -> None:
        outcome = env["outcome"]
        if outcome is not None:
            raise outcome  # type: ignore[misc]

    monkeypatch.setattr(rl, "assert_startup_allowed_sync", _preflight)
    broker = StubBroker()
    broker.add_middleware(RecoveryLockMiddleware())
    spy = _AfterBootSpy()
    broker.add_middleware(spy)
    env["broker"] = broker
    env["spy"] = spy
    yield env
    broker.close()


def _consumer_middleware_installed(broker: StubBroker) -> bool:
    return any(type(m).__name__ == "_WorkerMiddleware" for m in broker.middleware)


# --- framework contract the fix depends on -------------------------------------


def test_dramatiq_swallows_plain_exceptions_but_propagates_middleware_error() -> None:
    """Pinned-framework contract: a plain exception from ``before_worker_boot`` is
    swallowed (this is WHY the old lock never aborted boot); a ``MiddlewareError``
    propagates. If dramatiq ever changes this, the fix must be revisited."""

    class Plain(Middleware):
        def before_worker_boot(self, broker: object, worker: object) -> None:
            raise RuntimeError("swallowed by the framework")

    class Fatal(Middleware):
        def before_worker_boot(self, broker: object, worker: object) -> None:
            raise MiddlewareError("fatal")

    plain = StubBroker()
    plain.add_middleware(Plain())
    plain.emit_before("worker_boot", None)  # returns normally: swallowed

    fatal = StubBroker()
    fatal.add_middleware(Fatal())
    with pytest.raises(MiddlewareError):
        fatal.emit_before("worker_boot", None)


def test_worker_boot_refused_is_the_framework_fatal_class() -> None:
    assert issubclass(WorkerBootRefused, MiddlewareError)
    assert not issubclass(WorkerBootRefused, RuntimeError)


# --- real Worker.start() against each recovery state --------------------------


@pytest.mark.parametrize(
    "outcome",
    [
        rl.RecoveryLocked("newest restore generation is quiesced but not validated"),
        rl.RecoveryLocked("newest restore generation is validated but not operator-enabled"),
        rl.RecoveryStateUnknown("cannot connect to check recovery-lock state"),
        rl.RecoveryStateUnknown("malformed restore event (missing id)"),
    ],
    ids=["quiesced-not-validated", "validated-not-enabled", "unreadable", "malformed"],
)
def test_locked_or_unknown_state_aborts_boot_before_any_thread_or_consumer(
    worker_env: dict[str, object], outcome: Exception
) -> None:
    worker_env["outcome"] = outcome
    broker = worker_env["broker"]
    assert isinstance(broker, StubBroker)
    worker = Worker(broker, worker_threads=3)

    with pytest.raises(WorkerBootRefused) as info:
        worker.start()

    # Nothing started: no worker threads, no consumers, no consumer middleware
    # (so a later queue declaration cannot spawn a consumer either), and the
    # post-boot hook (metrics bind) never ran.
    assert worker.workers == []
    assert worker.consumers == {}
    assert not _consumer_middleware_installed(broker)
    broker.declare_queue("default")
    assert worker.consumers == {}
    spy = worker_env["spy"]
    assert isinstance(spy, _AfterBootSpy) and spy.after_boot_calls == 0
    # The engine is always released, and the message is our own controlled
    # reason (class + reason), never driver / DSN text.
    assert _Engine.disposed == 1
    assert type(outcome).__name__ in str(info.value)
    assert str(outcome) in str(info.value)
    assert "postgresql" not in str(info.value)
    assert info.value.__cause__ is None  # no chained driver exception in the traceback


def test_never_restored_db_boots_normally(worker_env: dict[str, object]) -> None:
    worker_env["outcome"] = None  # preflight allows (no restore event / enabled)
    broker = worker_env["broker"]
    assert isinstance(broker, StubBroker)
    worker = Worker(broker, worker_threads=2)
    try:
        worker.start()
        assert len(worker.workers) == 2
        assert _consumer_middleware_installed(broker)
        spy = worker_env["spy"]
        assert isinstance(spy, _AfterBootSpy) and spy.after_boot_calls == 1
        assert _Engine.disposed == 1
    finally:
        worker.stop()


def test_a_later_unenabled_generation_relocks_boot(worker_env: dict[str, object]) -> None:
    """Enabled generation -> boot permitted; a newer un-enabled generation appears
    (a later restore) -> the next boot is refused again."""
    broker = worker_env["broker"]
    assert isinstance(broker, StubBroker)

    worker_env["outcome"] = None  # newest generation validated + enabled
    first = Worker(broker, worker_threads=1)
    first.start()
    first.stop()

    worker_env["outcome"] = rl.RecoveryLocked(
        "newest restore generation is quiesced but not validated"
    )
    second = Worker(StubBroker(), worker_threads=1)
    second.broker.add_middleware(RecoveryLockMiddleware())
    with pytest.raises(WorkerBootRefused):
        second.start()
    assert second.workers == []


def test_engine_construction_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch, worker_env: dict[str, object]
) -> None:
    """If the sync engine cannot even be built (bad DATABASE_URL), the state is
    indeterminate: refuse boot rather than continue."""

    def _broken(settings: object) -> object:
        raise ValueError("bad url")

    monkeypatch.setattr(dbs, "create_sync_engine", _broken)
    broker = worker_env["broker"]
    assert isinstance(broker, StubBroker)
    worker = Worker(broker, worker_threads=1)
    with pytest.raises(WorkerBootRefused, match="unreadable"):
        worker.start()
    assert worker.workers == []


def test_unexpected_preflight_error_fails_closed(worker_env: dict[str, object]) -> None:
    worker_env["outcome"] = KeyError("unexpected")
    broker = worker_env["broker"]
    assert isinstance(broker, StubBroker)
    worker = Worker(broker, worker_threads=1)
    with pytest.raises(WorkerBootRefused, match="preflight failed \\(KeyError\\)"):
        worker.start()
    assert worker.workers == []
    assert _Engine.disposed == 1
