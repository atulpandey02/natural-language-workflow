"""Restore runtime-service guard (M11.5 P2 addendum B).

A running-but-idle api/worker/scheduler/web (no current DB session) must still block
a restore. The guard inspects Compose state scoped to the EXACT project + service
names and fails closed when state is undeterminable.
"""

import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from nlw.backup.runtime_guard import (
    ComposeRuntimeProbe,
    NullRuntimeProbe,
    RuntimeActive,
    RuntimeStateUnknown,
    assert_runtime_stopped,
)


def _fake_run(stdout: str, returncode: int = 0):  # type: ignore[no-untyped-def]
    def run(cmd: Any, **kwargs: Any) -> Any:
        # Assert the probe scopes to a project and asks for running services only.
        assert "-p" in cmd and "ps" in cmd and "--status" in cmd
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")

    return run


def test_running_runtime_service_blocks_even_without_db_session() -> None:
    # `worker` is up (idle, no DB session) -> must block.
    probe = ComposeRuntimeProbe(project="nlw-restore-x", run=_fake_run("worker\n"))
    with pytest.raises(RuntimeActive, match="worker"):
        assert_runtime_stopped(probe)


def test_only_support_services_running_is_permitted() -> None:
    # Only restore/postgres/redis/minio support services -> allowed.
    probe = ComposeRuntimeProbe(
        project="nlw-restore-x", run=_fake_run("postgres\nredis\nminio\nrestore\n")
    )
    assert_runtime_stopped(probe)  # no raise


def test_probe_scoped_intersection_flags_only_runtime_services() -> None:
    probe = ComposeRuntimeProbe(project="p", run=_fake_run("postgres\nscheduler\nredis\n"))
    assert probe.running_runtime_services() == {"scheduler"}


def test_missing_project_fails_closed() -> None:
    probe = ComposeRuntimeProbe(project="", run=_fake_run(""))
    with pytest.raises(RuntimeStateUnknown):
        assert_runtime_stopped(probe)


def test_docker_error_fails_closed() -> None:
    probe = ComposeRuntimeProbe(project="p", run=_fake_run("", returncode=1))
    with pytest.raises(RuntimeStateUnknown):
        assert_runtime_stopped(probe)


def test_docker_absent_fails_closed() -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise FileNotFoundError("docker not found")

    probe = ComposeRuntimeProbe(project="p", run=boom)
    with pytest.raises(RuntimeStateUnknown):
        assert_runtime_stopped(probe)


def test_docker_timeout_fails_closed() -> None:
    def slow(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired("docker", 30)

    probe = ComposeRuntimeProbe(project="p", run=slow)
    with pytest.raises(RuntimeStateUnknown):
        assert_runtime_stopped(probe)


def test_null_probe_is_permitted_structural_isolation() -> None:
    assert_runtime_stopped(NullRuntimeProbe())  # no raise
