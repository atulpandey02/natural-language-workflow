"""Runtime-service guard for restore (M11.5 P2 addendum B).

A database-session check alone is insufficient: an api/worker/scheduler/web
container can be running but idle (no current DB connection) and reconnect the
instant after the check. So the restore ALSO inspects Compose runtime state,
scoped to the EXACT validated Compose project and the EXACT expected service names
(never a global container scan / partial-name guess), and fails closed if any
runtime service is running OR if the state cannot be determined.

The probe is injectable so the six required cases are testable without Docker.
"""

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# The runtime services that must NOT be running during a restore.
RUNTIME_SERVICES = ("api", "worker", "scheduler", "web")


class RuntimeStateUnknown(RuntimeError):
    """The runtime state could not be determined — restore must fail closed."""


class RuntimeActive(RuntimeError):
    """A runtime service is running in the restore project — restore refused."""


RunFn = Callable[..., "subprocess.CompletedProcess[str]"]


@dataclass
class ComposeRuntimeProbe:
    """Probe running services in a specific Compose project via the docker CLI.

    Scoped by ``project``; returns only the running services whose names are in
    RUNTIME_SERVICES. Raises :class:`RuntimeStateUnknown` if the project is unset or
    docker cannot be queried (so the caller fails closed).
    """

    project: str
    run: RunFn = field(default=subprocess.run)

    def running_runtime_services(self) -> set[str]:
        if not self.project:
            raise RuntimeStateUnknown(
                "no Compose project to scope the runtime-state check (set "
                "NLW_RESTORE_COMPOSE_PROJECT)"
            )
        try:
            res = self.run(
                [
                    "docker",
                    "compose",
                    "-p",
                    self.project,
                    "ps",
                    "--status",
                    "running",
                    "--format",
                    "{{.Service}}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeStateUnknown("cannot inspect Compose runtime state") from exc
        if res.returncode != 0:
            raise RuntimeStateUnknown(
                f"`docker compose ps` failed (exit {res.returncode}) for project {self.project}"
            )
        running = {line.strip() for line in (res.stdout or "").splitlines() if line.strip()}
        return running & set(RUNTIME_SERVICES)


@dataclass
class NullRuntimeProbe:
    """Structural-isolation probe: the restore Compose project defines no runtime
    services, so none can be running. Used only where ``runtime_guard='off'`` (local
    drills that run the scoped docker check on the host instead)."""

    def running_runtime_services(self) -> set[str]:
        return set()


@runtime_checkable
class RuntimeProbe(Protocol):
    def running_runtime_services(self) -> set[str]: ...


def assert_runtime_stopped(probe: RuntimeProbe) -> None:
    """Fail closed unless the probe proves no runtime service is running.

    Raises :class:`RuntimeStateUnknown` (undeterminable) or :class:`RuntimeActive`
    (a runtime service is up). Callers invoke this both early and again immediately
    before the destructive restore (TOCTOU: a service starting in between is caught
    by the later call).
    """
    running = probe.running_runtime_services()  # may raise RuntimeStateUnknown
    if running:
        raise RuntimeActive(
            "restore refused: runtime services are running in the restore project: "
            f"{sorted(running)}. Stop api/worker/scheduler/web first."
        )
