"""Command execution against the rollout target (M12A-Prep §B/§D).

``SshRemote`` runs commands on the staging host as the operator user (docker
group; no sudo). ``LocalRemote`` runs the same commands locally for the
disposable rehearsal. Both return sanitized results; callers never place
secrets on the command line — anything sensitive travels on stdin or stays in
host-side files.

Host layout (``TargetConfig``): ``<ops_root>/app`` is the ACTIVE checkout the
running services were started from; a release is STAGED in
``<ops_root>/releases/<sha>`` with its own ``.env.prod`` and is only activated
(``<ops_root>/current`` symlink + container recreation) after the verified
backup and the migration; rollout state lives in ``<ops_root>/rollout``.
"""

from __future__ import annotations

import contextlib
import os
import re
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

_TARGET_KEYS = (
    "NLW_STAGING_INSTANCE_ID",
    "NLW_STAGING_SSH_HOST",
    "NLW_STAGING_SSH_USER",
    "NLW_STAGING_REMOTE_APP",
    "NLW_STAGING_COMPOSE_PROJECT",
)


class TargetConfigError(ValueError):
    pass


@dataclass(frozen=True)
class TargetConfig:
    instance_id: str
    ssh_host: str
    ssh_user: str
    ssh_key: Path
    remote_app: str  # the ACTIVE checkout (M11 today)
    compose_project: str
    ops_root: str = "/opt/nlw"
    compose_files: tuple[str, ...] = ("docker-compose.prod.yml", "docker-compose.staging.yml")
    # The backup job's env file (restic repository + credentials) — the SAME file
    # the systemd timer uses; never merged into .env.prod.
    backup_env_file: str = "/opt/nlw/.env.backup"

    # ---- layout ---------------------------------------------------------------
    def release_dir(self, sha: str) -> str:
        return f"{self.ops_root}/releases/{sha}"

    @property
    def current_link(self) -> str:
        return f"{self.ops_root}/current"

    @property
    def state_dir(self) -> str:
        return f"{self.ops_root}/rollout"

    def state_path(self, sha: str) -> str:
        return f"{self.state_dir}/{sha}.json"

    # ---- compose invocations --------------------------------------------------
    def dc_in(self, directory: str) -> str:
        """The reviewed Compose invocation from ``directory`` (explicit project
        name so a staged release joins the running project; never e2e)."""
        files = " ".join(f"-f {f}" for f in self.compose_files)
        return (
            f"cd '{directory}' && docker compose -p {self.compose_project} "
            f"--env-file .env.prod {files}"
        )

    @property
    def dc(self) -> str:
        """Compose against the ACTIVE checkout (read/stop/exec only)."""
        return self.dc_in(self.remote_app)

    def dc_backup_in(self, directory: str) -> str:
        """Backup profile from ``directory``, mirroring docker/systemd/nlw-backup.service."""
        return (
            f"cd '{directory}' && docker compose -p {self.compose_project} "
            f"--env-file .env.prod --env-file '{self.backup_env_file}' "
            f"-f docker-compose.prod.yml --profile backup"
        )


def parse_target_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        values[k.strip()] = v.strip().strip('"')
    missing = [k for k in _TARGET_KEYS if not values.get(k)]
    if missing:
        raise TargetConfigError(f"target config missing: {missing}")
    if not re.match(r"^i-[0-9a-f]{8,17}$", values["NLW_STAGING_INSTANCE_ID"]):
        raise TargetConfigError("NLW_STAGING_INSTANCE_ID is not an EC2 instance id")
    if not re.match(r"^[A-Za-z0-9.\-]+$", values["NLW_STAGING_SSH_HOST"]):
        raise TargetConfigError("NLW_STAGING_SSH_HOST must be a hostname or IP")
    if not values["NLW_STAGING_REMOTE_APP"].startswith("/"):
        raise TargetConfigError("NLW_STAGING_REMOTE_APP must be absolute")
    return values


def load_target(path: Path, *, ssh_key: Path | None = None) -> TargetConfig:
    try:
        values = parse_target_env(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TargetConfigError(f"target config not found: {path}") from exc
    key = ssh_key or Path(os.environ.get("NLW_STAGING_SSH_KEY", "~/.ssh/nlw-staging-key.pem"))
    files = values.get("NLW_STAGING_COMPOSE_FILES", "")
    compose_files = tuple(f for f in files.split() if f) or (
        "docker-compose.prod.yml",
        "docker-compose.staging.yml",
    )
    if any("e2e" in f for f in compose_files):
        raise TargetConfigError("the e2e overlay must never be part of a real/rehearsal target")
    remote_app = values["NLW_STAGING_REMOTE_APP"]
    ops_root = values.get("NLW_STAGING_OPS_ROOT") or str(Path(remote_app).parent)
    return TargetConfig(
        instance_id=values["NLW_STAGING_INSTANCE_ID"],
        ssh_host=values["NLW_STAGING_SSH_HOST"],
        ssh_user=values["NLW_STAGING_SSH_USER"],
        ssh_key=key.expanduser(),
        remote_app=remote_app,
        compose_project=values["NLW_STAGING_COMPOSE_PROJECT"],
        ops_root=ops_root,
        compose_files=compose_files,
        backup_env_file=values.get("NLW_STAGING_BACKUP_ENV_FILE") or f"{ops_root}/.env.backup",
    )


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def text(self) -> str:
        return self.stdout.replace("\r", "").strip()


class Remote(Protocol):
    def run(
        self, command: str, *, stdin: str | None = None, timeout: int = 300
    ) -> CommandResult: ...

    def describe(self) -> str: ...

    @property
    def is_local(self) -> bool: ...


class SshRemote:
    is_local = False

    def __init__(self, target: TargetConfig) -> None:
        self._t = target

    def describe(self) -> str:
        return f"{self._t.ssh_user}@{self._t.ssh_host} (expects {self._t.instance_id})"

    def run(self, command: str, *, stdin: str | None = None, timeout: int = 300) -> CommandResult:
        argv = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=15",
            "-o", "StrictHostKeyChecking=accept-new",
            "-i", str(self._t.ssh_key),
            f"{self._t.ssh_user}@{self._t.ssh_host}",
            command,
        ]  # fmt: skip
        try:
            p = subprocess.run(  # noqa: S603 - fixed argv; the command is ours
                argv, input=stdin, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired:
            return CommandResult(124, "", "timed out")
        return CommandResult(p.returncode, p.stdout, p.stderr)


class LocalRemote:
    """Rehearsal executor: the same shell commands, run locally with bash."""

    is_local = True

    def __init__(self, label: str = "LOCAL REHEARSAL (not the VPS)") -> None:
        self._label = label

    def describe(self) -> str:
        return self._label

    def run(self, command: str, *, stdin: str | None = None, timeout: int = 300) -> CommandResult:
        # A developer machine has no EC2 IMDS. The rehearsal supplies a canned
        # identity (instance-id / region / public-ipv4 lines) via the environment;
        # everything else runs for real. Never consulted by SshRemote.
        canned = os.environ.get("NLW_REHEARSAL_IDENTITY")
        if "169.254.169.254" in command and canned:
            return CommandResult(0, canned + "\n", "")
        # Own process group so a timeout kills `docker compose run` and every
        # child too (never an orphaned one-shot container after a STOP).
        proc = subprocess.Popen(  # noqa: S603
            ["bash", "-c", command],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            out, err = proc.communicate(input=stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            return CommandResult(124, "", "timed out")
        return CommandResult(proc.returncode, out, err)
