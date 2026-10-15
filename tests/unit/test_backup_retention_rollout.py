"""O-5 backup retention at rollout (ADR-035): the rollout gate's model of the
effective retention (an env-file value overrides the Compose default) matches
what Docker Compose actually renders, and a host env file still carrying the
pre-O-5 14/8/6 is caught before activation. Rendering only: nothing is run."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from nlw.ops.rollout import gates

ROOT = Path(__file__).resolve().parents[2]
KEYS = gates.BACKUP_RETENTION_KEYS


def _render(tmp_path: Path, env_file: str) -> dict[str, str]:
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose is required for rendered-Compose tests")
    env = {
        key: f"fixture-{key}"
        for key in re.findall(r"\$\{([A-Z_]+):\?", (ROOT / "docker-compose.prod.yml").read_text())
    }
    env.update(
        PATH=os.environ["PATH"],
        NLW_CTX_KEYS_DIR="/srv/nlw/ctx-keys",
        REDIS_URL="redis://localhost:6379/0",
        SUPABASE_URL="https://fixture.supabase.co",
    )
    for key in KEYS:  # the test runner's own environment must not leak in
        env.pop(key, None)
    args = ["docker", "compose", "--project-directory", str(tmp_path), "--env-file", env_file,
            "-p", "nlw-retention-test", "-f", str(ROOT / "docker-compose.prod.yml"),
            "--profile", "*", "config", "--format", "json"]  # fmt: skip
    result = subprocess.run(args, env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    doc: dict[str, Any] = json.loads(result.stdout)
    services = [s for s in doc["services"].values() if KEYS[0] in (s.get("environment") or {})]
    assert len(services) == 1, "exactly one service (backup) carries the retention"
    return {k: str(services[0]["environment"][k]) for k in KEYS}


O5 = dict(zip(KEYS, ("30", "0", "12"), strict=True))


@pytest.mark.parametrize(
    "env_text, rendered, refused",
    [
        ("", O5, None),  # no override: the release's Compose defaults
        ("\n".join(f"{k}={v}" for k, v in O5.items()) + "\n", O5, None),
        ("NLW_BACKUP_RETENTION_DAILY=14\nNLW_BACKUP_RETENTION_WEEKLY=8\n"
         "NLW_BACKUP_RETENTION_MONTHLY=6\n", dict(zip(KEYS, ("14", "8", "6"), strict=True)),
         "pre-O-5 14/8/6"),
        ("NLW_BACKUP_RETENTION_MONTHLY=6\n", {**O5, "NLW_BACKUP_RETENTION_MONTHLY": "6"},
         "MONTHLY must be 12"),
    ],
    ids=["defaults", "explicit-o5", "legacy-14-8-6", "partial-override"],
)  # fmt: skip
def test_the_gate_models_compose_and_refuses_anything_but_o5(
    tmp_path: Path, env_text: str, rendered: dict[str, str], refused: str | None
) -> None:
    env_file = tmp_path / "backup.env"
    env_file.write_text(env_text)
    # What Compose would run the backup job with...
    assert _render(tmp_path, str(env_file)) == rendered
    # ...is what the gate computes from the retention lines alone.
    lines = "\n".join(line for line in env_text.splitlines() if "NLW_BACKUP_RETENTION" in line)
    assert gates.effective_backup_retention(lines) == rendered
    if refused is None:
        assert gates.check_backup_retention(lines) == O5
    else:
        with pytest.raises(gates.GateError, match=refused):
            gates.check_backup_retention(lines)


def test_the_runbooks_say_compose_defaults_do_not_update_an_env_file() -> None:
    for doc in ("docs/runbooks/backup-operations.md", "docs/ops/backup-systemd.md",
                "docs/adr/ADR-035-phase2-retention-policy.md"):  # fmt: skip
        text = " ".join((ROOT / doc).read_text().split())
        assert "not update an existing env file" in text, doc


# --- the operator's shell can never override the reviewed retention ----------------------
#
# Compose ranks the shell environment ABOVE --env-file and the defaults. Every
# rollout Compose invocation is prefixed with `env -u ...` for the retention keys
# (remote.AMBIENT_UNSET), so the reviewed backup env file and the Compose
# defaults are the only sources: the same ones the preflight gate reads.

from dataclasses import replace  # noqa: E402

from test_edge_hostnames import TARGET  # noqa: E402

from nlw.ops.rollout.remote import AMBIENT_UNSET, load_target  # noqa: E402

LEGACY = dict(zip(KEYS, ("14", "8", "6"), strict=True))
EXPORTED_LEGACY = dict(LEGACY)  # as if exported in the operator's shell


def _rollout_render(
    tmp_path: Path, env_file_text: str, *, shell: dict[str, str], protected: bool = True
) -> dict[str, str]:
    """Render the backup profile with the EXACT command the rollout runs."""
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose is required for rendered-Compose tests")
    shutil.copyfile(ROOT / "docker-compose.prod.yml", tmp_path / "docker-compose.prod.yml")
    (tmp_path / ".env.prod").write_text("")
    (tmp_path / "backup.env").write_text(env_file_text)
    target = replace(
        load_target(TARGET), operator_alerting=None, backup_env_file=str(tmp_path / "backup.env")
    )
    command = target.dc_backup_in(str(tmp_path))
    if not protected:  # the unprotected form, as a control
        command = re.sub(r"env( -u [A-Z_]+)+ ", "", command)
    env = {
        key: f"fixture-{key}"
        for key in re.findall(r"\$\{([A-Z_]+):\?", (ROOT / "docker-compose.prod.yml").read_text())
    }
    env.update(PATH=os.environ["PATH"], NLW_CTX_KEYS_DIR="/srv/nlw/ctx-keys",
               REDIS_URL="redis://localhost:6379/0", SUPABASE_URL="https://fixture.supabase.co",
               **shell)  # fmt: skip
    result = subprocess.run(
        ["bash", "-c", command + " config --format json"],
        env=env, capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    doc = json.loads(result.stdout)
    [svc] = [s for s in doc["services"].values() if KEYS[0] in (s.get("environment") or {})]
    return {k: str(svc["environment"][k]) for k in KEYS}


def _lines(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if "NLW_BACKUP_RETENTION" in line)


@pytest.mark.parametrize(
    "env_file_text, rendered, refused",
    [
        ("", O5, None),  # absent values: the Compose defaults
        ("\n".join(f"{k}={v}" for k, v in O5.items()) + "\n", O5, None),  # explicit O-5
        ("\n".join(f"{k}={v}" for k, v in LEGACY.items()) + "\n", LEGACY, "pre-O-5 14/8/6"),
    ],
    ids=["absent", "explicit-o5", "env-file-legacy"],
)
def test_exported_14_8_6_cannot_change_what_the_rollout_renders_or_checks(
    tmp_path: Path, env_file_text: str, rendered: dict[str, str], refused: str | None
) -> None:
    got = _rollout_render(tmp_path, env_file_text, shell=EXPORTED_LEGACY)
    assert got == rendered  # the shell's 14/8/6 never reached Compose
    # The preflight gate computes the same values from the env file alone, so
    # the retention it checks is the one the backup build/run/evidence use.
    assert gates.effective_backup_retention(_lines(env_file_text)) == got
    if refused is None:
        assert gates.check_backup_retention(_lines(env_file_text)) == O5
    else:
        with pytest.raises(gates.GateError, match=refused):
            gates.check_backup_retention(_lines(env_file_text))


def test_without_the_prefix_the_shell_would_win(tmp_path: Path) -> None:
    """Control: the protection is what keeps the shell out."""
    assert _rollout_render(tmp_path, "", shell=EXPORTED_LEGACY, protected=False) == LEGACY


def test_every_backup_compose_invocation_is_sanitized_and_nothing_else_is_removed(
    tmp_path: Path,
) -> None:
    for key in KEYS:
        assert key in AMBIENT_UNSET
    reviewed = (
        "DEMO_TOOLS_ENABLED", "PUBLIC_HOSTNAME", "PUBLIC_HOSTNAME_FALLBACK",
        "NLW_LLM_PROVIDER", "NLW_LLM_MODEL", "NLW_LLM_API_KEY", *KEYS,
    )  # fmt: skip
    assert reviewed == AMBIENT_UNSET
    target = replace(load_target(TARGET), operator_alerting=None)
    prefix = "env " + " ".join(f"-u {k}" for k in AMBIENT_UNSET) + " docker compose"
    for command in (target.dc_backup_in("/srv/x"), target.dc_in("/srv/x")):
        assert prefix in command
    # The rollout never builds a Compose command anywhere else.
    phases = (ROOT / "src/nlw/ops/rollout/phases.py").read_text()
    assert not re.search(r"f[\"']docker compose", phases)
    assert "dc_backup_in(self.staged)} build" in phases
    assert "dc_backup_in(self.staged)} run --rm --no-deps -T {env} backup" in phases
    assert "dc_backup_in(self.staged)} run --rm --no-deps -T backup evidence" in phases
    # `env -u` removes exactly these names; every other variable passes through.
    unrelated = {
        "PATH": os.environ["PATH"], "HOME": "/home/ops", "AWS_REGION": "us-east-1",
        "RESTIC_REPOSITORY": "s3:example.invalid/r", "NLW_BACKUP_DATABASE_URL": "postgresql://x",
        "NLW_BACKUP_RETENTION_MODE": "simple", "NLW_BACKUP_RETENTION_DAILYX": "keep-me",
    }  # fmt: skip
    env = {**unrelated, **EXPORTED_LEGACY, "PUBLIC_HOSTNAME": "evil.example"}
    out = subprocess.run(
        ["bash", "-c", "env " + " ".join(f"-u {k}" for k in AMBIENT_UNSET) + " env"],
        env=env, capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    seen = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    for name, value in unrelated.items():
        assert seen.get(name) == value, name
    for name in AMBIENT_UNSET:
        assert name not in seen, name


def test_the_rollout_runbook_says_the_shell_overrides_are_sanitized() -> None:
    text = " ".join((ROOT / "docs/runbooks/staging-signed-context-rollout.md").read_text().split())
    for key in AMBIENT_UNSET:
        assert f"-u {key}" in text, key
    assert "rollout sanitizes the three `NLW_BACKUP_RETENTION_*` shell variables" in text
    assert "Nothing else is removed from the environment." in text
