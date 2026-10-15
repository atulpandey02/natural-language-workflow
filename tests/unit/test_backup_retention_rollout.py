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
