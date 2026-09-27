"""The shipped Caddyfile, run through the REAL Caddy (the image Compose deploys),
serves exactly the reviewed primary + fallback in ONE site whose maintenance 503,
/metrics 404 and reverse proxy therefore apply identically to both hostnames.
No network (`--network none`), no host, no ACME."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from nlw.ops.rollout import gates
from nlw.ops.rollout.gates import GateError

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed"),
]

ROOT = Path(__file__).resolve().parents[2]
CADDYFILE = ROOT / "docker/caddy/Caddyfile"
IMAGE = yaml.safe_load((ROOT / "docker-compose.prod.yml").read_text())["services"]["caddy"]["image"]
PRIMARY = "app.nlwplatform.com"
FALLBACK = "32-197-83-193.sslip.io"


def _caddy(cmd: str, primary: str, fallback: str | None) -> subprocess.CompletedProcess[str]:
    env = ["-e", f"PUBLIC_HOSTNAME={primary}"]
    if fallback is not None:
        env += ["-e", f"PUBLIC_HOSTNAME_FALLBACK={fallback}"]
    return subprocess.run(
        ["docker", "run", "--rm", "--network", "none", *env, "-v",
         f"{CADDYFILE}:/etc/caddy/Caddyfile:ro", IMAGE, "caddy", cmd,
         "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"],
        capture_output=True, text=True, check=False, timeout=120,
    )  # fmt: skip


def _statuses(node: Any) -> list[int]:
    """Every static_response status code anywhere under ``node``."""
    found: list[int] = []
    if isinstance(node, dict):
        if node.get("handler") == "static_response" and "status_code" in node:
            found.append(int(node["status_code"]))
        for value in node.values():
            found += _statuses(value)
    elif isinstance(node, list):
        for value in node:
            found += _statuses(value)
    return found


@pytest.mark.parametrize(
    "fallback,expected",
    [
        (FALLBACK, sorted([PRIMARY, FALLBACK])),
        ("", [PRIMARY]),  # empty fallback: primary only
        (None, [PRIMARY]),  # unset fallback: the sslip-only / rehearsal shape
    ],
)
def test_real_caddy_serves_exactly_the_reviewed_hosts_in_one_site(
    fallback: str | None, expected: list[str]
) -> None:
    validated = _caddy("validate", PRIMARY, fallback)
    assert validated.returncode == 0, validated.stderr[-400:]
    adapted = _caddy("adapt", PRIMARY, fallback)
    assert adapted.returncode == 0, adapted.stderr[-400:]
    assert gates.check_adapted_caddy_hosts(adapted.stdout, PRIMARY, fallback or "") == expected
    routes = json.loads(adapted.stdout)["apps"]["http"]["servers"]["srv0"]["routes"]
    assert len(routes) == 1  # one site: every route below applies to every hostname
    body = json.dumps(routes[0])
    assert 503 in _statuses(routes[0]) and 404 in _statuses(routes[0])  # maintenance, /metrics
    assert "/srv/maint" in body and "MAINTENANCE" in body and '"web:3000"' in body


def test_real_caddy_output_is_rejected_for_an_unreviewed_host_set() -> None:
    adapted = _caddy("adapt", PRIMARY, FALLBACK)
    assert adapted.returncode == 0, adapted.stderr[-400:]
    with pytest.raises(GateError, match="!= reviewed"):
        gates.check_adapted_caddy_hosts(adapted.stdout, PRIMARY, "")
    injected = _caddy("adapt", PRIMARY, f"{FALLBACK} evil.example")  # multi-token injection
    assert injected.returncode == 0, injected.stderr[-400:]
    with pytest.raises(GateError, match="!= reviewed"):
        gates.check_adapted_caddy_hosts(injected.stdout, PRIMARY, FALLBACK)
