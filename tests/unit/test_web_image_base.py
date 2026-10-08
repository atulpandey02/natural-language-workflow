"""Contract: the web image's base is a REVIEWED, explicit Node + Debian pair.

The floating ``node:22-slim`` tag silently tracks Debian 12 "bookworm", whose
perl-base shipped CVE-2026-13221, CVE-2026-42496 and CVE-2026-8376 (CRITICAL)
and failed the gating frontend Trivy scan. Every web build stage must name an
explicit Node patch version and an explicit, reviewed Debian release, the SAME
in every stage (native binaries resolved by ``npm ci`` must match the runtime
glibc). Moving to another release means updating ``REVIEWED_DEBIAN_RELEASES``
here, in review. The Node patch version and the digest are deliberately not
pinned by this test: patch upgrades on the same release stay routine.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "web" / "Dockerfile"
WEB_IMAGE = "nlw-web:ci"

REVIEWED_DEBIAN_RELEASES = {"trixie"}  # Debian 13; bookworm is the vulnerable one
EXPLICIT_BASE = re.compile(r"^node:(?P<node>\d+\.\d+\.\d+)-(?P<release>[a-z]+)-slim$")


def _stages() -> list[tuple[str, str]]:
    stages = []
    for line in DOCKERFILE.read_text().splitlines():
        m = re.match(r"^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$", line, re.IGNORECASE)
        if m:
            stages.append((m.group(1), (m.group(2) or "").lower()))
    return stages


def test_every_web_stage_uses_one_explicit_reviewed_node_debian_base() -> None:
    stages = _stages()
    assert [name for _, name in stages] == ["deps", "build", "runner"]
    bases = {base for base, _ in stages}
    assert len(bases) == 1, f"stages must share one base, got {sorted(bases)}"
    (base,) = bases
    m = EXPLICIT_BASE.match(base)
    assert m, f"{base!r} is not an explicit node:<x.y.z>-<debian-release>-slim tag"
    assert m.group("node").startswith("22."), base  # Node major is a separate decision
    assert m.group("release") in REVIEWED_DEBIAN_RELEASES, (
        f"Debian release {m.group('release')!r} is not reviewed for the web image"
    )


def test_the_runtime_stage_is_not_bookworm_or_a_floating_tag() -> None:
    runner = dict((name, base) for base, name in _stages())["runner"]
    assert "bookworm" not in runner
    assert runner not in {"node:22-slim", "node:22", "node:lts-slim", "node:slim"}


def test_the_web_image_scan_stays_gating_with_no_suppression() -> None:
    doc: dict[str, Any] = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = [s for job in doc["jobs"].values() for s in job.get("steps", [])]
    builds = [s for s in steps if s.get("with", {}).get("tags") == WEB_IMAGE]
    assert len(builds) == 1 and builds[0]["with"]["context"] == "./web"
    scans = [
        s
        for s in steps
        if str(s.get("uses", "")).startswith("aquasecurity/")
        and s["with"].get("image-ref") == WEB_IMAGE
    ]
    assert len(scans) == 1
    scan = scans[0]
    assert scan["with"]["exit-code"] == "1"
    assert scan["with"]["severity"] == "CRITICAL"
    assert scan["with"]["ignore-unfixed"] is True
    assert "continue-on-error" not in scan and "if" not in scan
    for key in ("trivyignores", "ignore-policy", "skip-files", "skip-dirs", "vuln-type"):
        assert key not in scan["with"], key
    assert not (ROOT / ".trivyignore").exists()
    assert not (ROOT / "web" / ".trivyignore").exists()
    assert not (ROOT / ".trivyignore.yaml").exists()
