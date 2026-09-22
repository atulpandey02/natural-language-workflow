"""CI supply-chain pins for the release-authority chain (M12A-Prep §D, ADR-025).

Every GitHub Action in every workflow is referenced by a full immutable commit
SHA (a mutable tag such as ``@v4`` can be re-pointed by the action's
maintainers or an attacker holding their credentials). The Delivery workflow
that mints release authority is additionally checked for the attestation
steps, the permissions they need, the trusted-trigger shape and the proof job.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
PINNED = re.compile(r"^(?P<action>[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-/]+)@(?P<sha>[0-9a-f]{40})$")
USES_LINE = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)\s*(?P<comment>#.*)?$")

ATTEST = "actions/attest-build-provenance"


def _jobs(path: Path) -> dict[str, Any]:
    doc = yaml.safe_load(path.read_text())
    return dict(doc.get("jobs") or {})


def _uses(job: dict[str, Any]) -> list[str]:
    return [str(s["uses"]) for s in job.get("steps") or [] if isinstance(s, dict) and "uses" in s]


def test_every_action_in_every_workflow_is_pinned_to_a_full_commit_sha() -> None:
    unpinned: list[str] = []
    for wf in WORKFLOWS:
        for lineno, line in enumerate(wf.read_text().splitlines(), 1):
            m = USES_LINE.match(line)
            if not m:
                continue
            ref = m.group("ref")
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            if not PINNED.match(ref):
                unpinned.append(f"{wf.name}:{lineno}: {ref}")
            elif not (m.group("comment") or "").lstrip("# ").startswith("v"):
                unpinned.append(
                    f"{wf.name}:{lineno}: {ref} (missing human-readable version comment)"
                )
    assert not unpinned, "mutable or uncommented action references:\n" + "\n".join(unpinned)


def test_release_authority_chain_is_pinned_attested_and_trusted_trigger_only() -> None:
    wf = ROOT / ".github" / "workflows" / "staging.yml"
    doc = yaml.safe_load(wf.read_text())
    # Only `push` to main mints release authority: no dispatch, no PR, no schedule.
    on = doc.get("on") or doc.get(True)  # PyYAML parses the bare key `on` as True
    assert set(on) == {"push"} and on["push"]["branches"] == ["main"]
    jobs = _jobs(wf)
    build = jobs["build-push"]
    proof = jobs["release-authority-proof"]
    for job in (build, proof):
        for ref in _uses(job):
            assert PINNED.match(ref), f"release-authority chain must be SHA-pinned: {ref}"
    # checkout, login, build/push, uv, attest, upload — all present and pinned by SHA.
    names = [ref.split("@")[0] for ref in _uses(build)]
    for needed in (
        "actions/checkout",
        "docker/login-action",
        "docker/build-push-action",
        "astral-sh/setup-uv",
        ATTEST,
        "actions/upload-artifact",
    ):
        assert needed in names, f"{needed} missing from build-push"
    assert names.count(ATTEST) == 3, "manifest, backend image and web image are each attested"
    assert "actions/download-artifact" in [ref.split("@")[0] for ref in _uses(proof)]
    perms = build["permissions"]
    assert perms["id-token"] == "write" and perms["attestations"] == "write"
    assert perms["contents"] == "read" and perms["packages"] == "write"
    # The attestation steps come AFTER both builds and the manifest generation,
    # and the upload comes after the manifest attestation.
    order = [f"{s.get('id', '')} {s.get('name', '')} {s.get('uses', '')}" for s in build["steps"]]

    def idx(needle: str) -> int:
        return next(i for i, n in enumerate(order) if needle in n)

    assert idx("build_web") < idx("Generate + validate the release manifest")
    assert idx("Generate + validate") < idx("Attest the release manifest")
    assert idx("Attest the release manifest") < idx("upload-artifact")
    # The proof job verifies real provenance with the SAME evaluator the operator uses.
    proof_text = "\n".join(str(s.get("run", "")) for s in proof["steps"])
    assert "nlw.ops.release_provenance verify release-manifest.json" in proof_text
    assert "--within-run" in proof_text and "release.example.json" in proof_text
    assert "nlw.ops.rollout.image_info" in proof_text
    # PR CI runs the REAL attestation path and proves PR provenance is rejected.
    ci_jobs = _jobs(ROOT / ".github" / "workflows" / "ci.yml")
    neg = ci_jobs["release-provenance-pr-negative-proof"]
    assert neg["permissions"]["id-token"] == "write"
    neg_text = "\n".join(str(s.get("run", "")) for s in neg["steps"])
    assert "--expect-rejected" in neg_text and "--relaxed-cli" in neg_text
    assert "upload-artifact" not in " ".join(_uses(neg)), "PR manifests are never uploaded"
    assert "pull_request" in str(neg.get("if"))
    assert "head.repo.full_name == github.repository" in str(neg.get("if"))
