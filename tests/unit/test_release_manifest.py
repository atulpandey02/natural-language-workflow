"""External release manifest: generation, validation, and rejection of
templates/fixtures/old images (M12A-Prep §A/§B/§H)."""

from __future__ import annotations

import json
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from nlw.ops import release_manifest as rm
from nlw.ops.rollout import gates
from nlw.ops.rollout.gates import GateError
from nlw.ops.rollout.release import load_release

ROOT = Path(__file__).resolve().parents[2]
COMMITTED_TARGET_ENV = ROOT / "deploy" / "staging" / "target.env"


def _target_env_at(revision: str) -> Path:
    """The committed target.env with the live revision rewritten: the generator
    tests describe a 0010 -> 0016 roll and must not depend on what the staging
    host is at today (0020 since the first rollout)."""
    text = COMMITTED_TARGET_ENV.read_text()
    text = re.sub(
        r"(?m)^NLW_STAGING_CURRENT_REVISION=.*$", f"NLW_STAGING_CURRENT_REVISION={revision}", text
    )
    p = Path(tempfile.mkdtemp(prefix="nlw-target-env-")) / "target.env"
    p.write_text(text)
    return p


TARGET_ENV = _target_env_at("0010_readiness_schema_grant")
SHA = "1eebf2ef19c0286c83bfe8768c908bfd2f40178d"
BACKEND = "ghcr.io/atulpandey02/natural-language-workflow@sha256:" + "a" * 64
WEB = "ghcr.io/atulpandey02/natural-language-workflow/web@sha256:" + "b" * 64
CI_ENV = {
    "GITHUB_WORKFLOW": "Delivery",
    "GITHUB_RUN_ID": "123",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "atulpandey02/natural-language-workflow",
    "GITHUB_ACTOR": "ci",
}
NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


def _gen(**over: Any) -> dict[str, Any]:
    kw: dict[str, Any] = {
        "target_env": TARGET_ENV,
        "release_sha": SHA,
        "backend_image": BACKEND,
        "web_image": WEB,
        "generated_by": "ci",
        "target_revision": "0016_signed_database_context",
        "now": NOW,
        "ci_env": CI_ENV,
    }
    kw.update(over)
    return rm.generate(**kw)


def test_generator_reads_target_env_and_ci_identity_and_validates() -> None:
    doc = _gen()
    assert doc["kind"] == "release" and doc["deployable"] is True
    assert doc["instance_id"] == "i-0d1e65cdc9401dbb9" and doc["compose_project"] == "app"
    assert doc["expected_current_revision"] == "0010_readiness_schema_grant"
    assert doc["key_ids"] == {
        "api": "stg-api-2026-09",
        "worker": "stg-worker-2026-09",
        "scheduler": "stg-scheduler-2026-09",
    }
    assert doc["ci"]["run_url"].endswith("/actions/runs/123")
    m = rm.parse_manifest(doc, raw_bytes=json.dumps(doc).encode())
    assert m.backend_digest == "sha256:" + "a" * 64 and len(m.sha256) == 64


def test_generator_derives_target_revision_from_this_checkout() -> None:
    doc = _gen(target_revision=None)
    assert doc["target_revision"] == "0020_schedule_authorization"


def test_committed_target_env_is_at_the_live_revision_and_needs_a_new_migration_to_roll() -> None:
    """The host is at 0020 (first rollout done). A release WITHOUT a new migration
    has nothing for the phased rollout to roll: the generator refuses instead of
    producing a manifest whose expected == target (known limitation)."""
    text = COMMITTED_TARGET_ENV.read_text()
    assert "NLW_STAGING_CURRENT_REVISION=0020_schedule_authorization" in text
    with pytest.raises(rm.ReleaseManifestError, match="nothing to roll"):
        _gen(target_env=COMMITTED_TARGET_ENV, target_revision=None)


def test_committed_example_is_rejected_in_every_mode() -> None:
    example = ROOT / "deploy" / "staging" / "release.example.json"
    for local in (False, True):
        with pytest.raises(rm.ReleaseManifestError, match="not a deployable"):
            load_release(example, local=local)
    assert not (ROOT / "deploy" / "staging" / "release.json").exists()  # no committed authority


def test_local_rehearsal_manifest_is_not_authority_for_a_real_target() -> None:
    doc = _gen(generated_by="local-rehearsal")
    with pytest.raises(rm.ReleaseManifestError, match="local-rehearsal"):
        rm.parse_manifest(doc, local=False)
    rm.parse_manifest(doc, local=True)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(kind="fixture"),
        lambda d: d.update(deployable=False),
        lambda d: d.update(backend_image="ghcr.io/o/r:latest"),
        lambda d: d.update(release_sha="1eebf2e"),
        lambda d: d.update(ci={}),
        lambda d: d.update(format_version=1),
        lambda d: d.update(key_ids={"api": "x", "worker": "x", "scheduler": "x"}),
        lambda d: d.update(escrow_secret="abc"),
        lambda d: d.update(expected_current_revision="0016_signed_database_context"),
    ],
)
def test_malformed_or_secret_bearing_manifests_are_rejected(mutate: Any) -> None:
    doc = _gen()
    mutate(doc)
    with pytest.raises(rm.ReleaseManifestError):
        rm.parse_manifest(doc)


def test_cli_generate_then_validate_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for k, v in CI_ENV.items():
        monkeypatch.setenv(k, v)
    out = tmp_path / "m.json"
    rc = rm.main(
        ["generate", "--target-env", str(TARGET_ENV), "--release-sha", SHA, "--backend-image",
         BACKEND, "--web-image", WEB, "--generated-by", "ci", "--out", str(out)]
    )  # fmt: skip
    assert rc == 0 and out.exists()
    assert rm.main(["validate", str(out)]) == 0
    assert rm.main(["validate", str(ROOT / "deploy/staging/release.example.json")]) == 3
    text = out.read_text().lower()
    for needle in ("password", "secret", "token", "aws_"):
        assert needle not in text


# --- §B: capability preflight against image metadata ------------------------------
GOOD_INFO: dict[str, Any] = {
    "git_sha": SHA,
    "alembic_head": "0016_signed_database_context",
    "migrations": [f"{n:04d}_x.py" for n in range(1, 17)],
    "modules": {
        m: True
        for m in (
            "nlw.ops.rollout",
            "nlw.ops.roles",
            "nlw.ctxkeys",
            "nlw.backup.__main__",
            "nlw.ops.rollout.smoke",
        )
    },
}


def _release() -> rm.ReleaseManifest:
    return rm.parse_manifest(_gen())


def test_release_image_metadata_passes() -> None:
    gates.check_image_info(GOOD_INFO, _release())


def test_old_p3b_image_metadata_is_rejected_as_incapable() -> None:
    """Recorded facts of the ghcr image built from 1eebf2e (P3B merge): it predates
    the M12A tooling — no NLW_GIT_SHA, no nlw.ops.rollout/roles, no evidence
    command — so its image_info probe cannot even run. Its metadata must fail
    BEFORE keys, roles, maintenance mode or any database change."""
    old_image_probe_failed: dict[str, Any] = {}  # `python -m nlw.ops.rollout.image_info` exits 1
    with pytest.raises(GateError, match="not the release artifact"):
        gates.check_image_info(old_image_probe_failed, _release())
    # Even if such an image reported the migrations, missing modules/head fail.
    partial = dict(
        GOOD_INFO, git_sha=SHA, modules={"nlw.ops.rollout": False, "nlw.ops.roles": False}
    )
    with pytest.raises(GateError, match="required module"):
        gates.check_image_info(partial, _release())
    stale_head = dict(GOOD_INFO, alembic_head="0015_membership_approval_sod")
    with pytest.raises(GateError, match="migration head"):
        gates.check_image_info(stale_head, _release())
    missing_mig = dict(GOOD_INFO, migrations=[f"{n:04d}_x.py" for n in range(1, 15)])
    with pytest.raises(GateError, match="lacks migration"):
        gates.check_image_info(missing_mig, _release())
    foreign = dict(GOOD_INFO, git_sha="f" * 40)
    with pytest.raises(GateError, match="not the release artifact"):
        gates.check_image_info(foreign, _release())
