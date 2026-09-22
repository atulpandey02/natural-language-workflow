"""Release-manifest provenance policy (M12A-Prep §A, ADR-025).

Three separate things are checked before a manifest is release authority:
schema validity, image capability/identity, and PROVENANCE. These tests first
reproduce the weakness (a hand-written manifest satisfies the first two) and
then prove the provenance policy rejects every substitution in the threat model
using committed fixtures in the exact ``gh attestation verify --format json``
shape. No network, no gh, no real signature: gh's cryptographic verification is
exercised end to end by CI (Delivery proof job + PR negative proof).
"""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from nlw.ops import release_manifest as rm
from nlw.ops import release_provenance as rp
from nlw.ops.release_provenance import (
    LOCAL_FIXTURE_POLICY,
    TRUSTED_POLICY,
    FixtureVerifier,
    GhVerifier,
    ProvenanceError,
    build_fixture,
    evaluate_attestation,
    evaluate_run,
    verify_manifest_file,
    verify_release_provenance,
)
from nlw.ops.rollout import gates

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests" / "fixtures" / "provenance"
MANIFEST = rm.load_manifest(FIX / "manifest.json")
DIGEST = rp.sha256_hex(MANIFEST.raw.encode())
SHA = MANIFEST.release_sha
RUN_ID = MANIFEST.ci["run_id"]


def _load(name: str) -> Any:
    return json.loads((FIX / name).read_text())


ATT_MANIFEST: list[dict[str, Any]] = _load("trusted-manifest-attestation.json")
ATT_BACKEND: list[dict[str, Any]] = _load("trusted-backend-attestation.json")
ATT_WEB: list[dict[str, Any]] = _load("trusted-web-attestation.json")
RUN: dict[str, Any] = _load("trusted-run.json")
ARTIFACTS: list[dict[str, Any]] = _load("trusted-artifacts.json")


class RecordedVerifier:
    """Plays back gh-shaped results (what the real verifier returns), no network."""

    name = "gh attestation verify"
    fixture = False

    def __init__(
        self,
        manifest: list[dict[str, Any]] | None = ATT_MANIFEST,
        backend: list[dict[str, Any]] | None = ATT_BACKEND,
        web: list[dict[str, Any]] | None = ATT_WEB,
        run: dict[str, Any] = RUN,
        artifacts: list[dict[str, Any]] = ARTIFACTS,
    ) -> None:
        self._by_subject = {
            "manifest": manifest or [],
            f"oci://{MANIFEST.backend_image}": backend or [],
            f"oci://{MANIFEST.web_image}": web or [],
        }
        self._run, self._artifacts = run, artifacts
        self.calls: list[str] = []

    def attestations(self, subject: str) -> list[dict[str, Any]]:
        self.calls.append(subject)
        key = subject if subject.startswith("oci://") else "manifest"
        return copy.deepcopy(self._by_subject.get(key, []))

    def run(self, run_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        return copy.deepcopy(self._run), copy.deepcopy(self._artifacts)


def _mutated(results: list[dict[str, Any]], **cert: Any) -> list[dict[str, Any]]:
    """Copy of gh-shaped results with certificate fields (and, where the SLSA
    predicate mirrors them, predicate fields) changed."""
    out = copy.deepcopy(results)
    c = out[0]["verificationResult"]["signature"]["certificate"]
    pred = out[0]["verificationResult"]["statement"]["predicate"]
    wf = pred["buildDefinition"]["externalParameters"]["workflow"]
    for k, v in cert.items():
        c[k] = v
    if "sourceRepositoryURI" in cert:
        wf["repository"] = cert["sourceRepositoryURI"]
    if "sourceRepositoryRef" in cert:
        wf["ref"] = cert["sourceRepositoryRef"]
    if "buildTrigger" in cert:
        pred["buildDefinition"]["internalParameters"]["github"]["event_name"] = cert["buildTrigger"]
    if "sourceRepositoryDigest" in cert:
        pred["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = cert[
            "sourceRepositoryDigest"
        ]
    if "runInvocationURI" in cert:
        pred["runDetails"]["metadata"]["invocationId"] = cert["runInvocationURI"]
    return out


def _verify(verifier: Any = None, manifest: rm.ReleaseManifest = MANIFEST) -> rp.ProvenanceReceipt:
    return verify_release_provenance(
        manifest, verifier=verifier or RecordedVerifier(), policy=TRUSTED_POLICY
    )


# --- A. the weakness, reproduced ----------------------------------------------------
def test_hand_written_ci_manifest_passes_schema_and_image_checks_but_not_provenance(
    tmp_path: Path,
) -> None:
    """A JSON written by hand with kind/deployable/generated_by=ci/full SHA/valid
    digests/expected identity is SCHEMA-valid and can be IMAGE-valid. Only the
    provenance check tells it apart from the CI artifact."""
    doc = json.loads(MANIFEST.raw)
    doc["ci"] = {"workflow": "Delivery", "run_id": "999", "run_url": "https://github.com/x/y"}
    doc["created_at"] = "2026-09-23T00:00:00+00:00"
    hand = tmp_path / "hand-written.json"
    hand.write_text(json.dumps(doc, indent=2) + "\n")
    # 1. schema validity: passes.
    m = rm.load_manifest(hand)
    assert m.generated_by == "ci" and m.release_sha == SHA
    # 2. image capability/identity: passes when the images really are that commit.
    gates.check_image_info(
        {
            "git_sha": SHA,
            "alembic_head": "0016_signed_database_context",
            "migrations": [f"00{n}" for n in range(10, 17)],
            "modules": {
                "nlw.ops.rollout": True,
                "nlw.ops.roles": True,
                "nlw.ctxkeys": True,
                "nlw.backup": True,
                "nlw.ops.rollout.image_info": True,
            },
        },
        m,
    )
    # 3. provenance: no attestation covers these bytes -> not release authority.
    with pytest.raises(ProvenanceError, match="no verified attestation"):
        _verify(RecordedVerifier(manifest=[]), manifest=m)
    # And the real attestation for the CI manifest does not cover the hand-written bytes.
    with pytest.raises(ProvenanceError, match="does not match the manifest bytes"):
        _verify(RecordedVerifier(), manifest=m)


# --- the trusted path ----------------------------------------------------------------
def test_trusted_merged_main_provenance_passes_and_binds_everything() -> None:
    v = RecordedVerifier()
    r = _verify(v)
    assert r.manifest_sha256 == DIGEST and r.release_sha == SHA and r.run_id == RUN_ID
    assert r.repository == TRUSTED_POLICY.repository and r.ref == "refs/heads/main"
    assert r.event == "push" and r.workflow == ".github/workflows/staging.yml"
    assert r.artifact_name == f"release-manifest-{SHA}" and not r.fixture
    assert r.subjects == {
        "manifest": DIGEST,
        "backend": MANIFEST.backend_digest.split(":")[1],
        "web": MANIFEST.web_digest.split(":")[1],
    }
    assert v.calls == [str(FIX / "manifest.json")] + [
        f"oci://{MANIFEST.backend_image}",
        f"oci://{MANIFEST.web_image}",
    ]
    assert "://" not in json.dumps(r.summary())  # state-file safe, URL-free


# --- adversarial matrix ------------------------------------------------------------------
def test_structurally_valid_but_unattested_manifest_is_rejected() -> None:
    with pytest.raises(ProvenanceError, match="no verified attestation"):
        _verify(RecordedVerifier(manifest=[]))
    with pytest.raises(ProvenanceError, match="no verified attestation"):
        _verify(RecordedVerifier(manifest=None))


def test_attestation_from_another_repository_is_rejected() -> None:
    other = "https://github.com/someone-else/natural-language-workflow"
    bad = _mutated(ATT_MANIFEST, sourceRepositoryURI=other)
    with pytest.raises(ProvenanceError, match="source repository"):
        _verify(RecordedVerifier(manifest=bad))


def test_attestation_from_another_workflow_is_rejected() -> None:
    uri = f"https://github.com/{TRUSTED_POLICY.repository}/.github/workflows/ci.yml@refs/heads/main"
    bad = _mutated(ATT_MANIFEST, buildSignerURI=uri)
    with pytest.raises(ProvenanceError, match="signer workflow"):
        _verify(RecordedVerifier(manifest=bad))
    # The SLSA predicate is checked independently of the certificate.
    bad2 = copy.deepcopy(ATT_MANIFEST)
    bad2[0]["verificationResult"]["statement"]["predicate"]["buildDefinition"][
        "externalParameters"
    ]["workflow"]["path"] = ".github/workflows/ci.yml"
    with pytest.raises(ProvenanceError, match="SLSA predicate workflow"):
        _verify(RecordedVerifier(manifest=bad2))


def test_pull_request_and_fork_provenance_are_rejected() -> None:
    pr = _mutated(
        ATT_MANIFEST,
        buildTrigger="pull_request",
        sourceRepositoryRef="refs/pull/42/merge",
        buildSignerURI=(
            f"https://github.com/{TRUSTED_POLICY.repository}/.github/workflows/staging.yml"
            "@refs/pull/42/merge"
        ),
    )
    with pytest.raises(ProvenanceError, match="source ref"):
        _verify(RecordedVerifier(manifest=pr))
    fork = _mutated(ATT_MANIFEST, sourceRepositoryURI="https://github.com/forker/nlw-fork")
    with pytest.raises(ProvenanceError, match="source repository"):
        _verify(RecordedVerifier(manifest=fork))
    dispatch = _mutated(ATT_MANIFEST, buildTrigger="workflow_dispatch")
    with pytest.raises(ProvenanceError, match="build trigger"):
        _verify(RecordedVerifier(manifest=dispatch))


def test_non_main_ref_is_rejected() -> None:
    feature = _mutated(
        ATT_MANIFEST,
        sourceRepositoryRef="refs/heads/feature",
        buildSignerURI=(
            f"https://github.com/{TRUSTED_POLICY.repository}/.github/workflows/staging.yml"
            "@refs/heads/feature"
        ),
    )
    with pytest.raises(ProvenanceError, match="source ref"):
        _verify(RecordedVerifier(manifest=feature))
    run = dict(RUN, head_branch="feature")
    with pytest.raises(ProvenanceError, match="branch"):
        _verify(RecordedVerifier(run=run))


def test_different_commit_is_rejected() -> None:
    other = "f" * 40
    bad = _mutated(ATT_MANIFEST, sourceRepositoryDigest=other)
    with pytest.raises(ProvenanceError, match="source commit"):
        _verify(RecordedVerifier(manifest=bad))
    with pytest.raises(ProvenanceError, match="head commit"):
        _verify(RecordedVerifier(run=dict(RUN, head_sha=other)))


def test_modified_manifest_after_attestation_is_rejected(tmp_path: Path) -> None:
    edited = tmp_path / "release-manifest.json"
    edited.write_text(MANIFEST.raw.replace("stg-api-2026-09", "stg-api-2026-10"))
    m = rm.load_manifest(edited)
    with pytest.raises(ProvenanceError, match="does not match the manifest bytes"):
        _verify(manifest=m)
    # Even a whitespace-only change is a different subject.
    edited.write_text(MANIFEST.raw + "\n")
    with pytest.raises(ProvenanceError, match="does not match the manifest bytes"):
        _verify(manifest=rm.load_manifest(edited))


@pytest.mark.parametrize("which", ["backend", "web"])
def test_image_digest_substitution_is_rejected(tmp_path: Path, which: str) -> None:
    """A manifest whose image digest was swapped: the manifest attestation no
    longer matches its bytes; and even a re-attested manifest cannot pass unless
    the substituted image itself carries provenance for the same commit/run."""
    doc = json.loads(MANIFEST.raw)
    key = f"{which}_image"
    doc[key] = doc[key].split("@")[0] + "@sha256:" + "e" * 64
    swapped = tmp_path / "release-manifest.json"
    swapped.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    m = rm.load_manifest(swapped)
    with pytest.raises(ProvenanceError, match="manifest: attested subject digest"):
        _verify(manifest=m)
    # Attacker re-issues a manifest attestation for the swapped bytes (they cannot,
    # but suppose): the image attestation lookup for the new digest finds nothing.
    reissued = copy.deepcopy(ATT_MANIFEST)
    reissued[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = (
        rp.sha256_hex(m.raw.encode())
    )
    v = RecordedVerifier(manifest=reissued)
    v._by_subject[f"oci://{getattr(m, key)}"] = []
    with pytest.raises(ProvenanceError, match=f"{which} image: no verified attestation"):
        _verify(v, manifest=m)
    # ... and an image attested for ANOTHER commit is not the same release.
    other_att = _mutated(
        ATT_BACKEND if which == "backend" else ATT_WEB, sourceRepositoryDigest="f" * 40
    )
    other_att[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "e" * 64
    v._by_subject[f"oci://{getattr(m, key)}"] = other_att
    with pytest.raises(ProvenanceError, match=f"{which} image: source commit"):
        _verify(v, manifest=m)


def test_run_and_artifact_confusion_is_rejected() -> None:
    # Attestation from a different run than the manifest names.
    other_run = _mutated(
        ATT_MANIFEST,
        runInvocationURI=f"https://github.com/{TRUSTED_POLICY.repository}/actions/runs/1/attempts/1",
    )
    with pytest.raises(ProvenanceError, match="attested run 1 != run"):
        _verify(RecordedVerifier(manifest=other_run))
    # Run failed / still running / from another workflow file / no artifact.
    with pytest.raises(ProvenanceError, match="not a successful completed run"):
        _verify(RecordedVerifier(run=dict(RUN, conclusion="failure")))
    with pytest.raises(ProvenanceError, match="not a successful completed run"):
        _verify(RecordedVerifier(run=dict(RUN, status="in_progress", conclusion=None)))
    with pytest.raises(ProvenanceError, match="not the trusted workflow"):
        _verify(RecordedVerifier(run=dict(RUN, path=".github/workflows/ci.yml")))
    with pytest.raises(ProvenanceError, match="event"):
        _verify(RecordedVerifier(run=dict(RUN, event="workflow_dispatch")))
    with pytest.raises(ProvenanceError, match="artifact"):
        _verify(RecordedVerifier(artifacts=[]))
    with pytest.raises(ProvenanceError, match="artifact"):
        _verify(RecordedVerifier(artifacts=[dict(ARTIFACTS[0], expired=True)]))
    # Image attested by a different run than the manifest.
    with pytest.raises(ProvenanceError, match="backend image: attested run"):
        _verify(
            RecordedVerifier(
                backend=_mutated(
                    ATT_BACKEND,
                    runInvocationURI=(
                        f"https://github.com/{TRUSTED_POLICY.repository}/actions/runs/7/attempts/1"
                    ),
                )
            )
        )


def test_within_run_tolerates_only_the_current_in_progress_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running = dict(RUN, status="in_progress", conclusion=None)
    kw: dict[str, Any] = {
        "expected_run_id": RUN_ID,
        "expected_commit": SHA,
        "policy": TRUSTED_POLICY,
        "artifact_name": f"release-manifest-{SHA}",
    }
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)
    with pytest.raises(ProvenanceError):
        evaluate_run(running, [], within_run=True, **kw)
    monkeypatch.setenv("GITHUB_RUN_ID", RUN_ID)
    evaluate_run(running, [], within_run=True, **kw)  # self-proof inside the same run
    with pytest.raises(ProvenanceError):
        evaluate_run(running, [], within_run=False, **kw)


def test_identity_and_runner_fields_are_all_enforced() -> None:
    for field, value, msg in (
        ("issuer", "https://evil.example/oidc", "OIDC issuer"),
        ("runnerEnvironment", "self-hosted", "runner environment"),
        (
            "runInvocationURI",
            "https://github.com/other/repo/actions/runs/1/attempts/1",
            "trusted repository",
        ),
    ):
        bad = _mutated(ATT_MANIFEST, **{field: value})
        with pytest.raises(ProvenanceError, match=msg):
            _verify(RecordedVerifier(manifest=bad))
    wrong_type = copy.deepcopy(ATT_MANIFEST)
    wrong_type[0]["verificationResult"]["statement"]["predicateType"] = "https://example/other"
    with pytest.raises(ProvenanceError, match="SLSA provenance"):
        evaluate_attestation(
            wrong_type, subject_sha256=DIGEST, expected_commit=SHA, policy=TRUSTED_POLICY
        )


# --- the local fixture mechanism -----------------------------------------------------
def _local_manifest(tmp_path: Path) -> rm.ReleaseManifest:
    doc = json.loads(MANIFEST.raw)
    doc["generated_by"] = "local-rehearsal"
    doc.pop("ci")
    p = tmp_path / "local-manifest.json"
    p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return rm.load_manifest(p, local=True)


def test_local_fixture_provenance_passes_only_under_local_policy(tmp_path: Path) -> None:
    m = _local_manifest(tmp_path)
    env = build_fixture(m)
    fixture = tmp_path / "provenance.json"
    fixture.write_text(json.dumps(env))
    r = verify_release_provenance(m, verifier=FixtureVerifier(fixture), policy=LOCAL_FIXTURE_POLICY)
    assert r.fixture and r.verifier == "local-rehearsal-fixture"
    assert r.repository == "local-rehearsal/disposable"
    # A fixture cannot be produced for a CI manifest, and never verifies one.
    with pytest.raises(ProvenanceError, match="only produced for a local-rehearsal"):
        build_fixture(MANIFEST)


def test_local_fixture_is_rejected_outside_local(tmp_path: Path) -> None:
    m = _local_manifest(tmp_path)
    fixture = tmp_path / "provenance.json"
    fixture.write_text(json.dumps(build_fixture(m)))
    # 1. The trusted policy rejects the fixture identity on the first axis it checks.
    with pytest.raises(ProvenanceError, match="OIDC issuer"):
        evaluate_attestation(
            FixtureVerifier(fixture).attestations("manifest"),
            subject_sha256=rp.sha256_hex(m.raw.encode()),
            expected_commit=m.release_sha,
            policy=TRUSTED_POLICY,
        )
    # 2. The verifier/policy pairing itself is refused.
    with pytest.raises(ProvenanceError, match="never be combined"):
        verify_release_provenance(m, verifier=FixtureVerifier(fixture), policy=TRUSTED_POLICY)
    # 3. The file-level entry point refuses a fixture without --local ...
    with pytest.raises(ProvenanceError, match="never accepted outside --local"):
        verify_manifest_file(FIX / "manifest.json", local=False, fixture=fixture)
    # ... and --local without a fixture is an UNATTESTED manifest.
    with pytest.raises(ProvenanceError, match="requires --provenance-fixture"):
        verify_manifest_file(tmp_path / "local-manifest.json", local=True, fixture=None)
    # 4. A forged envelope claiming GitHub identity does not pass the LOCAL policy either.
    forged = json.loads(fixture.read_text())
    forged["attestations"]["manifest"][0]["verificationResult"]["signature"]["certificate"][
        "issuer"
    ] = rp.GITHUB_OIDC_ISSUER
    fixture.write_text(json.dumps(forged))
    with pytest.raises(ProvenanceError, match="OIDC issuer"):
        verify_release_provenance(m, verifier=FixtureVerifier(fixture), policy=LOCAL_FIXTURE_POLICY)
    # 5. A CI manifest with a fixture, or a rehearsal manifest with GitHub, is refused.
    with pytest.raises(ProvenanceError, match="disagree"):
        verify_release_provenance(
            MANIFEST, verifier=FixtureVerifier(fixture), policy=LOCAL_FIXTURE_POLICY
        )


# --- unavailable verification fails closed ------------------------------------------
def test_missing_gh_or_failed_verification_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_gh(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("gh")

    monkeypatch.setattr(subprocess, "run", no_gh)
    with pytest.raises(ProvenanceError, match="gh CLI not available"):
        GhVerifier(TRUSTED_POLICY, commit=SHA).attestations(str(FIX / "manifest.json"))

    def failing(argv: list[str], **_k: Any) -> Any:
        class R:
            returncode = 1
            stdout = ""
            stderr = "✗ Loaded digest ...\nError: no attestations found matching the policy"

        return R()

    monkeypatch.setattr(subprocess, "run", failing)
    with pytest.raises(ProvenanceError, match="no attestations found"):
        GhVerifier(TRUSTED_POLICY, commit=SHA).attestations(str(FIX / "manifest.json"))
    with pytest.raises(ProvenanceError):
        verify_manifest_file(FIX / "manifest.json", local=False, fixture=None)


def test_gh_verifier_passes_exact_policy_constraints(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_k: Any) -> Any:
        seen.append(argv)

        class R:
            returncode = 0
            stdout = "[]"
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    GhVerifier(TRUSTED_POLICY, commit=SHA).attestations("release-manifest.json")
    argv = seen[0]
    for flag, value in (
        ("--repo", TRUSTED_POLICY.repository),
        ("--signer-workflow", f"{TRUSTED_POLICY.repository}/.github/workflows/staging.yml"),
        ("--source-ref", "refs/heads/main"),
        ("--source-digest", SHA),
        ("--cert-oidc-issuer", rp.GITHUB_OIDC_ISSUER),
        ("--predicate-type", rp.PREDICATE_TYPE),
    ):
        assert argv[argv.index(flag) + 1] == value
    assert "--deny-self-hosted-runners" in argv and "--format" in argv


# --- CLI ---------------------------------------------------------------------------------
def test_cli_fixture_roundtrip_and_expect_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _local_manifest(tmp_path)
    fixture = tmp_path / "provenance.json"
    assert rp.main(["fixture", str(tmp_path / "local-manifest.json"), "--out", str(fixture)]) == 0
    receipt = tmp_path / "receipt.json"
    assert (
        rp.main(
            [
                "verify",
                str(tmp_path / "local-manifest.json"),
                "--local",
                "--fixture",
                str(fixture),
                "--receipt",
                str(receipt),
            ]
        )
        == 0
    )
    assert json.loads(receipt.read_text())["fixture"] is True
    # The same fixture is not authority without --local (exit 3, fail closed).
    assert (
        rp.main(["verify", str(tmp_path / "local-manifest.json"), "--fixture", str(fixture)]) == 3
    )
    # --expect-rejected: exit 0 only when the policy rejects.
    assert (
        rp.main(
            [
                "verify",
                str(tmp_path / "local-manifest.json"),
                "--fixture",
                str(fixture),
                "--expect-rejected",
            ]
        )
        == 0
    )
    assert (
        rp.main(
            [
                "verify",
                str(tmp_path / "local-manifest.json"),
                "--local",
                "--fixture",
                str(fixture),
                "--expect-rejected",
            ]
        )
        == 3
    )
    # A fixture can never be made for a CI manifest.
    assert rp.main(["fixture", str(FIX / "manifest.json"), "--out", str(fixture)]) == 3
    capsys.readouterr()
