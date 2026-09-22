"""Release-manifest PROVENANCE: trusted release authority (M12A-Prep §A, ADR-025).

Three independent checks are all required before a staging/production rollout:

1. **Schema validity** (``nlw.ops.release_manifest``) — the document is
   well-formed, deployable, secret-free, internally consistent. A hand-written
   JSON can satisfy this: ``kind: release``, ``deployable: true``,
   ``generated_by: ci``, a full SHA, plausible digests.
2. **Image capability/identity** (rollout ``verify-release``) — the pinned
   digests exist, carry the release SHA, expose the required commands and the
   target migration head. A hand-written manifest naming a real, current image
   can satisfy this too.
3. **Provenance / authenticity** (this module) — the manifest bytes were
   produced by the trusted GitHub workflow, for this repository, on
   ``refs/heads/main``, by a ``push`` event, for exactly the commit the manifest
   names, in a successful run that uploaded the expected artifact; and both
   image digests named inside it were attested by the same run for the same
   commit. This is what makes the manifest *release authority*.

Mechanism: GitHub artifact attestations (``actions/attest-build-provenance``,
Sigstore keyless signing with the GitHub OIDC identity; SLSA v1 provenance).
Verification uses ``gh attestation verify`` (signature, transparency log,
certificate chain) with exact ``--repo``/``--signer-workflow``/``--source-ref``/
``--source-digest``/``--cert-oidc-issuer`` constraints, and this module
re-evaluates the returned certificate extensions + SLSA predicate itself, so
the accepted policy is explicit code, not only CLI flags.

Trust boundary: verification needs network access to GitHub (attestation API,
Sigstore public-good trust root, Actions API) and a ``gh`` login with read
access to the repository/packages. Whoever administers the repository, its
workflows, branch protection and the ``main`` ref is INSIDE the trust boundary:
a compromised trusted workflow or repository administration is not detected by
this check. Nothing here is offline-verifiable in the operator flow; when
verification cannot be performed, the rollout fails closed for
staging/production.

Local rehearsal: a SEPARATE fixture mechanism (``fixture`` subcommand /
``FixtureVerifier``) produces an attestation-shaped envelope carrying a
distinct issuer/repository identity. It is only consulted under ``--local`` and
can never satisfy the trusted policy (tests prove it).

    python -m nlw.ops.release_provenance verify MANIFEST [--receipt OUT]
    python -m nlw.ops.release_provenance verify MANIFEST --local --fixture ENVELOPE
    python -m nlw.ops.release_provenance fixture MANIFEST --out ENVELOPE   # rehearsal only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from nlw.ops.release_manifest import ReleaseManifest, ReleaseManifestError, load_manifest

PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
ARTIFACT_PREFIX = "release-manifest-"
_RUN_URI_RE = re.compile(r"^(?P<repo>https://[^/]+/[^/]+/[^/]+)/actions/runs/(?P<run>[0-9]+)/")


class ProvenanceError(RuntimeError):
    """Provenance could not be verified or does not satisfy the policy (fail closed)."""


@dataclass(frozen=True)
class ProvenancePolicy:
    """Exactly who may produce release authority."""

    repository: str  # OWNER/REPO
    workflow_path: str  # .github/workflows/<file>.yml
    ref: str  # refs/heads/main
    event: str  # push
    oidc_issuer: str
    runner_environment: str
    server: str = "https://github.com"

    @property
    def repository_uri(self) -> str:
        return f"{self.server}/{self.repository}"

    @property
    def workflow_uri(self) -> str:
        return f"{self.repository_uri}/{self.workflow_path}@{self.ref}"

    @property
    def signer_workflow(self) -> str:
        return f"{self.repository}/{self.workflow_path}"

    @property
    def branch(self) -> str:
        return self.ref.removeprefix("refs/heads/")

    def describe(self) -> dict[str, str]:
        return {
            "repository": self.repository,
            "workflow": self.workflow_path,
            "ref": self.ref,
            "event": self.event,
            "oidc_issuer_kind": "github-actions"
            if self.oidc_issuer == GITHUB_OIDC_ISSUER
            else "local-rehearsal-fixture",
            "runner_environment": self.runner_environment,
        }


# The ONE trusted release-authority chain. Reviewed in git; changing it is a
# security change (ADR-025).
TRUSTED_POLICY = ProvenancePolicy(
    repository="atulpandey02/natural-language-workflow",
    workflow_path=".github/workflows/staging.yml",
    ref="refs/heads/main",
    event="push",
    oidc_issuer=GITHUB_OIDC_ISSUER,
    runner_environment="github-hosted",
)
# Rehearsal fixtures carry a DIFFERENT identity on every axis the trusted
# policy checks, so no fixture can ever be mistaken for GitHub provenance.
LOCAL_FIXTURE_POLICY = ProvenancePolicy(
    repository="local-rehearsal/disposable",
    workflow_path="scripts/ops/rehearse-0010-to-0016.sh",
    ref="refs/heads/main",
    event="push",
    oidc_issuer="local-rehearsal-fixture",
    runner_environment="local-rehearsal",
    server="https://rehearsal.invalid",
)


@dataclass(frozen=True)
class ProvenanceReceipt:
    """Non-secret, URL-free record of a successful verification."""

    manifest_sha256: str
    release_sha: str
    backend_digest: str
    web_digest: str
    repository: str
    workflow: str
    ref: str
    event: str
    run_id: str
    artifact_name: str
    verifier: str  # "gh attestation verify" | "local-rehearsal-fixture"
    verified_at: str
    fixture: bool
    subjects: dict[str, str] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "manifest_sha256": self.manifest_sha256,
            "release_sha": self.release_sha,
            "backend_digest": self.backend_digest,
            "web_digest": self.web_digest,
            "repository": self.repository,
            "workflow": self.workflow,
            "ref": self.ref,
            "event": self.event,
            "run_id": self.run_id,
            "artifact_name": self.artifact_name,
            "verifier": self.verifier,
            "verified_at": self.verified_at,
            "fixture": self.fixture,
            "subjects": dict(self.subjects),
        }


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _get(doc: Any, *path: str) -> Any:
    cur = doc
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


# --- policy evaluation (pure; the same code for gh output and fixtures) -----------


def evaluate_attestation(
    results: list[dict[str, Any]],
    *,
    subject_sha256: str,
    expected_commit: str,
    policy: ProvenancePolicy,
    expected_run_id: str | None = None,
    what: str = "manifest",
) -> dict[str, str]:
    """Accept only a verification result whose SUBJECT digest is exactly
    ``subject_sha256`` and whose signing identity (Fulcio certificate
    extensions) AND SLSA predicate both match ``policy`` for ``expected_commit``.

    ``results`` is the JSON array ``gh attestation verify --format json`` prints
    (or a fixture of the same shape). Every result is a candidate; the first that
    matches every check is accepted; otherwise the most specific failure is raised.
    """
    if not isinstance(results, list) or not results:
        raise ProvenanceError(f"{what}: no verified attestation")
    failures: list[str] = []
    for res in results:
        vr = res.get("verificationResult") if isinstance(res, dict) else None
        if not isinstance(vr, dict):
            failures.append("malformed verification result")
            continue
        try:
            return _check_one(
                vr,
                subject_sha256=subject_sha256,
                expected_commit=expected_commit,
                policy=policy,
                expected_run_id=expected_run_id,
                what=what,
            )
        except ProvenanceError as exc:
            failures.append(str(exc))
    raise ProvenanceError(failures[0] if len(failures) == 1 else "; ".join(failures))


def _check_one(
    vr: dict[str, Any],
    *,
    subject_sha256: str,
    expected_commit: str,
    policy: ProvenancePolicy,
    expected_run_id: str | None,
    what: str,
) -> dict[str, str]:
    st = vr.get("statement")
    if not isinstance(st, dict):
        raise ProvenanceError(f"{what}: attestation carries no in-toto statement")
    if st.get("predicateType") != PREDICATE_TYPE:
        raise ProvenanceError(f"{what}: predicate type is not SLSA provenance v1")
    subjects = st.get("subject")
    digests = {
        str(_get(s, "digest", "sha256") or "").lower()
        for s in (subjects if isinstance(subjects, list) else [])
        if isinstance(s, dict)
    }
    if subject_sha256.lower() not in digests:
        raise ProvenanceError(
            f"{what}: attested subject digest does not match the {what} bytes "
            f"(modified after attestation, or the wrong artifact was selected)"
        )
    cert = _get(vr, "signature", "certificate")
    if not isinstance(cert, dict):
        raise ProvenanceError(f"{what}: no signing certificate in the verification result")
    checks: list[tuple[str, Any, Any]] = [
        ("OIDC issuer", cert.get("issuer"), policy.oidc_issuer),
        ("source repository", cert.get("sourceRepositoryURI"), policy.repository_uri),
        ("source ref", cert.get("sourceRepositoryRef"), policy.ref),
        ("source commit", cert.get("sourceRepositoryDigest"), expected_commit),
        ("build trigger (event)", cert.get("buildTrigger"), policy.event),
        ("signer workflow", cert.get("buildSignerURI"), policy.workflow_uri),
        ("runner environment", cert.get("runnerEnvironment"), policy.runner_environment),
    ]
    for label, got, want in checks:
        if got != want:
            raise ProvenanceError(f"{what}: {label} {got!r} is not the trusted {want!r}")
    run_uri = str(cert.get("runInvocationURI") or "")
    m = _RUN_URI_RE.match(run_uri)
    if not m or m.group("repo") != policy.repository_uri:
        raise ProvenanceError(f"{what}: run invocation is not a run of the trusted repository")
    run_id = m.group("run")
    if expected_run_id is not None and run_id != expected_run_id:
        raise ProvenanceError(
            f"{what}: attested run {run_id} != run {expected_run_id} named in the manifest"
        )
    # SLSA predicate must agree with the certificate (defence in depth).
    pred = st.get("predicate") if isinstance(st.get("predicate"), dict) else {}
    wf = _get(pred, "buildDefinition", "externalParameters", "workflow") or {}
    if (
        wf.get("path") != policy.workflow_path
        or wf.get("ref") != policy.ref
        or wf.get("repository") != policy.repository_uri
    ):
        raise ProvenanceError(
            f"{what}: SLSA predicate workflow/ref/repository disagree with policy"
        )
    if _get(pred, "buildDefinition", "internalParameters", "github", "event_name") != policy.event:
        raise ProvenanceError(f"{what}: SLSA predicate event is not {policy.event!r}")
    deps = _get(pred, "buildDefinition", "resolvedDependencies") or []
    commits = {str(_get(d, "digest", "gitCommit")) for d in deps if isinstance(d, dict)}
    if expected_commit not in commits:
        raise ProvenanceError(
            f"{what}: SLSA predicate does not resolve commit {expected_commit[:12]}"
        )
    if _get(pred, "runDetails", "metadata", "invocationId") != run_uri:
        raise ProvenanceError(f"{what}: SLSA predicate invocation disagrees with the certificate")
    return {"subject_sha256": subject_sha256, "run_id": run_id, "commit": expected_commit}


def evaluate_run(
    run: dict[str, Any],
    artifacts: list[dict[str, Any]],
    *,
    expected_run_id: str,
    expected_commit: str,
    policy: ProvenancePolicy,
    artifact_name: str,
    within_run: bool = False,
) -> None:
    """The attested run must be the trusted workflow, on the trusted branch, for
    the exact commit, completed successfully, and have uploaded the artifact.
    ``within_run`` (CI self-proof only) tolerates the run still being in progress."""
    if str(run.get("id")) != expected_run_id:
        raise ProvenanceError("run: the queried run is not the attested run")
    if run.get("path") != policy.workflow_path:
        raise ProvenanceError(f"run: workflow {run.get('path')!r} is not the trusted workflow")
    if run.get("event") != policy.event:
        raise ProvenanceError(f"run: event {run.get('event')!r} is not {policy.event!r}")
    if run.get("head_branch") != policy.branch:
        raise ProvenanceError(f"run: branch {run.get('head_branch')!r} is not {policy.branch!r}")
    if run.get("head_sha") != expected_commit:
        raise ProvenanceError("run: head commit differs from the manifest release SHA")
    repo = _get(run, "repository", "full_name")
    if repo != policy.repository:
        raise ProvenanceError(f"run: repository {repo!r} is not the trusted repository")
    status, conclusion = run.get("status"), run.get("conclusion")
    if (
        within_run
        and status == "in_progress"
        and str(os.environ.get("GITHUB_RUN_ID")) == str(run.get("id"))
    ):
        pass
    elif status != "completed" or conclusion != "success":
        raise ProvenanceError(
            f"run: not a successful completed run (status={status!r}, conclusion={conclusion!r})"
        )
    names = {
        str(a.get("name")) for a in artifacts if isinstance(a, dict) and not a.get("expired", False)
    }
    if artifact_name not in names and not within_run:
        raise ProvenanceError(f"run: artifact {artifact_name!r} was not uploaded by the run")


# --- verifiers -------------------------------------------------------------------


class Verifier(Protocol):
    name: str
    fixture: bool

    def attestations(self, subject: str) -> list[dict[str, Any]]: ...

    def run(self, run_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]: ...


class GhVerifier:
    """Real GitHub provenance through the ``gh`` CLI (network + gh login)."""

    name = "gh attestation verify"
    fixture = False

    def __init__(self, policy: ProvenancePolicy, *, commit: str, relaxed_cli: bool = False) -> None:
        self._p = policy
        self._commit = commit
        self._relaxed = relaxed_cli  # PR negative proof: let the evaluator do the rejecting

    def _gh(self, argv: list[str], *, timeout: int = 180) -> str:
        try:
            p = subprocess.run(  # noqa: S603 - fixed argv
                ["gh", *argv], capture_output=True, text=True, timeout=timeout, check=False
            )
        except FileNotFoundError as exc:
            raise ProvenanceError(
                "gh CLI not available: provenance cannot be verified (fail closed)"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ProvenanceError("gh timed out: provenance cannot be verified") from exc
        if p.returncode != 0:
            tail = (p.stderr or p.stdout).strip().splitlines()[-1:] or ["no output"]
            raise ProvenanceError(f"gh {argv[0]} {argv[1] if len(argv) > 1 else ''}: {tail[0]}")
        return p.stdout

    def attestations(self, subject: str) -> list[dict[str, Any]]:
        argv = [
            "attestation",
            "verify",
            subject,
            "--repo",
            self._p.repository,
            "--predicate-type",
            PREDICATE_TYPE,
            "--format",
            "json",
        ]
        if not self._relaxed:
            argv += [
                "--signer-workflow",
                self._p.signer_workflow,
                "--source-ref",
                self._p.ref,
                "--source-digest",
                self._commit,
                "--cert-oidc-issuer",
                self._p.oidc_issuer,
                "--deny-self-hosted-runners",
            ]
        out = self._gh(argv)
        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            raise ProvenanceError("gh attestation verify returned no JSON") from exc
        return data if isinstance(data, list) else []

    def run(self, run_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        base = f"repos/{self._p.repository}/actions/runs/{run_id}"
        try:
            run = json.loads(self._gh(["api", base]))
            arts = json.loads(self._gh(["api", f"{base}/artifacts?per_page=100"]))
        except json.JSONDecodeError as exc:
            raise ProvenanceError("gh api returned no JSON") from exc
        return run, list(arts.get("artifacts") or [])


class FixtureVerifier:
    """Rehearsal-only envelope: the same shapes, a distinct identity, no signature."""

    name = "local-rehearsal-fixture"
    fixture = True

    def __init__(self, path: Path) -> None:
        try:
            doc = json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise ProvenanceError(f"provenance fixture unreadable: {path}") from exc
        if not isinstance(doc, dict) or doc.get("kind") != "local-rehearsal-provenance-fixture":
            raise ProvenanceError("not a local-rehearsal provenance fixture")
        self._doc = doc

    def attestations(self, subject: str) -> list[dict[str, Any]]:
        att = self._doc.get("attestations") or {}
        found = att.get(subject if subject.startswith("oci://") else "manifest")
        return list(found) if isinstance(found, list) else []

    def run(self, run_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        return dict(self._doc.get("run") or {}), list(self._doc.get("artifacts") or [])


# --- the verification flow ---------------------------------------------------------


def verify_release_provenance(
    manifest: ReleaseManifest,
    *,
    verifier: Verifier,
    policy: ProvenancePolicy,
    within_run: bool = False,
    now: datetime | None = None,
) -> ProvenanceReceipt:
    """Manifest attestation (subject = manifest bytes) + trusted run/artifact +
    both image attestations, all for the same commit/run/policy."""
    if not manifest.raw:
        raise ProvenanceError("manifest bytes unavailable (load it from a file)")
    if verifier.fixture != (policy is LOCAL_FIXTURE_POLICY):
        raise ProvenanceError("fixture provenance and the trusted policy can never be combined")
    if verifier.fixture != (manifest.generated_by == "local-rehearsal"):
        raise ProvenanceError(
            "manifest generated_by and the provenance mechanism disagree "
            "(a CI manifest needs GitHub provenance; a rehearsal manifest needs the fixture)"
        )
    digest = sha256_hex(manifest.raw.encode("utf-8"))
    run_id = manifest.ci.get("run_id") or None
    m = evaluate_attestation(
        verifier.attestations(_subject_for_manifest(manifest)),
        subject_sha256=digest,
        expected_commit=manifest.release_sha,
        policy=policy,
        expected_run_id=run_id,
        what="manifest",
    )
    run, artifacts = verifier.run(m["run_id"])
    artifact_name = f"{ARTIFACT_PREFIX}{manifest.release_sha}"
    evaluate_run(
        run,
        artifacts,
        expected_run_id=m["run_id"],
        expected_commit=manifest.release_sha,
        policy=policy,
        artifact_name=artifact_name,
        within_run=within_run,
    )
    subjects = {"manifest": digest}
    for what, image, digest_ref in (
        ("backend", manifest.backend_image, manifest.backend_digest),
        ("web", manifest.web_image, manifest.web_digest),
    ):
        hex_digest = digest_ref.split(":", 1)[1]
        evaluate_attestation(
            verifier.attestations(f"oci://{image}"),
            subject_sha256=hex_digest,
            expected_commit=manifest.release_sha,
            policy=policy,
            expected_run_id=m["run_id"],
            what=f"{what} image",
        )
        subjects[what] = hex_digest
    return ProvenanceReceipt(
        manifest_sha256=digest,
        release_sha=manifest.release_sha,
        backend_digest=manifest.backend_digest,
        web_digest=manifest.web_digest,
        repository=policy.repository,
        workflow=policy.workflow_path,
        ref=policy.ref,
        event=policy.event,
        run_id=m["run_id"],
        artifact_name=artifact_name,
        verifier=verifier.name,
        verified_at=(now or datetime.now(UTC)).isoformat(),
        fixture=verifier.fixture,
        subjects=subjects,
    )


def _subject_for_manifest(manifest: ReleaseManifest) -> str:
    return manifest.source_path or "release-manifest.json"


def verify_manifest_file(
    path: Path, *, local: bool, fixture: Path | None, within_run: bool = False
) -> tuple[ReleaseManifest, ProvenanceReceipt]:
    """Schema + provenance for a manifest file. ``local`` selects the rehearsal
    fixture mechanism (and requires ``fixture``); otherwise real GitHub provenance."""
    manifest = load_manifest(path, local=local)
    if local:
        if fixture is None:
            raise ProvenanceError("--local requires --provenance-fixture (unattested manifest)")
        verifier: Verifier = FixtureVerifier(fixture)
        policy = LOCAL_FIXTURE_POLICY
    else:
        if fixture is not None:
            raise ProvenanceError("a provenance fixture is never accepted outside --local")
        verifier = GhVerifier(TRUSTED_POLICY, commit=manifest.release_sha)
        policy = TRUSTED_POLICY
    receipt = verify_release_provenance(
        manifest, verifier=verifier, policy=policy, within_run=within_run
    )
    return manifest, receipt


# --- rehearsal fixture generation --------------------------------------------------


def build_fixture(manifest: ReleaseManifest, *, run_id: str = "1") -> dict[str, Any]:
    """An attestation-shaped envelope for THIS manifest's bytes and digests under
    the LOCAL_FIXTURE_POLICY identity. It carries no signature and a non-GitHub
    issuer/repository: the trusted policy rejects it on every identity axis."""
    if manifest.generated_by != "local-rehearsal":
        raise ProvenanceError("fixture provenance is only produced for a local-rehearsal manifest")
    p = LOCAL_FIXTURE_POLICY
    run_uri = f"{p.repository_uri}/actions/runs/{run_id}/attempts/1"

    def envelope(name: str, digest: str) -> list[dict[str, Any]]:
        return [
            {
                "attestation": {"bundle": "local-rehearsal-fixture (unsigned)"},
                "verificationResult": {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "signature": {
                        "certificate": {
                            "issuer": p.oidc_issuer,
                            "sourceRepositoryURI": p.repository_uri,
                            "sourceRepositoryRef": p.ref,
                            "sourceRepositoryDigest": manifest.release_sha,
                            "buildTrigger": p.event,
                            "buildSignerURI": p.workflow_uri,
                            "runnerEnvironment": p.runner_environment,
                            "runInvocationURI": run_uri,
                        }
                    },
                    "statement": {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [{"name": name, "digest": {"sha256": digest}}],
                        "predicateType": PREDICATE_TYPE,
                        "predicate": {
                            "buildDefinition": {
                                "buildType": "local-rehearsal-fixture",
                                "externalParameters": {
                                    "workflow": {
                                        "path": p.workflow_path,
                                        "ref": p.ref,
                                        "repository": p.repository_uri,
                                    }
                                },
                                "internalParameters": {"github": {"event_name": p.event}},
                                "resolvedDependencies": [
                                    {"digest": {"gitCommit": manifest.release_sha}}
                                ],
                            },
                            "runDetails": {"metadata": {"invocationId": run_uri}},
                        },
                    },
                },
            }
        ]

    return {
        "kind": "local-rehearsal-provenance-fixture",
        "fixture": True,
        "note": "UNSIGNED rehearsal envelope; never release authority for a real target",
        "attestations": {
            "manifest": envelope("release-manifest.json", sha256_hex(manifest.raw.encode("utf-8"))),
            f"oci://{manifest.backend_image}": envelope(
                manifest.backend_image, manifest.backend_digest.split(":", 1)[1]
            ),
            f"oci://{manifest.web_image}": envelope(
                manifest.web_image, manifest.web_digest.split(":", 1)[1]
            ),
        },
        "run": {
            "id": int(run_id),
            "path": p.workflow_path,
            "event": p.event,
            "head_branch": p.branch,
            "head_sha": manifest.release_sha,
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": p.repository},
        },
        "artifacts": [{"name": f"{ARTIFACT_PREFIX}{manifest.release_sha}", "expired": False}],
    }


# --- CLI ----------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ops.release_provenance")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="schema + provenance; exit 3 when not release authority")
    v.add_argument("manifest", type=Path)
    v.add_argument("--local", action="store_true", help="rehearsal: use the fixture mechanism")
    v.add_argument("--fixture", type=Path, default=None, help="rehearsal provenance envelope")
    v.add_argument("--receipt", type=Path, default=None, help="write the verification receipt")
    v.add_argument(
        "--within-run",
        action="store_true",
        help="CI self-proof: tolerate the attested run still being in progress",
    )
    v.add_argument(
        "--expect-rejected",
        action="store_true",
        help="negative proof: exit 0 only if the policy REJECTS (e.g. a PR attestation)",
    )
    v.add_argument(
        "--relaxed-cli",
        action="store_true",
        help="negative proof: do not pass ref/commit constraints to gh so the evaluator decides",
    )
    f = sub.add_parser("fixture", help="rehearsal only: write the fixture envelope for a manifest")
    f.add_argument("manifest", type=Path)
    f.add_argument("--out", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        if a.cmd == "fixture":
            manifest = load_manifest(a.manifest, local=True)
            a.out.write_text(json.dumps(build_fixture(manifest), indent=2, sort_keys=True) + "\n")
            print(f"rehearsal provenance fixture written: {a.out} (NOT GitHub provenance)")
            return 0
        if a.relaxed_cli:
            manifest = load_manifest(a.manifest, local=False)
            verifier = GhVerifier(TRUSTED_POLICY, commit=manifest.release_sha, relaxed_cli=True)
            receipt = verify_release_provenance(
                manifest, verifier=verifier, policy=TRUSTED_POLICY, within_run=a.within_run
            )
        else:
            manifest, receipt = verify_manifest_file(
                a.manifest, local=a.local, fixture=a.fixture, within_run=a.within_run
            )
    except (ReleaseManifestError, ProvenanceError) as exc:
        if a.cmd == "verify" and a.expect_rejected:
            print(f"provenance REJECTED as expected: {exc}")
            return 0
        print(f"release provenance REJECTED: {exc}", file=sys.stderr)
        return 3
    if a.expect_rejected:
        print("provenance was ACCEPTED but rejection was expected", file=sys.stderr)
        return 3
    if a.receipt:
        a.receipt.write_text(json.dumps(receipt.summary(), indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt.summary(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
