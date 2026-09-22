"""Release manifest: the external, CI-generated release authority (M12A-Prep §A).

Git never contains a deployable manifest: a commit cannot know the digest of
the image built FROM it. Instead CI builds the exact commit, pushes the images,
and generates this document with the resulting manifest digests; it is
uploaded as a run artifact tied to that commit. The operator downloads it and
passes it to the rollout, which validates the schema, the SHA, the digests and
— on the host — that the images are pullable, carry the same SHA, expose the
required commands and hold the expected migration head.

    python -m nlw.ops.release_manifest generate --target-env deploy/staging/target.env \
        --release-sha <40 hex> --backend-image <img@sha256:..> --web-image <img@sha256:..> \
        --generated-by ci --out release-manifest.json
    python -m nlw.ops.release_manifest validate release-manifest.json [--local]

``deploy/staging/release.example.json`` is a committed, NON-DEPLOYABLE template
(``kind: example``); the loader rejects it in every mode. A rehearsal manifest
(``generated_by: local-rehearsal``) is accepted only by a ``--local`` rollout.

SCOPE: this module is STRUCTURAL validation only. A hand-written document can
satisfy every check here (``kind: release``, ``deployable: true``,
``generated_by: ci``, a real SHA, real digests). Release AUTHORITY additionally
requires image verification (rollout ``verify-release``) and PROVENANCE
verification (``nlw.ops.release_provenance``: GitHub artifact attestation bound
to these exact bytes, repository, workflow, ``refs/heads/main``, ``push``, commit).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FORMAT_VERSION = 2
KEY_CLASSES: tuple[str, ...] = ("api", "worker", "scheduler")
GENERATED_BY = ("ci", "local-rehearsal")

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_IMAGE_RE = re.compile(r"^[a-z0-9.\-]+(:[0-9]+)?(/[a-z0-9._\-]+)+@sha256:[0-9a-f]{64}$")
_REVISION_RE = re.compile(r"^[0-9]{4}_[a-z0-9_]+$")
_INSTANCE_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
_PROJECT_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-[0-9]$")
_FORBIDDEN = ("password", "passphrase", "secret", "token", "aws_")


class ReleaseManifestError(ValueError):
    """The manifest is missing, malformed, an example/fixture, or inconsistent."""


@dataclass(frozen=True)
class ReleaseManifest:
    generated_by: str
    created_at: datetime
    release_sha: str
    backend_image: str
    web_image: str
    expected_current_revision: str
    target_revision: str
    environment: str
    instance_id: str
    region: str
    compose_project: str
    public_hostname: str
    key_ids: dict[str, str]
    ci: dict[str, str]
    attestation: str | None
    sha256: str  # of the manifest bytes as loaded (integrity for the state file)
    raw: str = ""  # the exact bytes (utf-8) the provenance subject digest covers
    source_path: str = ""  # where it was loaded from (gh verifies that file)

    @property
    def backend_digest(self) -> str:
        return self.backend_image.split("@", 1)[1]

    @property
    def web_digest(self) -> str:
        return self.web_image.split("@", 1)[1]

    def summary(self) -> dict[str, Any]:
        """Non-secret description for reports and the rollout state file."""
        return {
            "manifest_sha256": self.sha256,
            "generated_by": self.generated_by,
            "created_at": self.created_at.isoformat(),
            "ci": dict(self.ci),
            "release_sha": self.release_sha,
            "backend_digest": self.backend_digest,
            "web_digest": self.web_digest,
            "expected_current_revision": self.expected_current_revision,
            "target_revision": self.target_revision,
            "environment": self.environment,
            "instance_id": self.instance_id,
            "region": self.region,
            "compose_project": self.compose_project,
            "public_hostname": self.public_hostname,
            "key_ids": dict(self.key_ids),
        }


def _req(doc: dict[str, Any], key: str, pattern: re.Pattern[str], what: str) -> str:
    v = doc.get(key)
    if not isinstance(v, str) or not pattern.match(v):
        raise ReleaseManifestError(f"{key}: {what} required")
    return v


def parse_manifest(
    doc: dict[str, Any], *, raw_bytes: bytes = b"", local: bool = False
) -> ReleaseManifest:
    """Validate a manifest document. ``local`` (rehearsal only) additionally
    accepts ``generated_by: local-rehearsal``; examples are never accepted."""
    if doc.get("format_version") != FORMAT_VERSION:
        raise ReleaseManifestError(f"format_version must be {FORMAT_VERSION}")
    kind = doc.get("kind")
    if kind != "release":
        raise ReleaseManifestError(
            f"kind={kind!r} is not a deployable release manifest "
            "(examples/fixtures are never authority)"
        )
    if doc.get("deployable") is not True:
        raise ReleaseManifestError("deployable must be literally true (templates are not)")
    blob = json.dumps(doc).lower()
    for needle in _FORBIDDEN:
        if needle in blob:
            raise ReleaseManifestError(f"manifest must not contain {needle!r} (secret-bearing)")
    generated_by = doc.get("generated_by")
    if generated_by not in GENERATED_BY:
        raise ReleaseManifestError("generated_by must be 'ci' or 'local-rehearsal'")
    if generated_by == "local-rehearsal" and not local:
        raise ReleaseManifestError(
            "a local-rehearsal manifest is not release authority for a real target"
        )
    env = doc.get("environment")
    if env not in ("staging", "production"):
        raise ReleaseManifestError("environment must be 'staging' or 'production'")
    ci = doc.get("ci")
    if generated_by == "ci":
        if not isinstance(ci, dict) or not all(
            isinstance(ci.get(k), str) and ci.get(k) for k in ("workflow", "run_id", "run_url")
        ):
            raise ReleaseManifestError(
                "ci.workflow/run_id/run_url are required for a CI-generated manifest"
            )
    elif ci is not None and not isinstance(ci, dict):
        raise ReleaseManifestError("ci must be an object")
    created_raw = doc.get("created_at")
    if not isinstance(created_raw, str):
        raise ReleaseManifestError("created_at required (ISO-8601)")
    try:
        created = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseManifestError("created_at is not ISO-8601") from exc
    if created.tzinfo is None:
        raise ReleaseManifestError("created_at must carry a timezone")
    key_ids = doc.get("key_ids")
    if not isinstance(key_ids, dict) or set(key_ids) != set(KEY_CLASSES):
        raise ReleaseManifestError("key_ids must name exactly api, worker and scheduler")
    for cls, kid in key_ids.items():
        if not isinstance(kid, str) or not _KEY_ID_RE.match(kid):
            raise ReleaseManifestError(f"key_ids.{cls}: invalid key id")
    if len(set(key_ids.values())) != len(KEY_CLASSES):
        raise ReleaseManifestError("key_ids must be unique per runtime class")
    attestation = doc.get("attestation")
    if attestation is not None and (not isinstance(attestation, str) or len(attestation) > 512):
        raise ReleaseManifestError("attestation must be a short reference string")
    m = ReleaseManifest(
        generated_by=generated_by,
        created_at=created.astimezone(UTC),
        release_sha=_req(doc, "release_sha", _SHA_RE, "40-hex git SHA"),
        backend_image=_req(doc, "backend_image", _DIGEST_IMAGE_RE, "image@sha256:<digest>"),
        web_image=_req(doc, "web_image", _DIGEST_IMAGE_RE, "image@sha256:<digest>"),
        expected_current_revision=_req(
            doc, "expected_current_revision", _REVISION_RE, "named revision"
        ),
        target_revision=_req(doc, "target_revision", _REVISION_RE, "named revision"),
        environment=env,
        instance_id=_req(doc, "instance_id", _INSTANCE_RE, "EC2 instance id"),
        region=_req(doc, "region", _REGION_RE, "AWS region"),
        compose_project=_req(doc, "compose_project", _PROJECT_RE, "compose project"),
        public_hostname=_req(doc, "public_hostname", _HOSTNAME_RE, "public hostname"),
        key_ids={c: str(key_ids[c]) for c in KEY_CLASSES},
        ci={k: str(v) for k, v in (ci or {}).items()},
        attestation=attestation,
        sha256=hashlib.sha256(raw_bytes).hexdigest() if raw_bytes else "",
    )
    if m.backend_image == m.web_image:
        raise ReleaseManifestError("backend and web images must differ")
    if m.expected_current_revision == m.target_revision:
        raise ReleaseManifestError(
            "expected_current_revision equals target_revision (nothing to roll)"
        )
    return m


def load_manifest(path: Path, *, local: bool = False) -> ReleaseManifest:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ReleaseManifestError(f"release manifest not found: {path}") from exc
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReleaseManifestError("release manifest is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise ReleaseManifestError("release manifest must be a JSON object")
    m = parse_manifest(doc, raw_bytes=raw, local=local)
    return replace(m, raw=raw.decode("utf-8"), source_path=str(path))


# --- generation (CI or the local rehearsal) --------------------------------------


def _target_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip().strip('"')
    return values


def alembic_head() -> str:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()
    if not head:
        raise ReleaseManifestError("could not derive the Alembic head from this checkout")
    return str(head)


def generate(
    *,
    target_env: Path,
    release_sha: str,
    backend_image: str,
    web_image: str,
    generated_by: str,
    target_revision: str | None = None,
    now: datetime | None = None,
    ci_env: Mapping[str, str] | None = None,
    attestation: str | None = None,
) -> dict[str, Any]:
    t = _target_env(target_env)
    env: Mapping[str, str] = os.environ if ci_env is None else ci_env
    ci: dict[str, str] = {}
    if generated_by == "ci":
        run_id = env.get("GITHUB_RUN_ID", "")
        server = env.get("GITHUB_SERVER_URL", "https://github.com")
        repo = env.get("GITHUB_REPOSITORY", "")
        ci = {
            "workflow": env.get("GITHUB_WORKFLOW", ""),
            "run_id": run_id,
            "run_url": f"{server}/{repo}/actions/runs/{run_id}" if run_id and repo else "",
            "actor": env.get("GITHUB_ACTOR", ""),
        }
    doc: dict[str, Any] = {
        "format_version": FORMAT_VERSION,
        "kind": "release",
        "deployable": True,
        "generated_by": generated_by,
        "created_at": (now or datetime.now(UTC)).isoformat(),
        "release_sha": release_sha,
        "backend_image": backend_image,
        "web_image": web_image,
        "expected_current_revision": t.get("NLW_STAGING_CURRENT_REVISION", ""),
        "target_revision": target_revision or alembic_head(),
        "environment": t.get("NLW_STAGING_ENVIRONMENT", "staging"),
        "instance_id": t.get("NLW_STAGING_INSTANCE_ID", ""),
        "region": t.get("NLW_STAGING_REGION", ""),
        "compose_project": t.get("NLW_STAGING_COMPOSE_PROJECT", ""),
        "public_hostname": t.get("NLW_STAGING_PUBLIC_HOSTNAME", ""),
        "key_ids": {c: t.get(f"NLW_STAGING_KEY_ID_{c.upper()}", "") for c in KEY_CLASSES},
        "ci": ci,
    }
    if attestation:
        doc["attestation"] = attestation
    parse_manifest(doc, local=(generated_by != "ci"))  # fail before writing anything
    return doc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ops.release_manifest")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--target-env", type=Path, required=True)
    g.add_argument("--release-sha", required=True)
    g.add_argument("--backend-image", required=True)
    g.add_argument("--web-image", required=True)
    g.add_argument("--generated-by", choices=GENERATED_BY, required=True)
    g.add_argument("--target-revision", default=None, help="default: this checkout's Alembic head")
    g.add_argument("--attestation", default=None, help="optional attestation reference")
    g.add_argument("--out", type=Path, required=True)
    v = sub.add_parser("validate")
    v.add_argument("path", type=Path)
    v.add_argument("--local", action="store_true", help="accept a local-rehearsal manifest")
    a = p.parse_args(argv)
    try:
        if a.cmd == "generate":
            doc = generate(
                target_env=a.target_env,
                release_sha=a.release_sha,
                backend_image=a.backend_image,
                web_image=a.web_image,
                generated_by=a.generated_by,
                target_revision=a.target_revision,
                attestation=a.attestation,
            )
            payload = json.dumps(doc, indent=2, sort_keys=True) + "\n"
            a.out.write_text(payload, encoding="utf-8")
            print(
                f"release manifest written: {a.out} "
                f"sha256={hashlib.sha256(payload.encode()).hexdigest()}"
            )
            return 0
        m = load_manifest(a.path, local=a.local)
        print(json.dumps(m.summary(), indent=2, sort_keys=True))
        return 0
    except ReleaseManifestError as exc:
        print(f"release manifest REJECTED: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
