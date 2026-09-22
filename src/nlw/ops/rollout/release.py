"""Immutable release identity for a rollout (M12A-Prep §B).

A release is a reviewed JSON document (``deploy/staging/release.json``) naming
exactly what may be deployed: the git SHA, the backend and web image DIGESTS
(never mutable tags), the migration the target database must currently be at,
the migration head the release carries, the EC2 instance that is the only valid
target, and the Compose project. Every value is shape-validated here so a typo
fails before any host is contacted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_IMAGE_RE = re.compile(r"^[a-z0-9.\-]+(:[0-9]+)?(/[a-z0-9._\-]+)+@sha256:[0-9a-f]{64}$")
_REVISION_RE = re.compile(r"^[0-9]{4}_[a-z0-9_]+$")
_INSTANCE_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
_PROJECT_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
KEY_CLASSES: tuple[str, ...] = ("api", "worker", "scheduler")
FORMAT_VERSION = 1


class ReleaseSpecError(ValueError):
    """The release document is missing, malformed, or internally inconsistent."""


@dataclass(frozen=True)
class ReleaseSpec:
    environment: str
    release_sha: str
    backend_image: str
    web_image: str
    expected_current_revision: str
    target_revision: str
    instance_id: str
    region: str
    compose_project: str
    public_hostname: str
    key_ids: dict[str, str]

    @property
    def backend_digest(self) -> str:
        return self.backend_image.split("@", 1)[1]

    @property
    def web_digest(self) -> str:
        return self.web_image.split("@", 1)[1]

    def summary(self) -> dict[str, Any]:
        """Non-secret description for reports and the rollout state file."""
        return {
            "environment": self.environment,
            "release_sha": self.release_sha,
            "backend_digest": self.backend_digest,
            "web_digest": self.web_digest,
            "expected_current_revision": self.expected_current_revision,
            "target_revision": self.target_revision,
            "instance_id": self.instance_id,
            "region": self.region,
            "compose_project": self.compose_project,
            "public_hostname": self.public_hostname,
            "key_ids": dict(self.key_ids),
        }


def _require(doc: dict[str, Any], key: str, pattern: re.Pattern[str], what: str) -> str:
    value = doc.get(key)
    if not isinstance(value, str) or not pattern.match(value):
        raise ReleaseSpecError(f"release.{key}: {what} required")
    return value


def parse_release(doc: dict[str, Any]) -> ReleaseSpec:
    if doc.get("format_version") != FORMAT_VERSION:
        raise ReleaseSpecError(f"release.format_version must be {FORMAT_VERSION}")
    environment = doc.get("environment")
    if environment not in ("staging", "production"):
        raise ReleaseSpecError("release.environment must be 'staging' or 'production'")
    key_ids = doc.get("key_ids")
    if not isinstance(key_ids, dict) or set(key_ids) != set(KEY_CLASSES):
        raise ReleaseSpecError("release.key_ids must name exactly api, worker and scheduler")
    for cls, kid in key_ids.items():
        if not isinstance(kid, str) or not _KEY_ID_RE.match(kid):
            raise ReleaseSpecError(f"release.key_ids.{cls}: invalid key id")
    if len(set(key_ids.values())) != len(KEY_CLASSES):
        raise ReleaseSpecError("release.key_ids must be unique per runtime class")
    spec = ReleaseSpec(
        environment=environment,
        release_sha=_require(doc, "release_sha", _SHA_RE, "40-hex git SHA"),
        backend_image=_require(doc, "backend_image", _DIGEST_IMAGE_RE, "image@sha256:<digest>"),
        web_image=_require(doc, "web_image", _DIGEST_IMAGE_RE, "image@sha256:<digest>"),
        expected_current_revision=_require(
            doc, "expected_current_revision", _REVISION_RE, "named Alembic revision"
        ),
        target_revision=_require(doc, "target_revision", _REVISION_RE, "named Alembic revision"),
        instance_id=_require(doc, "instance_id", _INSTANCE_RE, "EC2 instance id"),
        region=_require(doc, "region", re.compile(r"^[a-z]{2}-[a-z]+-[0-9]$"), "AWS region"),
        compose_project=_require(doc, "compose_project", _PROJECT_RE, "compose project name"),
        public_hostname=_require(doc, "public_hostname", _HOSTNAME_RE, "public hostname"),
        key_ids={cls: str(key_ids[cls]) for cls in KEY_CLASSES},
    )
    if spec.backend_image == spec.web_image:
        raise ReleaseSpecError("backend and web images must differ")
    if spec.expected_current_revision == spec.target_revision:
        raise ReleaseSpecError("expected_current_revision equals target_revision (nothing to roll)")
    return spec


def load_release(path: Path) -> ReleaseSpec:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReleaseSpecError(f"release file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReleaseSpecError(f"release file is not valid JSON: {path}") from exc
    if not isinstance(doc, dict):
        raise ReleaseSpecError("release file must be a JSON object")
    return parse_release(doc)
