"""Off-host key escrow attestation (M12A-Prep §F).

The tooling cannot open an operator's vault, so the escrow gate is an
operator-authored, NON-SECRET attestation that the three runtime key files were
copied to an encrypted off-host location and that recovery was tested. The
attestation carries only key ids, purposes and SHA-256 **fingerprints** of the
material; deployment verifies those fingerprints against the key files on the
host (``python -m nlw.ctxkeys fingerprint``). Pasting the key material itself
into the fingerprint field cannot satisfy the gate — sha256(material) never
equals material — so the check also catches that mistake.

The attestation is written by the OPERATOR after escrow. Key preparation never
creates it (that would make the gate meaningless).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nlw.ops.rollout.release import KEY_CLASSES, ReleaseSpec

FORMAT_VERSION = 1
_FP_RE = re.compile(r"^[0-9a-f]{64}$")
_OPERATOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@+-]{1,79}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/@+-]{1,119}$")
# Anything that looks like a credential or URL with credentials must not appear.
_FORBIDDEN = ("password", "passphrase", "secret", "token", "://", "BEGIN ", "aws_")
MAX_AGE = timedelta(days=30)


class AttestationError(ValueError):
    """The attestation is missing, malformed, stale, or does not match the keys."""


@dataclass(frozen=True)
class KeyAttestation:
    key_class: str
    key_id: str
    sha256_fingerprint: str


@dataclass(frozen=True)
class EscrowAttestation:
    environment: str
    release_sha: str
    keys: dict[str, KeyAttestation]
    escrow_verified_at: datetime
    operator: str
    recovery_test_confirmed: bool
    escrow_location_label: str

    def summary(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "release_sha": self.release_sha,
            "escrow_verified_at": self.escrow_verified_at.isoformat(),
            "operator": self.operator,
            "escrow_location_label": self.escrow_location_label,
            "keys": {
                c: {"key_id": k.key_id, "sha256_fingerprint": k.sha256_fingerprint}
                for c, k in sorted(self.keys.items())
            },
        }


def _parse_ts(value: object) -> datetime:
    if not isinstance(value, str):
        raise AttestationError("escrow_verified_at must be an ISO-8601 timestamp")
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttestationError("escrow_verified_at is not ISO-8601") from exc
    if ts.tzinfo is None:
        raise AttestationError("escrow_verified_at must carry a timezone")
    return ts.astimezone(UTC)


def parse_attestation(doc: dict[str, Any]) -> EscrowAttestation:
    if doc.get("format_version") != FORMAT_VERSION:
        raise AttestationError(f"format_version must be {FORMAT_VERSION}")
    blob = json.dumps(doc).lower()
    for needle in _FORBIDDEN:
        if needle.lower() in blob:
            raise AttestationError(f"attestation must not contain {needle!r} (secret-bearing)")
    env = doc.get("environment")
    if env not in ("staging", "production"):
        raise AttestationError("environment must be 'staging' or 'production'")
    sha = doc.get("release_sha")
    if not isinstance(sha, str) or not re.match(r"^[0-9a-f]{40}$", sha):
        raise AttestationError("release_sha must be a 40-hex git SHA")
    raw_keys = doc.get("keys")
    if not isinstance(raw_keys, list) or len(raw_keys) != len(KEY_CLASSES):
        raise AttestationError("keys must list exactly the api, worker and scheduler keys")
    keys: dict[str, KeyAttestation] = {}
    for item in raw_keys:
        if not isinstance(item, dict):
            raise AttestationError("keys entries must be objects")
        cls, kid, fp = item.get("purpose_class"), item.get("key_id"), item.get("sha256_fingerprint")
        if cls not in KEY_CLASSES or cls in keys:
            raise AttestationError("keys must contain each of api/worker/scheduler once")
        if not isinstance(kid, str) or not kid:
            raise AttestationError(f"keys[{cls}].key_id required")
        if not isinstance(fp, str) or not _FP_RE.match(fp):
            raise AttestationError(f"keys[{cls}].sha256_fingerprint must be 64 hex characters")
        keys[cls] = KeyAttestation(key_class=cls, key_id=kid, sha256_fingerprint=fp)
    if len({k.sha256_fingerprint for k in keys.values()}) != len(KEY_CLASSES):
        raise AttestationError("fingerprints must be distinct (independent keys)")
    operator = doc.get("operator")
    if not isinstance(operator, str) or not _OPERATOR_RE.match(operator):
        raise AttestationError("operator identifier required")
    label = doc.get("escrow_location_label")
    if not isinstance(label, str) or not _LABEL_RE.match(label):
        raise AttestationError("escrow_location_label required (a non-secret label, not a URL)")
    if doc.get("recovery_test_confirmed") is not True:
        raise AttestationError("recovery_test_confirmed must be literally true")
    return EscrowAttestation(
        environment=env,
        release_sha=sha,
        keys=keys,
        escrow_verified_at=_parse_ts(doc.get("escrow_verified_at")),
        operator=operator,
        recovery_test_confirmed=True,
        escrow_location_label=label,
    )


def load_attestation(path: Path) -> EscrowAttestation:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AttestationError(f"escrow attestation not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AttestationError("escrow attestation is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise AttestationError("escrow attestation must be a JSON object")
    return parse_attestation(doc)


def verify_attestation(
    att: EscrowAttestation,
    release: ReleaseSpec,
    host_fingerprints: dict[str, tuple[str, str]],
    *,
    now: datetime,
) -> None:
    """``host_fingerprints`` maps class -> (key_id, sha256 fingerprint) as read
    from the key files ON THE HOST. Every mismatch is a hard failure."""
    if att.environment != release.environment:
        raise AttestationError("attestation environment does not match the release")
    if att.release_sha != release.release_sha:
        raise AttestationError("attestation release_sha does not match the release")
    if att.escrow_verified_at > now + timedelta(minutes=5):
        raise AttestationError("escrow_verified_at is in the future")
    if now - att.escrow_verified_at > MAX_AGE:
        raise AttestationError("escrow attestation is older than 30 days; re-verify escrow")
    if set(host_fingerprints) != set(KEY_CLASSES):
        raise AttestationError("host fingerprints must cover api, worker and scheduler")
    for cls in KEY_CLASSES:
        kid, fp = host_fingerprints[cls]
        if att.keys[cls].key_id != kid or att.keys[cls].key_id != release.key_ids[cls]:
            raise AttestationError(f"{cls}: key id in attestation/release/host differ")
        if att.keys[cls].sha256_fingerprint != fp:
            raise AttestationError(f"{cls}: attested fingerprint does not match the key file")
