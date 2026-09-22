"""Rollout state: per-release, host-side, metadata only (M12A-Prep §C).

The state file lives on the target (``<remote_app>/.rollout/<release_sha>.json``)
so a restarted phase sees what already happened on THAT host. It records phase
completion times and non-secret evidence (snapshot ids, fingerprints, digests,
counts). It never records credentials, key material, phrases, or URLs with
credentials, and the writer rejects anything that looks like one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from nlw.ops.rollout.remote import Remote

PHASES: tuple[str, ...] = (
    "preflight",
    "prepare-keys",
    "verify-escrow",
    "pin-release",
    "prepare-roles",
    "verify-backup",
    "drain",
    "migrate",
    "install-context-keys",
    "recreate-runtime",
    "validate",
    "reopen",
)
_FORBIDDEN = ("password", "passphrase", "secret", "token", "://", "AUTHORIZE_", "ESCROWED_")


class StateError(RuntimeError):
    pass


def _path(remote_app: str, release_sha: str) -> str:
    return f"{remote_app}/.rollout/{release_sha}.json"


def assert_state_is_secret_free(doc: dict[str, Any]) -> None:
    blob = json.dumps(doc, default=str)
    for needle in _FORBIDDEN:
        if needle in blob:
            raise StateError(f"rollout state must not contain {needle!r}")


def load_state(remote: Remote, remote_app: str, release_sha: str) -> dict[str, Any]:
    res = remote.run(f"cat '{_path(remote_app, release_sha)}' 2>/dev/null || echo '{{}}'")
    if not res.ok:
        raise StateError("could not read rollout state")
    try:
        doc = json.loads(res.text or "{}")
    except json.JSONDecodeError as exc:
        raise StateError("rollout state file is corrupt") from exc
    if not isinstance(doc, dict):
        raise StateError("rollout state file is not an object")
    doc.setdefault("phases", {})
    doc.setdefault("evidence", {})
    return doc


def save_state(remote: Remote, remote_app: str, release_sha: str, doc: dict[str, Any]) -> None:
    assert_state_is_secret_free(doc)
    payload = json.dumps(doc, indent=2, sort_keys=True, default=str)
    path = _path(remote_app, release_sha)
    res = remote.run(
        f"mkdir -p '{remote_app}/.rollout' && umask 077 && "
        f"cat > '{path}.tmp' && mv '{path}.tmp' '{path}'",
        stdin=payload,
    )
    if not res.ok:
        raise StateError("could not write rollout state")


def mark_phase(doc: dict[str, Any], phase: str, **evidence: Any) -> None:
    if phase not in PHASES:
        raise StateError(f"unknown phase {phase}")
    doc["phases"][phase] = {"completed_at": datetime.now(UTC).isoformat()}
    if evidence:
        doc["evidence"][phase] = evidence


def phase_done(doc: dict[str, Any], phase: str) -> bool:
    return phase in doc.get("phases", {})


def require_phases(doc: dict[str, Any], *phases: str) -> None:
    missing = [p for p in phases if not phase_done(doc, p)]
    if missing:
        raise StateError(f"required phase(s) not completed on this host: {missing}")
