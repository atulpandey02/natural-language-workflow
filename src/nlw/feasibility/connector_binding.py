"""Authoritative connector identity binding (M12B final correction, Part 3).

Name-only connector references are unsafe: a connector can be deleted and
recreated (or materially reconfigured) under the same name, after which an
existing workflow would silently talk to a *different* system. This module pins
each connector-backed step to the connector's durable IDENTITY (its UUID) plus a
non-secret fingerprint of its execution-relevant configuration, computed once
during deterministic materialization and re-verified before every use.

Design invariants:
- the binding is computed deterministically from the tenant's authoritative
  connectors — the LLM never sees or chooses a connector UUID/fingerprint;
- the fingerprint covers only ``connectors.config`` (destination/settings). The
  secret lives in ``secret_ref`` (a separate column), so a secret ROTATION never
  changes the fingerprint and never invalidates a workflow;
- verification loads by the BOUND UUID (tenant-scoped), never re-resolves by name,
  so delete+recreate-with-same-name yields a new UUID and fails closed;
- a type change or an execution-relevant config change is STALE;
- everything is fail-closed: an unresolved/undecidable binding is STALE, never
  fresh.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from nlw.feasibility.engine import FeasibilityCode


def fingerprint_config(config: Mapping[str, Any]) -> str:
    """sha256 over the canonical (sorted-key) JSON of the connector config.

    Excludes secrets by construction: the secret is referenced by ``secret_ref``,
    not stored in ``config``. A destination/setting change flips this; a secret
    rotation does not.
    """
    canonical = json.dumps(
        dict(config), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CurrentConnector:
    """The authoritative connector state at verification time (tenant-scoped)."""

    connector_id: str
    connector_type: str
    config: Mapping[str, Any]
    status: str


def build_binding(
    connector_id: str, connector_type: str, config: Mapping[str, Any]
) -> dict[str, str]:
    """The immutable binding record persisted per connector-backed step."""
    return {
        "connector_id": str(connector_id),
        "connector_type": connector_type,
        "config_fingerprint": fingerprint_config(config),
    }


def verify_binding(binding: Mapping[str, str], current: CurrentConnector | None) -> str | None:
    """Re-verify a stored binding against the CURRENT connector. Fail closed.

    Returns ``None`` when the binding is still fresh, or a stable low-cardinality
    ``FeasibilityCode`` value (string) naming why it is STALE. ``current`` is the
    connector loaded BY THE BOUND UUID (tenant-scoped) — ``None`` means no such
    connector exists for this tenant (deleted, or recreated under a new UUID).
    """
    if current is None:
        return FeasibilityCode.CONNECTOR_NOT_FOUND.value
    if str(current.connector_id) != str(binding["connector_id"]):
        # Loaded a different row than bound (should not happen when loading by id).
        return FeasibilityCode.CONNECTOR_NOT_FOUND.value
    if current.connector_type != binding["connector_type"]:
        return FeasibilityCode.CONNECTOR_TYPE_MISMATCH.value
    if current.status == "disabled":
        return FeasibilityCode.CONNECTOR_UNUSABLE.value
    if fingerprint_config(current.config) != binding["config_fingerprint"]:
        return FeasibilityCode.CONNECTOR_CONFIG_CHANGED.value
    return None


class StalePlanError(Exception):
    """Raised at execution when a bound connector is no longer fresh.

    Carries a stable, low-cardinality ``reason_code`` (a ``FeasibilityCode`` value)
    and a sanitized message; NEVER secrets, config values, or DB internals. It is a
    terminal, non-retryable failure — the customer must re-plan.
    """

    def __init__(self, reason_code: str, connector_name: str | None = None) -> None:
        self.reason_code = reason_code
        who = f" for '{connector_name}'" if connector_name else ""
        super().__init__(
            f"STALE_PLAN ({reason_code}): the connector{who} this workflow was bound "
            "to has been changed or removed; re-plan the request to continue."
        )
