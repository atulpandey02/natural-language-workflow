"""Pure, testable rollout gates (M12A-Prep §C/§D/§H).

Every function here takes plain values already read from the host and either
returns normalized data or raises ``GateError``. No I/O, no secrets: callers
pass counts, role attribute strings, revision names and the operator's typed
phrases — never credentials or key material.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from nlw.ops.rollout.release import ReleaseSpec

AUTHORIZATION_PHRASE = "AUTHORIZE_M12A_SIGNED_CONTEXT_STAGING_DEPLOYMENT"
ESCROW_PHRASE = "SIGNED_CONTEXT_KEYS_ESCROWED_AND_RECOVERY_TESTED"

# Expected role model on the target database AFTER role provisioning. Value =
# canlogin / superuser / bypassrls as t/f — the same encoding the reviewed
# verify-staging-deployment.sh uses. The migration owner is checked separately.
EXPECTED_ROLES: dict[str, str] = {
    "nlw_app": "tff",
    "nlw_worker": "tff",
    "nlw_scheduler": "tff",
    "nlw_rls_bypass": "fft",
    "nlw_workspace_bootstrap": "fft",
    "nlw_membership_admin": "fft",
    "nlw_ctx_verifier": "fff",
}
# Roles that must ALREADY exist before the upgrade (M11 set); the two P3A/P3B
# roles are the ones prepare-roles may create.
PRE_UPGRADE_ROLES = frozenset(
    {"nlw_app", "nlw_worker", "nlw_scheduler", "nlw_rls_bypass", "nlw_workspace_bootstrap"}
)
PROVISIONABLE_ROLES = frozenset({"nlw_membership_admin", "nlw_ctx_verifier"})
RUNTIME_ROLES = ("nlw_app", "nlw_worker", "nlw_scheduler")


class GateError(RuntimeError):
    """A rollout precondition is not met. Always safe to stop on."""


def check_instance_identity(imds_instance_id: str, imds_region: str, release: ReleaseSpec) -> None:
    got = imds_instance_id.strip()
    if not got:
        raise GateError("could not read the instance id from IMDSv2 on the target")
    if got != release.instance_id:
        raise GateError(f"target instance {got!r} != release instance {release.instance_id!r}")
    if imds_region.strip() != release.region:
        raise GateError(
            f"target region {imds_region.strip()!r} != release region {release.region!r}"
        )


def check_public_ip_matches_hostname(imds_public_ip: str, release: ReleaseSpec) -> None:
    """sslip.io hostnames encode the IP; a changed IP invalidates TLS + Supabase config."""
    host = release.public_hostname
    if host.endswith(".sslip.io"):
        encoded = host[: -len(".sslip.io")].replace("-", ".")
        if encoded != imds_public_ip.strip():
            raise GateError(
                f"public hostname {host} encodes {encoded} but the instance reports "
                f"{imds_public_ip.strip()!r} — the address changed; stop"
            )


def parse_env_pins(env_text: str) -> dict[str, str]:
    """Extract ONLY the non-secret pin lines from .env.prod text."""
    wanted = {
        "NLW_IMAGE",
        "NLW_WEB_IMAGE",
        "PUBLIC_HOSTNAME",
        "NLW_CTX_KEYS_DIR",
        "NLW_CTX_API_KEY_ID",
        "NLW_CTX_WORKER_KEY_ID",
        "NLW_CTX_SCHEDULER_KEY_ID",
    }
    out: dict[str, str] = {}
    for line in env_text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            if k.strip() in wanted:
                out[k.strip()] = v.strip()
    return out


def check_release_pins(pins: dict[str, str], release: ReleaseSpec, *, post_pin: bool) -> None:
    """Before ``migrate`` the host must ALREADY be pinned to the release images
    (pin_release does that); the hostname must always match."""
    if pins.get("PUBLIC_HOSTNAME") != release.public_hostname:
        raise GateError("PUBLIC_HOSTNAME in .env.prod does not match the release")
    if post_pin:
        if pins.get("NLW_IMAGE") != release.backend_image:
            raise GateError("NLW_IMAGE in .env.prod is not the release backend digest")
        if pins.get("NLW_WEB_IMAGE") != release.web_image:
            raise GateError("NLW_WEB_IMAGE in .env.prod is not the release web digest")
        for cls, kid in release.key_ids.items():
            if pins.get(f"NLW_CTX_{cls.upper()}_KEY_ID") != kid:
                raise GateError(f"NLW_CTX_{cls.upper()}_KEY_ID in .env.prod is not {kid!r}")
        if not pins.get("NLW_CTX_KEYS_DIR", "").startswith("/"):
            raise GateError("NLW_CTX_KEYS_DIR in .env.prod must be an absolute path")


def check_current_revision(current: str, expected: str) -> None:
    cur = current.strip()
    if not cur:
        raise GateError("could not read alembic_version from the target database")
    if cur != expected:
        raise GateError(f"database is at {cur!r}, expected {expected!r} — unknown migration state")


def check_authorization(phrase: str | None) -> None:
    """Only the EXACT phrase authorizes mutation. No --yes, no substring, no env."""
    if phrase is None or phrase != AUTHORIZATION_PHRASE:
        raise GateError("mutation requires the exact operator authorization phrase")


def check_escrow_confirmation(phrase: str | None) -> None:
    if phrase is None or phrase != ESCROW_PHRASE:
        raise GateError("mutation requires the exact escrow confirmation phrase")


def parse_role_lines(text: str) -> dict[str, str]:
    """``rolname:tft`` lines (canlogin/super/bypassrls) -> {name: 'tft'}."""
    roles: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(nlw[a-z_]*):([tf]{3})$", line)
        if not m:
            raise GateError(f"unparseable role line {line!r}")
        roles[m.group(1)] = m.group(2)
    return roles


def check_roles(roles: dict[str, str], *, require_provisioned: bool) -> None:
    """Existing roles must have EXACTLY the expected attributes (an incompatible
    role is an error, never silently widened/narrowed). The two provisionable
    roles may be absent before ``prepare-roles``; never after."""
    for name, want in EXPECTED_ROLES.items():
        got = roles.get(name)
        if got is None:
            if name in PROVISIONABLE_ROLES and not require_provisioned:
                continue
            raise GateError(f"role {name} is missing")
        if got != want:
            raise GateError(
                f"role {name} has attributes {got} (canlogin/super/bypassrls), want {want}"
            )
    extra = {n for n in roles if n.startswith("nlw_") and n not in EXPECTED_ROLES}
    if extra:
        raise GateError(f"unexpected nlw_* roles present: {sorted(extra)}")


def check_no_runtime_sessions(count: int) -> None:
    if count != 0:
        raise GateError(f"{count} runtime database session(s) still open; stop runtimes first")


@dataclass(frozen=True)
class DrainSnapshot:
    non_terminal_runs: int
    pending_actions: int
    leased_actions: int
    queue_depth: int


def check_drained(d: DrainSnapshot) -> None:
    problems = []
    if d.non_terminal_runs:
        problems.append(f"{d.non_terminal_runs} non-terminal run(s)")
    if d.pending_actions:
        problems.append(f"{d.pending_actions} pending external action(s)")
    if d.leased_actions:
        problems.append(f"{d.leased_actions} leased external action(s)")
    if d.queue_depth:
        problems.append(f"{d.queue_depth} queued message(s)")
    if problems:
        raise GateError(
            "drain not clean: " + ", ".join(problems) + " — never force-retry ambiguous work"
        )


def check_policy_cutover(policy_count: int, legacy_count: int, *, expected_policies: int) -> None:
    if policy_count != expected_policies:
        raise GateError(f"{policy_count} live policies, expected {expected_policies}")
    if legacy_count != 0:
        raise GateError(
            f"{legacy_count} live policies still trust unsigned app.user_id/app.tenant_id"
        )


def check_running_images(images: dict[str, str], release: ReleaseSpec) -> None:
    """Every runtime container must run the release digests (never the old runtime)."""
    for svc in ("api", "worker", "scheduler"):
        got = images.get(svc, "")
        if not got.endswith("@" + release.backend_digest):
            raise GateError(f"{svc} is running {got or '<none>'}, not the release backend digest")
    if not images.get("web", "").endswith("@" + release.web_digest):
        raise GateError("web is not running the release web digest")


def check_readiness_body(body: str) -> None:
    if '"status":"ready"' not in body.replace(" ", ""):
        raise GateError("API readiness is not 'ready'")
    if '"signed_context":"ok"' not in body.replace(" ", ""):
        raise GateError("API readiness does not report signed_context: ok")
