"""Pure, testable rollout gates (M12A-Prep §C/§D/§H).

Every function here takes plain values already read from the host and either
returns normalized data or raises ``GateError``. No I/O, no secrets: callers
pass counts, role attribute strings, revision names and the operator's typed
phrases — never credentials or key material.
"""

from __future__ import annotations

import json
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


# ---- public edge hostnames (Caddy site addresses) ----------------------------
# One reviewed primary (the attested manifest's ``public_hostname``) and at most
# one reviewed fallback (``NLW_STAGING_PUBLIC_HOSTNAME_FALLBACK``, an sslip.io name
# that encodes the instance's own IPv4). Bare, lowercase, fully qualified names
# only: no scheme, port, path, wildcard, whitespace, quotes or trailing dot.
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_SSLIP_RE = re.compile(r"^(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\.sslip\.io$")
LOOPBACK_IPV4 = "127.0.0.1"


def hostname_problem(value: str) -> str | None:
    """Why ``value`` is not a canonical public hostname (None when it is)."""
    if not value:
        return "empty"
    if len(value) > 253 or any(len(label) > 63 for label in value.split(".")):
        return "too long"
    if not _HOSTNAME_RE.fullmatch(value):
        return "not a bare lowercase fully qualified hostname"
    return None


def sslip_ipv4(hostname: str) -> str | None:
    """The canonical dotted IPv4 an ``a-b-c-d.sslip.io`` name encodes, else None."""
    m = _SSLIP_RE.fullmatch(hostname)
    if m is None:
        return None
    octets = m.groups()
    if any(str(int(o)) != o or int(o) > 255 for o in octets):
        return None  # leading zeros / out of range: not the canonical encoding
    return ".".join(octets)


def check_fallback_hostname(fallback: str, primary: str) -> None:
    """A fallback must be a canonical sslip.io name, distinct from the primary."""
    problem = hostname_problem(fallback)
    if problem is not None:
        raise GateError(f"fallback public hostname is invalid ({problem})")
    if sslip_ipv4(fallback) is None:
        raise GateError("fallback public hostname must be a canonical <a-b-c-d>.sslip.io name")
    if fallback == primary:
        raise GateError("fallback public hostname duplicates the primary")


def check_edge_identity(
    imds_public_ip: str,
    release: ReleaseSpec,
    *,
    target_primary: str | None,
    fallback: str | None,
) -> None:
    """Pure, every-phase binding of the edge hostnames to this instance: the
    reviewed target names the SAME primary as the attested manifest, and the
    fallback (when configured) encodes the instance's actual public IPv4."""
    if target_primary is not None and target_primary != release.public_hostname:
        raise GateError(
            "target NLW_STAGING_PUBLIC_HOSTNAME differs from the attested release "
            "public_hostname — use the manifest generated for this target; STOP"
        )
    if fallback is None:
        return
    check_fallback_hostname(fallback, release.public_hostname)
    ip = imds_public_ip.strip()
    if sslip_ipv4(fallback) != ip:
        raise GateError(
            f"fallback hostname {fallback} does not encode the instance public IPv4 "
            f"{ip!r} — the address changed; stop"
        )


def check_primary_dns(primary: str, imds_public_ip: str, resolved: set[str]) -> None:
    """The primary must resolve to THIS instance before Caddy serves it (ACME
    HTTP-01 and every client depend on it). sslip.io names are checked by their
    encoding; RFC 6761 ``*.localhost`` names resolve to loopback by definition
    (disposable rehearsal only). ``resolved`` = the primary's IPv4 A records."""
    ip = imds_public_ip.strip()
    if not ip:
        raise GateError("could not read the instance public IPv4 from IMDSv2")
    if sslip_ipv4(primary) is not None:
        if sslip_ipv4(primary) != ip:
            raise GateError(f"public hostname {primary} does not encode {ip!r}; stop")
        return
    if primary.endswith(".localhost"):
        if ip != LOOPBACK_IPV4:
            raise GateError("a *.localhost public hostname is only valid on a loopback rehearsal")
        return
    if not resolved:
        raise GateError(f"public hostname {primary} has no IPv4 A record — configure DNS; stop")
    if ip not in resolved:
        raise GateError(
            f"public hostname {primary} resolves to {sorted(resolved)}, not this instance "
            f"({ip}) — fix DNS before activating the edge; stop"
        )


def check_active_hostname(pins: dict[str, str], release: ReleaseSpec, fallback: str | None) -> None:
    """Preflight: the ACTIVE edge must be a known neighbour of the reviewed one —
    its primary is the release primary or the reviewed fallback (forward switch,
    e.g. sslip-only -> custom domain + sslip fallback), or its fallback already
    serves the release primary (reverse switch back to the sslip name). Any other
    active hostname is an unknown edge state."""
    active = pins.get("PUBLIC_HOSTNAME")
    active_fallback = pins.get("PUBLIC_HOSTNAME_FALLBACK") or None
    forward = active in {release.public_hostname} | ({fallback} if fallback else set())
    reverse = active_fallback is not None and active_fallback == release.public_hostname
    if not (forward or reverse):
        raise GateError(
            "PUBLIC_HOSTNAME in the active .env.prod is neither the release primary nor "
            "the reviewed fallback, and the active edge does not already serve the "
            "release primary — unknown edge state; stop"
        )


def expected_edge_hosts(primary: str, fallback: str) -> list[str]:
    return sorted([primary, *([fallback] if fallback else [])])


def check_adapted_caddy_hosts(adapted_json: str, primary: str, fallback: str) -> list[str]:
    """``caddy adapt`` output: every host matcher across every HTTP route must be
    EXACTLY the reviewed primary (+ fallback) — one site, nothing else served."""
    try:
        servers = json.loads(adapted_json)["apps"]["http"]["servers"]
        sites = [
            [h for match in route.get("match", []) for h in match.get("host", [])]
            for server in servers.values()
            for route in server.get("routes", [])
        ]
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise GateError("cannot read the adapted Caddy configuration; STOP") from exc
    sites = [hosts for hosts in sites if hosts]
    if len(sites) != 1:
        # Two site blocks could route differently (e.g. no maintenance matcher):
        # both hostnames must share ONE site so every route applies identically.
        raise GateError(f"adapted Caddy config has {len(sites)} host sites, want exactly one")
    hosts = sites[0]
    if sorted(hosts) != expected_edge_hosts(primary, fallback):
        raise GateError(
            f"adapted Caddy site hosts {sorted(hosts)} != reviewed "
            f"{expected_edge_hosts(primary, fallback)}; re-run stage-release"
        )
    return sorted(hosts)


def check_running_edge_facts(
    lines: list[str], primary: str, fallback: str, caddyfile_sources: set[str]
) -> None:
    """Facts filtered from the RUNNING caddy container: only its two hostname
    variables and its /etc/caddy/Caddyfile mount (never other environment)."""
    if "NOT_RUNNING" in lines:
        raise GateError("the caddy container is not running; keep traffic closed")
    # ``lines`` are pre-filtered by the inspect template to the two hostname
    # variables and the Caddyfile mount — non-secret, so a mismatch names them.
    env = sorted(line for line in lines if line.startswith("PUBLIC_HOSTNAME"))
    want = sorted([f"PUBLIC_HOSTNAME={primary}", f"PUBLIC_HOSTNAME_FALLBACK={fallback}"])
    if env != want:
        raise GateError(
            f"running Caddy edge hostnames {env} != reviewed {want}; keep traffic closed"
        )
    mounts = [line.removeprefix("MOUNT=") for line in lines if line.startswith("MOUNT=")]
    allowed = sorted(f"{s}:false" for s in caddyfile_sources)
    if len(mounts) != 1 or mounts[0] not in allowed:
        raise GateError(
            "running Caddy does not mount the reviewed release Caddyfile read-only "
            f"(observed {mounts}, allowed {allowed}); keep traffic closed"
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
        "DEMO_TOOLS_ENABLED",
        "PUBLIC_HOSTNAME_FALLBACK",
    }
    out: dict[str, str] = {}
    for line in env_text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            if re.fullmatch(r"\s*(?:export\s+)?DEMO_TOOLS_ENABLED\s*", k) and (
                k != "DEMO_TOOLS_ENABLED" or v not in ("true", "false") or k in out
            ):
                raise GateError("noncanonical demo-tool pin; re-run stage-release")
            edge = re.fullmatch(r"\s*(?:export\s+)?(PUBLIC_HOSTNAME(?:_FALLBACK)?)\s*", k)
            if edge and (
                k != edge.group(1)
                or k in out
                or (hostname_problem(v) is not None and not (k.endswith("_FALLBACK") and v == ""))
            ):
                raise GateError("noncanonical edge-hostname pin; re-run stage-release")
            if k.strip() in wanted:
                out[k.strip()] = v.strip()
    return out


def check_release_pins(
    pins: dict[str, str],
    release: ReleaseSpec,
    *,
    post_pin: bool,
    demo_tools_enabled: bool | None = None,
    public_hostname_fallback: str | None = None,
) -> None:
    """Before ``migrate`` the host must ALREADY be pinned to the release images
    (pin_release does that); the hostname must always match. A STAGED file also
    carries the canonical ``PUBLIC_HOSTNAME_FALLBACK`` line (empty = no fallback)."""
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
        expected = "true" if demo_tools_enabled else "false"
        if type(demo_tools_enabled) is not bool or pins.get("DEMO_TOOLS_ENABLED") != expected:
            raise GateError("staged demo-tool policy mismatch; re-run stage-release")
        if pins.get("PUBLIC_HOSTNAME_FALLBACK") != (public_hostname_fallback or ""):
            raise GateError("staged fallback hostname mismatch; re-run stage-release")


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


# Go-live SQL that counts materialized workflow versions predating connector
# identity binding (migration 0019). Such versions have NULL connector_bindings and
# fall back to NAME resolution at execution — they are legacy and are NOT
# identity-pinned. The count is surfaced (never silently treated as protected).
LEGACY_CONNECTOR_BINDING_SQL = (
    "SELECT count(*) FROM workflow_versions WHERE connector_bindings IS NULL"
)


def report_legacy_connector_bindings(null_binding_versions: int) -> str:
    """Advisory go-live report (NOT a hard gate): surface how many workflow versions
    predate connector identity binding (0019) and therefore fall back to NAME
    resolution — legacy, NOT identity-pinned. Never claims they are protected; a
    non-zero count is informational, not a failure (legacy versions remain valid)."""
    if null_binding_versions < 0:
        raise GateError("legacy connector-binding count cannot be negative")
    if null_binding_versions == 0:
        return "connector bindings: 0 legacy versions — every workflow version is identity-pinned"
    return (
        f"connector bindings: {null_binding_versions} LEGACY workflow version(s) predate "
        "migration 0019 (connector_bindings IS NULL). These are NAME-resolved at execution, "
        "NOT identity-pinned; a connector rename/recreate is not stale-detected for them. "
        "Re-materialize them to pin identity."
    )


def check_policy_cutover(policy_count: int, legacy_count: int, *, expected_policies: int) -> None:
    if policy_count != expected_policies:
        raise GateError(f"{policy_count} live policies, expected {expected_policies}")
    if legacy_count != 0:
        raise GateError(
            f"{legacy_count} live policies still trust unsigned app.user_id/app.tenant_id"
        )


def check_workspace_bootstrap_gated(overloads: int, gated: bool, runtime_access: list[str]) -> None:
    """Phase 2 B01 (migration 0022): exactly one workspace bootstrap function
    exists and its body enforces the operator grant; no runtime role can touch
    the grant table. A host still running the ungated bootstrap is NO-GO."""
    if overloads != 1:
        raise GateError(f"{overloads} create_workspace_for_current_user overloads, expected 1")
    if not gated:
        raise GateError("create_workspace_for_current_user does not enforce creation grants")
    if runtime_access:
        raise GateError(f"runtime roles can access workspace_creation_grants: {runtime_access}")


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


def check_image_info(info: dict[str, object], release: ReleaseSpec) -> None:
    """The backend image must BE the release: same git SHA, the target migration
    head, every migration between expected+1 and target present, and the M12A
    modules importable (an older image fails here, before any mutation)."""
    if info.get("git_sha") != release.release_sha:
        raise GateError(
            f"image reports git sha {str(info.get('git_sha'))[:12]!r}, release is "
            f"{release.release_sha[:12]} — not the release artifact"
        )
    if info.get("alembic_head") != release.target_revision:
        raise GateError(
            f"image migration head {info.get('alembic_head')!r} != target "
            f"{release.target_revision!r}"
        )
    migrations = info.get("migrations")
    names = [str(m) for m in migrations] if isinstance(migrations, list) else []
    lo = int(release.expected_current_revision[:4]) + 1
    hi = int(release.target_revision[:4])
    have = {n[:4] for n in names}
    missing = [f"{n:04d}" for n in range(lo, hi + 1) if f"{n:04d}" not in have]
    if missing:
        raise GateError(f"image lacks migration file(s) {missing}")
    modules = info.get("modules")
    mods = modules if isinstance(modules, dict) else {}
    absent = [m for m, ok in mods.items() if not ok] or (["<none reported>"] if not mods else [])
    if absent:
        raise GateError(f"image lacks required module(s): {absent}")
