"""The rollout state machine (M12A-Prep §C/§D/§H): explicit phases, every
mutation re-gated, no database mutation before the verified off-host backup,
fail closed with runtimes stopped after migration.

Phase order for an upgrade from the expected current schema to the release's
target head (both named by the release manifest; ``state.PHASES``):

    preflight            read-only (the default)
    verify-release       pull the manifest digests; prove the exact image carries
                         the release SHA, the required commands, migrations, head
    prepare-keys         generate the three key files on the host (0700/0400) —
                         or verify + fingerprint the existing ones (N -> N+1)
    verify-escrow        operator attestation fingerprints == host key files
    stage-release        clone+checkout the release into <ops_root>/releases/<sha>
                         with its own pinned .env.prod; build the backup image.
                         The ACTIVE checkout, .env.prod and containers are untouched
    backup               run the real off-host backup (owner credential, read-only)
    verify-backup        evidence from the repository: off-host, verified, fresh,
                         bound to this instance/environment/database/revision/release
    ----- no database mutation above this line -----
    drain                caddy on the release config + maintenance 503; stop
                         scheduler; wait for zero work; stop worker+api; no sessions
    prepare-roles        create nlw_membership_admin / nlw_ctx_verifier if absent
    migrate              alembic upgrade head == manifest target_revision (migrate
                         service from the staged release)
    install-context-keys install + check the three registry keys (each one-shot
                         mounts ONLY its key file: the key dir is root 0700)
    recreate-runtime     ACTIVATE: <ops_root>/current -> staged release; recreate
                         api/worker/scheduler/web (+ monitoring, with the
                         operator Alertmanager override) from it
    validate             signed_context readiness, cutover, mounts, forgery,
                         health, alert rules/connectivity (delivery kept separate)
    reopen               leave maintenance mode; record open launch gates

The active checkout is what ``target.env`` names: the legacy ``<ops_root>/app``
for the first rollout, ``<ops_root>/current`` afterwards (``follows_current``);
the phases never guess it. Alerting for staging/production is evaluated from
the RUNNING Alertmanager against the operator's host files (``OperatorAlerting``),
never from the committed null config in a checkout.

Every command runs through the ``Remote`` (SSH to the host or local rehearsal).
Secrets never appear on argv: the installer reads files mounted into a
throwaway container; the staged ``.env.prod`` is written with a temp-file
rewrite that carries only image digests, key ids and paths.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from nlw.ops.release_provenance import ProvenanceReceipt
from nlw.ops.rollout import alerting, gates, keyfiles, state
from nlw.ops.rollout.attestation import (
    AttestationError,
    load_attestation,
    verify_attestation,
)
from nlw.ops.rollout.backup_evidence import (
    BackupEvidence,
    BackupEvidenceError,
    SourceBinding,
    evaluate_backup_evidence,
    parse_snapshots_json,
)
from nlw.ops.rollout.gates import GateError
from nlw.ops.rollout.release import KEY_CLASSES, ReleaseSpec
from nlw.ops.rollout.remote import OperatorAlerting, Remote, TargetConfig

EXPECTED_SIGNED_POLICIES = 51
# Caddy serves 503 for every request while this file exists on its `caddy_maint`
# volume (docker/caddy/Caddyfile `@maintenance`). Toggled with `exec`, no reload.
MAINTENANCE_FLAG = "/srv/maint/MAINTENANCE"
RUNTIME_SERVICES = ("api", "worker", "scheduler")
DRAIN_WAIT_S = 120
REVISION_LABEL = "org.opencontainers.image.revision"
# Commands the release image must be able to execute (M12A-Prep §B).
REQUIRED_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("-m", "nlw.ops.rollout", "--help"),
    ("-m", "nlw.ops.roles", "--help"),
    ("-m", "nlw.ctxkeys", "prepare", "--help"),
    ("-m", "nlw.ctxkeys", "fingerprint", "--help"),
    ("-m", "nlw.ctxkeys", "verify-files", "--help"),
    ("-m", "nlw.backup", "evidence", "--help"),
)
Log = Callable[[str], None]


@dataclass(frozen=True)
class Operator:
    """What the operator supplied on THIS invocation. Phrases are compared
    exactly and never stored."""

    authorization: str | None = None
    escrow_confirmation: str | None = None
    attestation_path: Path | None = None
    backup_max_age: timedelta = timedelta(hours=26)
    # REHEARSAL ONLY (LocalRemote): accept the disposable MinIO fixture as the
    # backup repository. Ignored — and refused — for a real (SSH) target.
    allow_fixture_repository: bool = False


class RolloutStop(RuntimeError):
    """Stop the rollout. The message is safe to print (no secrets)."""


@dataclass(frozen=True)
class OperatorConfigFacts:
    """What the operator's Alertmanager files say (host side, never secrets)."""

    receiver: str
    receivers: dict[str, alerting.ReceiverConfig]
    config_sha256: str
    credential_paths: dict[str, str]  # container path -> host path

    def evidence(self) -> dict[str, Any]:
        # Names only — never a path into the secrets directory.
        return {
            "receiver": self.receiver,
            "config_sha256": self.config_sha256,
            "credential_file_count": len(self.credential_paths),
        }


class Rollout:
    def __init__(
        self,
        *,
        release: ReleaseSpec,
        target: TargetConfig,
        remote: Remote,
        operator: Operator,
        log: Log,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        receipt: ProvenanceReceipt | None = None,
    ) -> None:
        self.release = release
        self.target = target
        self.remote = remote
        self.op = operator
        self.log = log
        self.now = now
        # The provenance receipt for THIS manifest (schema + image checks are not
        # authority). The CLI always verifies before constructing the rollout; the
        # receipt is stored on the host at verify-release as evidence.
        self.receipt = receipt
        self.staged = target.release_dir(release.release_sha)
        self.dc = target.dc  # ACTIVE checkout: exec / ps / stop only
        self.dc_staged = target.dc_in(self.staged)
        self._probe_image_cache: str | None = None

    # ---- helpers -----------------------------------------------------------
    def _run(self, cmd: str, *, stdin: str | None = None, timeout: int = 300) -> str:
        res = self.remote.run(cmd, stdin=stdin, timeout=timeout)
        if not res.ok:
            raise RolloutStop(f"command failed (exit {res.returncode}): {cmd.split(' ', 3)[:3]}")
        return res.text

    def _psql(self, sql: str) -> str:
        return self._run(f"{self.dc} exec -T postgres psql -U nlw -d nlw -tAc {shlex.quote(sql)}")

    def _state(self) -> dict[str, Any]:
        doc = state.load_state(self.remote, self.target, self.release.release_sha)
        state.bind_manifest(doc, self.release.sha256)
        return doc

    def _save(self, doc: dict[str, Any]) -> None:
        state.save_state(self.remote, self.target, self.release.release_sha, doc)

    def _migrate_run(self, extra: str, cmd: str, *, timeout: int = 600) -> str:
        """One-shot command in the STAGED release's migrate profile service (owner
        credential), container removed afterwards. ``extra`` adds run flags.

        ``--no-deps`` is mandatory: the staged release lives in a different
        directory from the one the running ``postgres`` container was created from,
        so its relative bind mounts (``./docker/postgres/initdb``) resolve to a
        different path and the service's config hash diverges. Without
        ``--no-deps`` Compose converges the ``depends_on`` dependency and RECREATES
        the live database container mid-rollout (reproduced with Compose v5). The
        database is proven reachable by the ``_psql`` gates that precede every call."""
        return self._run(
            f"{self.dc_staged} --profile migration run --rm --no-deps -T {extra} migrate {cmd}",
            timeout=timeout,
        )

    def _image_python(self, image: str, args: str, *, extra: str = "", timeout: int = 120) -> str:
        return self._run(
            f"docker run --rm --network none {extra} --entrypoint python {image} {args}",
            timeout=timeout,
        )

    def _require_mutation_authority(self) -> None:
        gates.check_authorization(self.op.authorization)

    # ---- gates (read-only) --------------------------------------------------
    def check_identity(self) -> dict[str, str]:
        out = self._run(
            'T=$(curl -sS -m 5 -X PUT "http://169.254.169.254/latest/api/token" '
            '-H "X-aws-ec2-metadata-token-ttl-seconds: 60"); '
            "for p in instance-id placement/region public-ipv4; do "
            'printf "%s=" "$p"; curl -sS -m 5 -H "X-aws-ec2-metadata-token: $T" '
            '"http://169.254.169.254/latest/meta-data/$p"; echo; done'
        )
        imds = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        gates.check_instance_identity(
            imds.get("instance-id", ""), imds.get("placement/region", ""), self.release
        )
        if self.target.instance_id != self.release.instance_id:
            raise GateError("target config instance id != release instance id")
        if self.target.compose_project != self.release.compose_project:
            raise GateError("target config compose project != release compose project")
        gates.check_public_ip_matches_hostname(imds.get("public-ipv4", ""), self.release)
        return imds

    def read_pins(self, directory: str) -> dict[str, str]:
        text = self._run(
            f"grep -E '^(NLW_IMAGE|NLW_WEB_IMAGE|PUBLIC_HOSTNAME|NLW_CTX_KEYS_DIR|"
            f"NLW_CTX_(API|WORKER|SCHEDULER)_KEY_ID)=' '{directory}/.env.prod'"
        )
        return gates.parse_env_pins(text)

    def read_revision(self) -> str:
        return self._psql("SELECT version_num FROM alembic_version")

    def read_db_system_identifier(self) -> str:
        return self._psql("SELECT system_identifier::text FROM pg_control_system()")

    def read_active_sha(self) -> str:
        return self._run(f"git -C '{self.target.remote_app}' rev-parse HEAD")

    def refuse_foreign_activation(self) -> str:
        """Bind the phases to the deployment ``target.env`` says is active.

        * ``follows_current`` (every rollout after the first): ``<ops_root>/current``
          must be a symlink into ``releases/`` — the PREVIOUS release (N) or, when a
          phase is re-run after activation, THIS release. A legacy host (no
          ``current``) is a configuration error, not a rollout.
        * legacy (first rollout, ``remote_app`` = ``<ops_root>/app``): ``current``
          must be absent or already point at THIS release; a host that has
          activated another release is served through ``current`` — the target must
          say so. Fail closed either way; nothing is changed."""
        cur = self.target.current_link
        out = self._run(
            f"if [ -L '{cur}' ]; then readlink '{cur}'; "
            f"elif [ -e '{cur}' ]; then echo NOT_A_SYMLINK; else echo ABSENT; fi"
        ).strip()
        if out == "NOT_A_SYMLINK":
            raise GateError(
                f"{cur} exists but is not a symlink: activation would not be able to "
                "switch it atomically — remove or rename it by hand (nothing was changed)"
            )
        if out == self.staged:
            return "THIS_RELEASE"
        if self.target.follows_current:
            if out == "ABSENT":
                raise GateError(
                    f"{cur} does not exist: this host has no activated release (legacy "
                    f"layout). For the FIRST rollout set NLW_STAGING_REMOTE_APP to the "
                    "legacy checkout (deploy/staging/target.env) — STOP (nothing was changed)"
                )
            if not out.startswith(f"{self.target.ops_root}/releases/"):
                raise GateError(
                    f"{cur} points at {out!r}, outside {self.target.ops_root}/releases/ — "
                    "not a release activated by this tooling; STOP (nothing was changed)"
                )
            return "PREVIOUS_RELEASE"
        if out == "ABSENT":
            return "ABSENT"
        raise GateError(
            f"{cur} already points at {out!r}: the active deployment is a release, not the "
            f"legacy checkout {self.target.remote_app}. Set NLW_STAGING_REMOTE_APP="
            f"{cur} (and NLW_STAGING_CURRENT_REVISION to the live revision) in "
            "deploy/staging/target.env — STOP (nothing was changed)"
        )

    # ---- operator Alertmanager authority (host files -> override -> running container) --
    def _probe_image(self) -> str:
        """An image present on the host for read-only stat/readability probes: the
        ACTIVE deployment's pinned backend image (running, hence pulled)."""
        if self._probe_image_cache is None:
            image = self.read_pins(self.target.remote_app).get("NLW_IMAGE", "")
            if "@sha256:" not in image:
                raise GateError("active .env.prod carries no digest-pinned NLW_IMAGE")
            self._probe_image_cache = image
        return self._probe_image_cache

    def _stat_host_path(self, path: str, *, directory: bool) -> keyfiles.StatLine:
        """stat a host path through a throwaway root container (the rollout user
        cannot traverse root-owned secret directories; the daemon can). Read-only,
        no network; the file's CONTENT is never read."""
        mount = f"-v '{path}:/probe:ro'" if directory else f"-v '{path}:/probe/f:ro'"
        target = "'/probe/.'" if directory else "/probe/f"
        line = self._run(
            f"docker run --rm --user 0:0 --network none --entrypoint stat {mount} "
            f"{self._probe_image()} -c '{keyfiles.STAT_FORMAT}' {target}"
        )
        return keyfiles.parse_stat_line(line)

    def _read_host_text(self, path: str, what: str) -> str:
        out = self._run(f"if [ -r '{path}' ]; then cat '{path}'; else echo __UNREADABLE__; fi")
        if out.strip() == "__UNREADABLE__" or not out.strip():
            raise GateError(
                f"{what} {path} is missing, empty or not readable by the rollout user "
                f"({self.target.ssh_user}) — STOP"
            )
        return out

    def _check_outside_releases(self, path: str, what: str) -> None:
        roots = (
            f"{self.target.ops_root}/releases/",
            self.target.current_link + "/",
            self.target.remote_app.rstrip("/") + "/",
        )
        if any(path.startswith(r) for r in roots):
            raise GateError(
                f"{what} {path} lies inside a release checkout: operator authority must live "
                f"on the host outside {self.target.ops_root}/releases/ and "
                f"{self.target.current_link}"
            )

    def check_alertmanager_authority(self) -> OperatorConfigFacts:
        """Fail closed unless the operator's Alertmanager files exist, are sane and
        are wired through the reviewed override: real (non-null) receiver with
        ``*_file`` credentials inside the secrets mount; config root-owned and not
        writable by others; secrets dir + files not world-accessible; every
        credential readable AS the Alertmanager user (uid 65534); the override
        mounts exactly those host paths read-only. Contents of credential files are
        never read."""
        contract: OperatorAlerting | None = self.target.operator_alerting
        if contract is None:
            raise GateError(
                "operator Alertmanager configuration is required for staging/production: set "
                "NLW_STAGING_ALERTMANAGER_CONFIG, NLW_STAGING_ALERTMANAGER_SECRETS_DIR and "
                "NLW_STAGING_COMPOSE_OVERRIDE in deploy/staging/target.env (docs/ops/alerting.md)"
            )
        for path, what in (
            (contract.config_path, "operator Alertmanager config"),
            (contract.secrets_dir, "Alertmanager secrets directory"),
            (contract.override_path, "operator Compose override"),
        ):
            self._check_outside_releases(path, what)
        override_doc = yaml.safe_load(
            self._read_host_text(contract.override_path, "operator Compose override")
        )
        alerting.check_override_mounts(
            alerting.override_alertmanager_mounts(override_doc),
            config_path=contract.config_path,
            secrets_dir=contract.secrets_dir,
            what="operator Compose override",
        )
        cfg_text = self._read_host_text(contract.config_path, "operator Alertmanager config")
        default, receivers = alerting.check_operator_config(cfg_text)
        cfg_sha = self._run(f"sha256sum '{contract.config_path}' | cut -d' ' -f1").strip()
        alerting.check_config_file_stat(
            self._stat_host_path(contract.config_path, directory=False), contract.config_path
        )
        alerting.check_secrets_dir_stat(
            self._stat_host_path(contract.secrets_dir, directory=True), contract.secrets_dir
        )
        cred = alerting.credential_host_paths(receivers, default, contract.secrets_dir)
        rel = [c[len(alerting.SECRETS_MOUNT) + 1 :] for c in cred]
        for name, host in zip(rel, cred.values(), strict=True):
            res = self.remote.run(
                f"docker run --rm --user 0:0 --network none --entrypoint stat "
                f"-v '{contract.secrets_dir}:/probe:ro' {self._probe_image()} "
                f"-c '{keyfiles.STAT_FORMAT}' '/probe/{name}'"
            )
            if not res.ok:
                raise GateError(f"credential file {host} is missing — STOP")
            alerting.check_credential_file_stat(keyfiles.parse_stat_line(res.text), host)
        probe = " ".join(shlex.quote(n) for n in rel)
        script = (
            f'for f in {probe}; do if [ -r "/probe/$f" ]; then echo "$f R"; '
            'else echo "$f X"; fi; done'
        )
        readable = self._run(
            f"docker run --rm --user {alerting.ALERTMANAGER_UID}:{alerting.ALERTMANAGER_UID} "
            f"--network none --entrypoint sh -v '{contract.secrets_dir}:/probe:ro' "
            f"{self._probe_image()} -c {shlex.quote(script)}"
        )
        verdicts = dict(line.split() for line in readable.splitlines() if len(line.split()) == 2)
        for name, host in zip(rel, cred.values(), strict=True):
            if verdicts.get(name) != "R":
                raise GateError(
                    f"credential file {host} is not readable by the Alertmanager user "
                    f"(uid {alerting.ALERTMANAGER_UID}): want root:65534 0640 in a root:65534 "
                    "0750 directory (docs/ops/alerting.md) — STOP"
                )
        return OperatorConfigFacts(default, receivers, cfg_sha, cred)

    def check_rendered_alertmanager_mounts(self, facts: OperatorConfigFacts) -> None:
        """The staged release's RENDERED Compose config (with the override) must
        mount the operator paths — proven before Alertmanager is (re)created."""
        contract = self.target.operator_alerting
        assert contract is not None
        raw = self._run(f"{self.dc_staged} config --format json")
        try:
            rendered = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GateError("rendered Compose config is not JSON") from exc
        mounts = alerting.override_alertmanager_mounts(
            {
                "services": {
                    "alertmanager": {
                        "volumes": rendered["services"]["alertmanager"].get("volumes", [])
                    }
                }
            }
            if isinstance(rendered, dict) and "alertmanager" in (rendered.get("services") or {})
            else {}
        )
        alerting.check_override_mounts(
            mounts,
            config_path=contract.config_path,
            secrets_dir=contract.secrets_dir,
            what="rendered Compose config",
        )

    def verify_alertmanager_runtime(self, facts: OperatorConfigFacts) -> None:
        """The RUNNING container is the authority: its mounts come from the operator
        paths (read-only), the mounted bytes equal the host file, the LOADED config
        (``/api/v2/status``) routes to the same receiver/credential files, and
        every credential is readable as the container's own user."""
        contract = self.target.operator_alerting
        assert contract is not None
        mounts_raw = self._run(
            "docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}}:{{.RW}} "
            f"{{{{end}}}}' $({self.dc_staged} ps -q alertmanager | head -1)"
        )
        # The daemon reports the RESOLVED source: on Linux the host path itself; on
        # Docker Desktop (rehearsal only) possibly `/host_mnt<realpath>`. Accept the
        # operator path or its `readlink -f` form, nothing else.
        aliases: dict[str, str] = {}
        for want in (contract.config_path, contract.secrets_dir):
            real = self._run(f"readlink -f '{want}' 2>/dev/null || echo '{want}'").strip()
            for form in (want, real):
                aliases[form.rstrip("/")] = want
        mounts: dict[str, tuple[str, bool]] = {}
        for item in mounts_raw.split():
            parts = item.rsplit(":", 2)
            if len(parts) == 3:
                src = parts[0]
                if src.startswith("/host_mnt/"):
                    src = src[len("/host_mnt") :]
                mounts[parts[1]] = (aliases.get(src.rstrip("/"), parts[0]), parts[2] == "false")
        alerting.check_override_mounts(
            mounts,
            config_path=contract.config_path,
            secrets_dir=contract.secrets_dir,
            what="running Alertmanager container",
        )
        mounted_sha = self._run(
            f"{self.dc_staged} exec -T alertmanager sha256sum {alerting.CONFIG_MOUNT} "
            "| cut -d' ' -f1"
        ).strip()
        if mounted_sha != facts.config_sha256:
            raise GateError(
                "the Alertmanager config mounted in the running container and the operator "
                f"file {contract.config_path} differ (sha256 {mounted_sha[:12]} != "
                f"{facts.config_sha256[:12]}): recreate the container — STOP"
            )
        status_raw = self.remote.run(
            f"{self.dc_staged} exec -T alertmanager wget -qO- http://127.0.0.1:9093/api/v2/status"
        )
        try:
            loaded = (json.loads(status_raw.text).get("config") or {}).get("original")
        except (json.JSONDecodeError, AttributeError):
            loaded = None
        if not status_raw.ok or not isinstance(loaded, str):
            raise GateError("running Alertmanager did not report its loaded configuration — STOP")
        alerting.check_loaded_matches_mounted(
            loaded, default=facts.receiver, receivers=facts.receivers
        )
        files = " ".join(shlex.quote(c) for c in facts.credential_paths)
        script = (
            f'for f in {files}; do if [ -r "$f" ]; then echo "$f R"; else echo "$f X"; fi; done'
        )
        readable = self._run(f"{self.dc_staged} exec -T alertmanager sh -c {shlex.quote(script)}")
        verdicts = dict(line.split() for line in readable.splitlines() if len(line.split()) == 2)
        for c in facts.credential_paths:
            if verdicts.get(c) != "R":
                raise GateError(
                    f"credential file {c} is not readable inside the running Alertmanager "
                    "container — STOP"
                )

    def _read_delivery_record(self) -> tuple[dict[str, Any] | None, str | None]:
        path = f"{self.target.state_dir}/alert-delivery.json"
        res = self.remote.run(
            f"if [ -e '{path}' ]; then if [ -r '{path}' ]; then echo __OK__; cat '{path}'; "
            f"else echo __UNREADABLE__; fi; else echo __ABSENT__; fi"
        )
        if not res.ok:
            return None, "unreadable"
        return alerting.classify_delivery_record(res.text)

    def check_backup_env_file(self) -> str:
        """The backup job's env file (restic repository + provider credentials) is
        read CLIENT-SIDE by ``docker compose --env-file`` as the rollout's SSH user
        — never by root. A file that is missing, unreadable, or world-readable
        stops the rollout here (preflight) instead of failing inside ``backup``,
        and its contents are never read by this check (mode + readability only)."""
        path = self.target.backup_env_file
        # Portable (GNU + BSD): readability via the shell test, the permission
        # string via `ls -ld` (never `stat -c`, which BSD stat does not know).
        res = self.remote.run(
            f"if [ -r '{path}' ] && [ -f '{path}' ]; then "
            f"if [ -s '{path}' ]; then ls -ld '{path}' | cut -c1-10; else echo EMPTY; fi; "
            f"else echo MISSING_OR_UNREADABLE; fi"
        )
        perms = res.text.strip()
        if perms == "EMPTY":
            raise GateError(
                f"backup env file {path} is empty: the backup job would fail closed inside "
                "the backup phase (missing RESTIC_REPOSITORY / RESTIC_PASSWORD / provider "
                "credentials / NLW_BACKUP_DATABASE_URL); fill it from .env.backup.example first"
            )
        if not res.ok or perms == "MISSING_OR_UNREADABLE" or len(perms) != 10:
            raise GateError(
                f"backup env file {path} is missing or not readable by the rollout user "
                f"({self.target.ssh_user}); the backup + verify-backup phases run "
                "`docker compose --env-file` as that user (no sudo). Provide the file "
                "readable by that user (e.g. root:<group> 0640) or point "
                "NLW_STAGING_BACKUP_ENV_FILE at the readable copy — see the runbook"
            )
        if perms[7] != "-":
            raise GateError(
                f"backup env file {path} has permissions {perms}: it must not be world-readable"
            )
        return perms

    def read_roles(self) -> dict[str, str]:
        text = self._psql(
            "SELECT rolname||':'||CASE WHEN rolcanlogin THEN 't' ELSE 'f' END"
            "||CASE WHEN rolsuper THEN 't' ELSE 'f' END"
            "||CASE WHEN rolbypassrls THEN 't' ELSE 'f' END"
            " FROM pg_roles WHERE rolname LIKE 'nlw\\_%' ORDER BY rolname"
        )
        return gates.parse_role_lines(text)

    def read_drain(self) -> gates.DrainSnapshot:
        row = self._psql(
            "SELECT (SELECT count(*) FROM workflow_runs WHERE status IN "
            "('PENDING','RUNNING','WAITING_APPROVAL')), "
            "(SELECT count(*) FROM external_actions WHERE status='pending'), "
            "(SELECT count(*) FROM external_actions WHERE lease_expires_at > now())"
        )
        runs, pending, leased = (int(x) for x in row.split("|"))
        q = int(self._run(f"{self.dc} exec -T redis redis-cli llen dramatiq:default") or "0")
        return gates.DrainSnapshot(runs, pending, leased, q)

    def read_runtime_sessions(self) -> int:
        return int(
            self._psql(
                "SELECT count(*) FROM pg_stat_activity WHERE usename IN "
                "('nlw_app','nlw_worker','nlw_scheduler')"
            )
        )

    def read_running_images(self) -> dict[str, str]:
        """service -> repository digest of the image each runtime container is
        ACTUALLY running (container -> image id -> RepoDigests), found by the
        Compose project label — never by what a compose file says it should be."""
        proj = self.target.compose_project
        out = self._run(
            "for s in api worker scheduler web; do "
            f"c=$(docker ps -q --filter label=com.docker.compose.project={proj} "
            "--filter label=com.docker.compose.service=$s | head -1); "
            '[ -n "$c" ] && echo "$s $(docker inspect --format \'{{join .RepoDigests " "}}\' '
            '"$(docker inspect --format \'{{.Image}}\' "$c")")"; done; true'
        )
        images: dict[str, str] = {}
        for line in out.splitlines():
            parts = line.split()
            digests = [d for d in parts[1:] if "@sha256:" in d]
            if len(parts) >= 2 and digests:
                wanted = self.release.web_image if parts[0] == "web" else self.release.backend_image
                images[parts[0]] = wanted if wanted in digests else digests[0]
        return images

    def verify_checkout(self, directory: str) -> None:
        """``directory`` must be a clean checkout of the release SHA."""
        sha = self._run(f"git -C '{directory}' rev-parse HEAD")
        if sha != self.release.release_sha:
            raise GateError(
                f"{directory} is at {sha[:12]}, release is {self.release.release_sha[:12]}"
            )
        if self._run(f"git -C '{directory}' status --porcelain"):
            raise GateError(f"{directory} checkout is not clean")

    # ---- phases -------------------------------------------------------------
    def preflight(self) -> dict[str, Any]:
        """READ-ONLY. Safe to run at any time."""
        self.log(f"target: {self.remote.describe()}")
        imds = self.check_identity()
        self.log(f"instance ok: {imds.get('instance-id')} {imds.get('placement/region')}")
        pins = self.read_pins(self.target.remote_app)
        gates.check_release_pins(pins, self.release, post_pin=False)
        rev = self.read_revision()
        roles = self.read_roles()
        gates.check_roles(roles, require_provisioned=False)
        drain = self.read_drain()
        current_shape = self.refuse_foreign_activation()
        backup_env_mode = self.check_backup_env_file()
        am = self.check_alertmanager_authority()
        doc = self._state()
        if not state.phase_done(doc, "migrate"):
            gates.check_current_revision(rev, self.release.expected_current_revision)
        report = {
            "alertmanager": am.evidence(),
            "backup_env_mode": backup_env_mode,
            "current_link": current_shape,
            "manifest_sha256": self.release.sha256,
            "release_sha": self.release.release_sha,
            "instance_id": imds.get("instance-id"),
            "region": imds.get("placement/region"),
            "active_checkout": self.read_active_sha(),
            "current_revision": rev,
            "roles": roles,
            "drain": drain.__dict__,
            "phases_done": sorted(doc["phases"]),
        }
        self.log("preflight: " + json.dumps(report, sort_keys=True))
        return report

    def verify_release(self) -> dict[str, Any]:
        """Prove the EXACT pinned images are pullable, carry the release SHA, and
        (backend) expose every command the rollout needs plus the target migration
        head. Pulling is host staging only — nothing running changes."""
        self._require_mutation_authority()
        if self.receipt is None or self.receipt.manifest_sha256 != self.release.sha256:
            raise GateError("release provenance was not verified for this manifest — STOP")
        self.check_identity()
        doc = self._state()
        for image in (self.release.backend_image, self.release.web_image):
            self._run(f"docker pull -q {image} >/dev/null", timeout=900)
            label = self._run(
                f"docker inspect --format '{{{{index .Config.Labels \"{REVISION_LABEL}\"}}}}' "
                f"{image}"
            )
            if label != self.release.release_sha:
                raise GateError(
                    f"image {image.split('@')[0]} revision label {label!r} != release "
                    f"{self.release.release_sha[:12]} (older or foreign build)"
                )
        raw = self._image_python(self.release.backend_image, "-m nlw.ops.rollout.image_info")
        try:
            info = json.loads(raw.splitlines()[-1])
        except (json.JSONDecodeError, IndexError) as exc:
            raise GateError(
                "backend image cannot report its release identity (missing M12A tooling)"
            ) from exc
        gates.check_image_info(info, self.release)
        for args in REQUIRED_COMMANDS:
            res = self.remote.run(
                f"docker run --rm --network none --entrypoint python {self.release.backend_image} "
                + " ".join(args),
                timeout=120,
            )
            if not res.ok:
                raise GateError(f"backend image lacks required command: python {' '.join(args)}")
        # Evidence directory (outside every checkout): the verified manifest bytes
        # and the provenance receipt, next to the state file.
        sha = self.release.release_sha
        for name, payload in (
            (f"{sha}.manifest.json", self.release.raw),
            (f"{sha}.receipt.json", json.dumps(self.receipt.summary(), indent=2, sort_keys=True)),
        ):
            path = f"{self.target.state_dir}/{name}"
            self._run(
                f"mkdir -p '{self.target.state_dir}' && umask 077 && "
                f"cat > '{path}.tmp' && mv '{path}.tmp' '{path}'",
                stdin=payload,
            )
        record = {
            "backend_digest": self.release.backend_digest,
            "web_digest": self.release.web_digest,
            "image_git_sha": info.get("git_sha"),
            "alembic_head": info.get("alembic_head"),
            "migrations": info.get("migrations"),
            "commands_verified": [" ".join(a) for a in REQUIRED_COMMANDS],
            "provenance": self.receipt.summary(),
        }
        state.mark_phase(doc, "verify-release", **record)
        self._save(doc)
        return record

    def prepare_keys(self, *, keys_dir: str) -> None:
        """Generate the three production key files ON THE HOST via the release
        image running as root (bind-mounting the parent directory). Material
        never leaves the host; only fingerprints come back."""
        self._require_mutation_authority()
        self.check_identity()
        doc = self._state()
        state.require_phases(doc, "verify-release")
        parent = str(Path(keys_dir).parent)
        # N -> N+1 keeps the installed keys: `ctxkeys prepare` never overwrites, so
        # an existing COMPLETE set is verified + fingerprinted instead of generated.
        # A partial set is never completed silently.
        existing = [
            cls
            for cls in KEY_CLASSES
            if self.remote.run(
                f"docker run --rm --user 0:0 --network none --entrypoint stat "
                f"-v '{keys_dir}:/keys:ro' {self.release.backend_image} "
                f"-c '{keyfiles.STAT_FORMAT}' '/keys/{cls}.key'"
            ).ok
        ]
        if existing and len(existing) != len(KEY_CLASSES):
            raise GateError(
                f"partial key set in {keys_dir}: {existing} exist, "
                f"{sorted(set(KEY_CLASSES) - set(existing))} do not — STOP "
                "(never completed silently)"
            )
        if existing:
            host_fps = self.verify_key_files(keys_dir)
            state.mark_phase(
                doc,
                "prepare-keys",
                keys_dir=keys_dir,
                fingerprints={c: fp for c, (_kid, fp) in host_fps.items()},
                reused_existing=True,
            )
            self._save(doc)
            self.log(
                "prepare-keys: existing key files verified and fingerprinted (not regenerated)"
            )
            return
        fps: dict[str, str] = {}
        for cls in KEY_CLASSES:
            out = self._image_python(
                self.release.backend_image,
                f"-m nlw.ctxkeys prepare --dir '/host{keys_dir}' --class {cls} "
                f"--owner {keyfiles.CONTAINER_UID}:{keyfiles.CONTAINER_UID}",
                extra=f"--user 0:0 -v '{parent}:/host{parent}'",
            )
            parts = out.split()
            if len(parts) != 3 or parts[0] != "prepared" or parts[1] != cls:
                raise RolloutStop(f"unexpected prepare output for {cls}")
            fps[cls] = parts[2]
        self.verify_key_files(keys_dir)
        state.mark_phase(
            doc, "prepare-keys", keys_dir=keys_dir, fingerprints=fps, reused_existing=False
        )
        self._save(doc)

    def _stat_in_container(self, keys_dir: str, name: str) -> keyfiles.StatLine:
        """stat through a throwaway container: the CONTAINER's view of owner/mode
        is what the runtime will see (and what a bind mount actually presents)."""
        line = self._run(
            f"docker run --rm --user 0:0 --network none --entrypoint stat "
            f"-v '{keys_dir}:/keys:ro' {self.release.backend_image} "
            f"-c '{keyfiles.STAT_FORMAT}' '/keys/{name}'"
        )
        return keyfiles.parse_stat_line(line)

    def verify_key_files(self, keys_dir: str) -> dict[str, tuple[str, str]]:
        keyfiles.check_key_dir(self._stat_in_container(keys_dir, "."))
        for cls in KEY_CLASSES:
            keyfiles.check_key_file(self._stat_in_container(keys_dir, f"{cls}.key"))
        ids = " ".join(f"--key-id-{c} {self.release.key_ids[c]}" for c in KEY_CLASSES)
        out = self._image_python(
            self.release.backend_image,
            f"-m nlw.ctxkeys fingerprint --dir /keys {ids} --owner {keyfiles.CONTAINER_UID}",
            extra=f"--user 0:0 -v '{keys_dir}:/keys:ro'",
        )
        return keyfiles.parse_fingerprint_lines(out)

    def verify_escrow(self, *, keys_dir: str) -> None:
        self._require_mutation_authority()
        gates.check_escrow_confirmation(self.op.escrow_confirmation)
        if self.op.attestation_path is None:
            raise GateError("an escrow attestation file is required (--attestation)")
        doc = self._state()
        state.require_phases(doc, "prepare-keys")
        att = load_attestation(self.op.attestation_path)
        host_fps = self.verify_key_files(keys_dir)
        try:
            verify_attestation(att, self.release, host_fps, now=self.now())
        except AttestationError as exc:
            raise GateError(f"escrow attestation rejected: {exc}") from exc
        state.mark_phase(doc, "verify-escrow", attestation=att.summary())
        self._save(doc)

    # ---- host staging (no database, no active config, no running container) ---
    def stage_release(self, *, keys_dir: str) -> None:
        """Clone + check out the release SHA into <ops_root>/releases/<sha>, write
        ITS .env.prod (a copy of the active one with the pins rewritten), build
        the backup image from the pinned digest. The active checkout, its
        .env.prod, Caddy and every running container are untouched."""
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "verify-release", "verify-escrow")
        self.check_identity()
        self.refuse_foreign_activation()
        active = self.target.remote_app
        active_env_hash_before = self._run(f"sha256sum '{active}/.env.prod' | cut -d' ' -f1")
        # Objects come from the active checkout (local, fast); the release SHA itself
        # is fetched from the REVIEWED git remote (target.env) — or, when none is
        # configured, from the active checkout's own origin (the legacy clone chain).
        remote = self.target.git_remote or f"$(git -C '{active}' remote get-url origin)"
        self._run(
            f"set -e; mkdir -p '{self.target.ops_root}/releases'; "
            f"if [ ! -d '{self.staged}/.git' ]; then git clone -q '{active}' '{self.staged}'; fi; "
            f"git -C '{self.staged}' fetch -q '{remote}' "
            "'+refs/heads/*:refs/remotes/origin/*' 2>/dev/null || true",
            timeout=600,
        )
        res = self.remote.run(
            f"git -C '{self.staged}' checkout -q --detach {self.release.release_sha}", timeout=300
        )
        if not res.ok:
            raise GateError(
                f"release {self.release.release_sha[:12]} is not available from "
                f"{self.target.git_remote or 'the active checkout origin'}: "
                "merge/push it first — STOP"
            )
        self.verify_checkout(self.staged)
        self._write_staged_env(keys_dir=keys_dir)
        worker_secrets = self._stage_worker_secrets()
        self._run(f"{self.dc_staged} config >/dev/null")
        self._run(f"{self.target.dc_backup_in(self.staged)} build -q backup", timeout=900)
        active_env_hash_after = self._run(f"sha256sum '{active}/.env.prod' | cut -d' ' -f1")
        if active_env_hash_before != active_env_hash_after:
            raise RolloutStop("active .env.prod changed during staging — aborting")
        gates.check_release_pins(self.read_pins(self.staged), self.release, post_pin=True)
        state.mark_phase(
            doc,
            "stage-release",
            staged_dir=self.staged,
            active_checkout=self.read_active_sha(),
            worker_env_file=worker_secrets,
        )
        self._save(doc)

    # The worker's connector secrets live in a git-IGNORED file next to the active
    # compose files; `git clone` never carries it and the worker service declares it
    # `required: false`, so a recreated worker would silently start WITHOUT its
    # connector secrets. Carry it into the staged release (0600, temp-file + mv).
    WORKER_SECRETS = "docker/worker.secrets.env"

    def _stage_worker_secrets(self) -> str:
        src = f"{self.target.remote_app}/{self.WORKER_SECRETS}"
        dst = f"{self.staged}/{self.WORKER_SECRETS}"
        out = self._run(
            f"if [ -f '{src}' ]; then set -e; umask 077; cp '{src}' '{dst}.tmp'; "
            f"chmod 600 '{dst}.tmp'; mv '{dst}.tmp' '{dst}'; echo staged; "
            f"else echo absent; fi"
        )
        verdict = out.strip()
        if verdict not in ("staged", "absent"):
            raise RolloutStop("unexpected result while staging the worker secrets file")
        self.log(f"worker connector secrets file: {verdict}")
        return verdict

    def _write_staged_env(self, *, keys_dir: str) -> None:
        """Staged .env.prod = active .env.prod with ONLY the pins rewritten
        (digests/ids/paths); portable temp-file rewrite, never `sed -i`."""
        lines = {
            "NLW_IMAGE": self.release.backend_image,
            "NLW_WEB_IMAGE": self.release.web_image,
            "NLW_CTX_KEYS_DIR": keys_dir,
            **{f"NLW_CTX_{c.upper()}_KEY_ID": self.release.key_ids[c] for c in KEY_CLASSES},
        }
        src, dst = f"{self.target.remote_app}/.env.prod", f"{self.staged}/.env.prod"
        pattern = "|".join(lines)
        script = f"set -e; umask 077; grep -Ev '^({pattern})=' '{src}' > '{dst}.tmp' || true; "
        for k, v in lines.items():
            script += f"printf '%s=%s\\n' '{k}' '{v}' >> '{dst}.tmp'; "
        script += f"chmod 600 '{dst}.tmp'; mv '{dst}.tmp' '{dst}'"
        self._run(script)

    def backup(self) -> None:
        """Run the REAL off-host backup of the pre-upgrade database from the staged
        release (new backup image, owner credential, read-only dump). Binds the
        manifest to this instance/environment/source release."""
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "stage-release")
        self.check_identity()
        self.refuse_foreign_activation()
        self.verify_checkout(self.staged)
        self.check_backup_env_file()
        gates.check_current_revision(self.read_revision(), self.release.expected_current_revision)
        env = (
            f"-e NLW_BACKUP_SOURCE_INSTANCE_ID={self.release.instance_id} "
            f"-e NLW_BACKUP_ENVIRONMENT={self.release.environment} "
            f"-e NLW_BACKUP_SOURCE_RELEASE={self.read_active_sha()}"
        )
        self._run(
            f"{self.target.dc_backup_in(self.staged)} run --rm --no-deps -T {env} backup",
            timeout=1800,
        )
        state.mark_phase(doc, "backup", source_revision=self.release.expected_current_revision)
        self._save(doc)

    def verify_backup(self) -> None:
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "stage-release")
        self.refuse_foreign_activation()
        self.verify_checkout(self.staged)
        res = self.remote.run(
            f"{self.target.dc_backup_in(self.staged)} run --rm --no-deps -T backup evidence",
            timeout=600,
        )
        if not res.ok:
            # stderr is deliberately not echoed (it may name the repository).
            raise GateError(
                "pre-deployment backup gate failed: no backup evidence could be produced "
                "(repository unreachable or uninitialized, or no backup has been taken yet)"
            )
        raw = res.text
        try:
            ev_doc = json.loads(raw[raw.index("{") :])
        except (json.JSONDecodeError, ValueError) as exc:
            raise GateError("backup evidence is not valid JSON") from exc
        manifest = ev_doc.get("manifest") if isinstance(ev_doc.get("manifest"), dict) else {}
        ev = BackupEvidence(
            repository=str(ev_doc.get("repository", "")),
            metrics_text=str(ev_doc.get("metrics_text", "")),
            snapshot=parse_snapshots_json(ev_doc.get("snapshots")),
            artifact_names=tuple(str(n) for n in ev_doc.get("artifact_names", [])),
            manifest=manifest,
        )
        fixture_ok = self.op.allow_fixture_repository and self.remote.is_local
        binding = SourceBinding(
            instance_id=self.release.instance_id,
            environment=self.release.environment,
            db_system_identifier=self.read_db_system_identifier(),
            source_revision=self.release.expected_current_revision,
            source_release=self.read_active_sha(),
        )
        try:
            record = evaluate_backup_evidence(
                ev,
                binding=binding,
                max_age=self.op.backup_max_age,
                now=self.now(),
                allow_fixture_repository=fixture_ok,
            )
        except BackupEvidenceError as exc:
            raise GateError(f"pre-deployment backup gate failed: {exc}") from exc
        if fixture_ok:
            self.log(
                "WARNING: backup repository is a LOCAL FIXTURE — rehearsal only, NOT DR evidence"
            )
            record["fixture_repository"] = True
        state.mark_phase(doc, "verify-backup", **record)
        self._save(doc)

    # ---- mutation (only after the verified backup) ----------------------------
    def drain(self) -> None:
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "verify-backup")
        self.check_identity()
        self.verify_checkout(self.staged)
        gates.check_release_pins(self.read_pins(self.staged), self.release, post_pin=True)
        gates.check_current_revision(self.read_revision(), self.release.expected_current_revision)
        # The edge must run the RELEASE config (maintenance matcher + caddy_maint
        # volume) before the flag means anything: recreate caddy alone, no deps.
        self._run(f"{self.dc_staged} up -d --no-deps --force-recreate caddy", timeout=300)
        self._run(f"{self.dc_staged} exec -T caddy touch {MAINTENANCE_FLAG}")
        self._run(f"{self.dc_staged} stop scheduler")
        deadline = self.now() + timedelta(seconds=DRAIN_WAIT_S)
        snap = self.read_drain()
        for _ in range(DRAIN_WAIT_S // 5):  # bounded by attempts AND wall clock
            if not (snap.non_terminal_runs or snap.queue_depth) or self.now() >= deadline:
                break
            self._run("sleep 5")
            snap = self.read_drain()
        gates.check_drained(snap)
        self._run(f"{self.dc_staged} stop worker api")
        sessions = self.read_runtime_sessions()
        gates.check_no_runtime_sessions(sessions)
        state.mark_phase(doc, "drain", **snap.__dict__, runtime_sessions=sessions)
        self._save(doc)

    def prepare_roles(self) -> None:
        """First database mutation of the rollout — only after drain (which itself
        requires the verified backup)."""
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "verify-backup", "drain")
        self.check_identity()
        self.verify_checkout(self.staged)
        gates.check_no_runtime_sessions(self.read_runtime_sessions())
        gates.check_current_revision(self.read_revision(), self.release.expected_current_revision)
        out = self._migrate_run("", "python -m nlw.ops.roles ensure")
        self.log(out)
        roles = self.read_roles()
        gates.check_roles(roles, require_provisioned=True)
        state.mark_phase(doc, "prepare-roles", roles=roles)
        self._save(doc)

    def migrate(self) -> None:
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "verify-backup", "drain", "prepare-roles")
        self.check_identity()
        self.verify_checkout(self.staged)
        gates.check_no_runtime_sessions(self.read_runtime_sessions())
        gates.check_current_revision(self.read_revision(), self.release.expected_current_revision)
        gates.check_roles(self.read_roles(), require_provisioned=True)
        gates.check_release_pins(self.read_pins(self.staged), self.release, post_pin=True)
        self._migrate_run("", "", timeout=900)  # the service's own command: alembic upgrade head
        rev = self.read_revision()
        gates.check_current_revision(rev, self.release.target_revision)
        self.verify_policy_cutover()
        state.mark_phase(doc, "migrate", revision=rev)
        self._save(doc)

    def verify_policy_cutover(self) -> None:
        row = self._psql(
            "SELECT count(*), count(*) FILTER (WHERE qual LIKE '%app.user_id%' OR "
            "qual LIKE '%app.tenant_id%' OR with_check LIKE '%app.user_id%' OR "
            "with_check LIKE '%app.tenant_id%') FROM pg_policies"
        )
        total, legacy = (int(x) for x in row.split("|"))
        gates.check_policy_cutover(total, legacy, expected_policies=EXPECTED_SIGNED_POLICIES)
        owner = self._psql("SELECT tableowner FROM pg_tables WHERE tablename='ctx_keys'")
        if owner != "nlw_ctx_verifier":
            raise GateError(f"ctx_keys owner is {owner!r}, want nlw_ctx_verifier")
        for r in gates.RUNTIME_ROLES:
            if self._psql(f"SELECT has_table_privilege('{r}','ctx_keys','SELECT')") != "f":
                raise GateError(f"{r} can read ctx_keys")
        if self._psql("SELECT has_table_privilege('public','ctx_keys','SELECT')") != "f":
            raise GateError("PUBLIC can read ctx_keys")

    def install_context_keys(self, *, keys_dir: str) -> None:
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "migrate")
        self.check_identity()
        gates.check_no_runtime_sessions(self.read_runtime_sessions())
        gates.check_current_revision(self.read_revision(), self.release.target_revision)

        # The one-shot runs as the image's uid 10001 and the key directory is root
        # 0700 (never loosened): mounting the DIRECTORY makes every key unreadable
        # ("context key file unreadable" on the pilot host). Each one-shot mounts
        # ONLY its own key file — exactly what the runtime services do.
        def mount(cls: str) -> str:
            return (
                f"-v '{keys_dir}/{cls}.key:/run/nlw/keys/{cls}.key:ro' -e NLW_CTX_OPERATOR=rollout"
            )

        for cls in KEY_CLASSES:
            kid = self.release.key_ids[cls]
            out = self._migrate_run(
                mount(cls),
                f"python -m nlw.ctxkeys install --class {cls} --key-id {kid} "
                f"--secret-file /run/nlw/keys/{cls}.key",
            )
            if not [ln for ln in out.splitlines() if ln.startswith(("installed:", "unchanged:"))]:
                raise RolloutStop(f"unexpected installer output for {cls}")
        for cls in KEY_CLASSES:
            kid = self.release.key_ids[cls]
            out = self._migrate_run(
                mount(cls),
                f"python -m nlw.ctxkeys check --class {cls} --key-id {kid} "
                f"--secret-file /run/nlw/keys/{cls}.key",
            )
            if not any(ln.startswith("ok:") for ln in out.splitlines()):
                raise GateError(f"ctxkeys check failed for {cls}")
        active = int(self._psql("SELECT count(*) FROM ctx_keys WHERE status='active'"))
        if active < len(KEY_CLASSES):
            raise GateError(f"only {active} active keys after install")
        leaked = self._psql(
            "SELECT count(*) FROM ctx_key_events "
            "WHERE actor ~ '[0-9a-f]{64}' OR key_id ~ '[0-9a-f]{64}'"
        )
        if leaked != "0":
            raise GateError("key audit contains key-like material")
        state.mark_phase(doc, "install-context-keys", key_ids=self.release.key_ids)
        self._save(doc)

    def recreate_runtime(self, *, keys_dir: str) -> None:
        """ACTIVATION: point <ops_root>/current at the staged release and recreate
        the runtimes (and monitoring) from it. Only after keys are installed."""
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "install-context-keys")
        self.check_identity()
        self.verify_checkout(self.staged)
        gates.check_current_revision(self.read_revision(), self.release.target_revision)
        gates.check_release_pins(self.read_pins(self.staged), self.release, post_pin=True)
        self._run(f"{self.dc_staged} config >/dev/null")
        # Operator Alertmanager authority is proven BEFORE anything is recreated: the
        # host files, the override and the rendered Compose config (which carries the
        # override on every invocation from a release directory).
        am = self.check_alertmanager_authority()
        self.check_rendered_alertmanager_mounts(am)
        # <ops_root>/current must be absent (first activation from the legacy
        # layout) or an existing SYMLINK (`ln -sfn` replaces it). A real directory
        # would silently receive a link INSIDE it and activation would be a lie.
        cur = self.target.current_link
        shape = self._run(
            f"if [ -e '{cur}' ] && [ ! -L '{cur}' ]; then echo DIRECTORY; "
            f"elif [ -L '{cur}' ]; then echo SYMLINK; else echo ABSENT; fi"
        ).strip()
        if shape == "DIRECTORY":
            raise GateError(
                f"{cur} exists and is not a symlink; refusing to activate over a directory"
            )
        self._run(f"ln -sfn '{self.staged}' '{cur}'")
        pointed = self._run(f"readlink '{cur}'").strip()
        if pointed != self.staged:
            raise GateError(f"{cur} points at {pointed!r}, not the staged release")
        self._run(
            f"{self.dc_staged} up -d --force-recreate --no-deps api worker scheduler web",
            timeout=600,
        )
        services = self._run(f"{self.dc_staged} config --services").split()
        monitoring = [s for s in ("prometheus", "alertmanager") if s in services]
        if monitoring:
            self._run(
                f"{self.dc_staged} up -d --force-recreate --no-deps {' '.join(monitoring)}",
                timeout=300,
            )
        images = self.read_running_images()
        gates.check_running_images(images, self.release)
        self.verify_mount_isolation(keys_dir)
        self.verify_alertmanager_runtime(am)
        state.mark_phase(
            doc,
            "recreate-runtime",
            images=images,
            current=self.staged,
            alertmanager={**am.evidence(), "config_source": "running-alertmanager"},
        )
        self._save(doc)

    def verify_mount_isolation(self, keys_dir: str) -> None:
        out = self._run(
            f"for s in api worker scheduler web postgres redis caddy prometheus alertmanager; do "
            f'c=$({self.dc_staged} ps -q $s 2>/dev/null | head -1); [ -z "$c" ] && continue; '
            'echo "$s $(docker inspect --format '
            "'{{range .Mounts}}{{.Source}}:{{.Destination}}:{{.RW}} {{end}}"
            '|{{range .Config.Env}}{{.}} {{end}}\' "$c")"; done'
        )
        for line in out.splitlines():
            svc, _, rest = line.partition(" ")
            mounts, _, env = rest.partition("|")
            key_mounts = [m for m in mounts.split() if "/run/nlw/keys/" in m]
            if svc in RUNTIME_SERVICES:
                want = f"{keys_dir}/{svc}.key:/run/nlw/keys/{svc}.key:false"
                if key_mounts != [want]:
                    raise GateError(f"{svc} key mounts are {key_mounts}, want [{want}]")
            elif key_mounts:
                raise GateError(f"{svc} must not mount a key file: {key_mounts}")
            if (
                any("backup_textfile" in m or "/textfile" in m for m in mounts.split())
                and svc != "backup"
            ):
                raise GateError(f"{svc} must not mount the backup evidence volume")
            contract = self.target.operator_alerting
            am_mounts = [
                m
                for m in mounts.split()
                if "/etc/alertmanager/" in m
                or (contract is not None and m.startswith(contract.secrets_dir + ":"))
            ]
            if svc != "alertmanager" and am_mounts:
                raise GateError(
                    f"{svc} must not mount Alertmanager configuration/secrets: {am_mounts}"
                )
            allowed = ("NLW_CTX_KEY_ID", "NLW_CTX_KEY_FILE", "NLW_CTX_TTL_S")
            for item in env.split():
                name = item.split("=", 1)[0]
                if name.startswith("NLW_CTX_") and name not in allowed:
                    raise GateError(f"{svc} environment carries an unexpected NLW_CTX_* variable")
            if svc in RUNTIME_SERVICES:
                # Inside the container: its own key material must not appear in its
                # environment (only the file path/id may). Prints a verdict, never the key.
                verdict = self._run(
                    f"{self.dc_staged} exec -T {svc} sh -c "
                    f'\'k=$(cat /run/nlw/keys/{svc}.key | tr -d "\\n"); '
                    'if env | grep -qF "$k"; then echo LEAK; else echo clean; fi\''
                )
                if verdict.strip() != "clean":
                    raise GateError(f"{svc} environment contains its key material")
        leftovers = self._run(
            f"docker ps -a --filter name={self.target.compose_project}-migrate "
            "--format '{{.Names}}'"
        )
        if leftovers:
            raise GateError(f"installer/migration container(s) still present: {leftovers}")

    def validate(self, *, keys_dir: str) -> alerting.AlertingStatus:
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "recreate-runtime")
        body = ""
        for _ in range(45):
            res = self.remote.run("curl -sS -m 5 http://127.0.0.1:8000/health/ready")
            body = res.text
            if res.ok and '"signed_context":"ok"' in body.replace(" ", ""):
                break
            self._run("sleep 2")
        gates.check_readiness_body(body)
        self.verify_policy_cutover()
        self.verify_mount_isolation(keys_dir)
        self.verify_unsigned_forgery_denied()
        # Worker/scheduler healthchecks include the signed-context self-check; they
        # start in state "starting" — wait (bounded) for a definitive verdict.
        for svc in ("worker", "scheduler"):
            health = "starting"
            for _ in range(45):
                health = self._run(
                    "docker inspect --format '{{.State.Health.Status}}' "
                    f"$({self.dc_staged} ps -q {svc})"
                )
                if health in ("healthy", "unhealthy"):
                    break
                self._run("sleep 2")
            if health != "healthy":
                raise GateError(f"{svc} is {health!r}, not healthy (signer/readiness check)")
        status = self.alerting_status()
        alerting.check_rules_and_connectivity(status)
        state.mark_phase(doc, "validate", readiness="signed_context ok", alerting=status.evidence())
        self._save(doc)
        return status

    def alerting_status(self) -> alerting.AlertingStatus:
        """Rules loaded / Alertmanager reachable / delivery verified — three
        separate facts, never conflated (M12A-Prep §E). The receiver configuration
        is read from the RUNNING Alertmanager after the operator authority checks
        (host files, override, mounts, mounted bytes, loaded config); the
        committed file in the release checkout is never consulted."""
        rules_raw = self.remote.run(
            f"{self.dc_staged} exec -T prometheus wget -qO- http://127.0.0.1:9090/api/v1/rules"
        )
        try:
            groups = alerting.parse_rule_groups(json.loads(rules_raw.text or "{}"))
        except json.JSONDecodeError:
            groups = ()
        am_raw = self.remote.run(
            f"{self.dc_staged} exec -T prometheus wget -qO- http://127.0.0.1:9090/api/v1/alertmanagers"
        )
        try:
            active = (json.loads(am_raw.text or "{}").get("data") or {}).get(
                "activeAlertmanagers"
            ) or []
        except json.JSONDecodeError:
            active = []
        healthy = self.remote.run(
            f"{self.dc_staged} exec -T alertmanager wget -qO- http://127.0.0.1:9093/-/healthy"
        )
        reachable = bool(active) and healthy.ok
        facts = self.check_alertmanager_authority()
        self.verify_alertmanager_runtime(facts)
        record, problem = self._read_delivery_record()
        return alerting.build_status(
            rule_groups=groups,
            alertmanager_reachable=reachable,
            default_receiver=facts.receiver,
            receivers=facts.receivers,
            present_files=set(facts.credential_paths),
            delivery_record=record,
            now=self.now(),
            config_source="running-alertmanager",
            record_problem=problem,
        )

    def verify_unsigned_forgery_denied(self) -> None:
        """As the REAL nlw_app login role (local-socket auth inside the postgres
        container), forge the legacy unsigned settings for an existing member and
        prove RLS returns nothing. A positive count means the cutover is not live."""
        sql = (
            "BEGIN; SELECT set_config('app.user_id', COALESCE((SELECT user_id::text "
            "FROM memberships LIMIT 1), gen_random_uuid()::text), true), "
            "set_config('app.tenant_id', COALESCE((SELECT workspace_id::text "
            "FROM memberships LIMIT 1), gen_random_uuid()::text), true); "
            "SELECT count(*) FROM memberships; ROLLBACK;"
        )
        out = self._run(
            f"{self.dc} exec -T postgres psql -U nlw_app -d nlw -tA -c {shlex.quote(sql)}"
        )
        counts = [line for line in out.splitlines() if line.strip().isdigit()]
        if not counts or counts[-1].strip() != "0":
            raise GateError(f"unsigned forged context could see tenant rows: {counts or out}")

    def reopen(self) -> list[str]:
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "validate")
        gates.check_readiness_body(self._run("curl -sS -m 5 http://127.0.0.1:8000/health/ready"))
        status = self.alerting_status()
        alerting.check_rules_and_connectivity(status)
        alerting.check_delivery_record_usable(status)
        open_gates = alerting.launch_gates_for(status, environment=self.release.environment)
        self._run(f"{self.dc_staged} exec -T caddy rm -f {MAINTENANCE_FLAG}")
        state.mark_phase(doc, "reopen", launch_gates_open=open_gates, alerting=status.evidence())
        self._save(doc)
        for g in open_gates:
            self.log(f"LAUNCH GATE OPEN: {g} — technical deployment only, NOT an M12 GO")
        return open_gates

    def go_check(self) -> None:
        """Read-only M12 GO evaluation of the recorded evidence + live alerting."""
        doc = self._state()
        state.require_phases(doc, "reopen")
        status = self.alerting_status()
        alerting.check_go(status, environment=self.release.environment)
