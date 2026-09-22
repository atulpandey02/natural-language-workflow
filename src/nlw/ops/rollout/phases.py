"""The rollout state machine (M12A-Prep §C/§H): explicit phases, every
mutation re-gated, fail closed with runtimes stopped after migration.

Phase order for the ``M11 runtime + schema 0010 -> P3B runtime + schema 0016``
boundary:

    preflight            read-only (the default)
    prepare-keys         generate the three key files on the host (0700/0400)
    verify-escrow        operator attestation fingerprints == host key files
    pin-release          check out the release SHA in the app dir; pin digests + key ids
    prepare-roles        create nlw_membership_admin / nlw_ctx_verifier if absent (release
                         image via the migrate service — the M11 compose has none)
    verify-backup        verified, off-host, pre-upgrade-revision snapshot (new backup image)
    drain                maintenance mode; stop scheduler; stop worker+api; no sessions
    migrate              pin release + key ids in .env.prod; 0010 -> 0016
    install-context-keys install + check the three registry keys
    recreate-runtime     pull digests; force-recreate api/worker/scheduler; mounts
    validate             signed_context readiness, policy cutover, adversarial smoke
    reopen               leave maintenance mode

Every command runs through the ``Remote`` (SSH to the host or local rehearsal).
Secrets never appear on argv: the installer reads files mounted into a
throwaway container; ``.env.prod`` is edited in place on the host with
``sed``/heredocs that carry only image digests and key ids.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nlw.ops.rollout import gates, keyfiles, state
from nlw.ops.rollout.attestation import (
    AttestationError,
    load_attestation,
    verify_attestation,
)
from nlw.ops.rollout.backup_evidence import (
    BackupEvidence,
    BackupEvidenceError,
    evaluate_backup_evidence,
    parse_snapshots_json,
)
from nlw.ops.rollout.gates import GateError
from nlw.ops.rollout.release import KEY_CLASSES, ReleaseSpec
from nlw.ops.rollout.remote import Remote, TargetConfig

EXPECTED_SIGNED_POLICIES = 51
# Caddy serves 503 for every request while this file exists on its `caddy_maint`
# volume (docker/caddy/Caddyfile `@maintenance`). Toggled with `exec`, no reload.
MAINTENANCE_FLAG = "/srv/maint/MAINTENANCE"
RUNTIME_SERVICES = ("api", "worker", "scheduler")
DRAIN_WAIT_S = 120
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
    ) -> None:
        self.release = release
        self.target = target
        self.remote = remote
        self.op = operator
        self.log = log
        self.now = now
        self.dc = target.dc

    # ---- helpers -----------------------------------------------------------
    def _run(self, cmd: str, *, stdin: str | None = None, timeout: int = 300) -> str:
        res = self.remote.run(cmd, stdin=stdin, timeout=timeout)
        if not res.ok:
            raise RolloutStop(f"command failed (exit {res.returncode}): {cmd.split(' ', 3)[:3]}")
        return res.text

    def _psql(self, sql: str) -> str:
        return self._run(f"{self.dc} exec -T postgres psql -U nlw -d nlw -tAc {shlex.quote(sql)}")

    def _state(self) -> dict[str, Any]:
        return state.load_state(self.remote, self.target.remote_app, self.release.release_sha)

    def _save(self, doc: dict[str, Any]) -> None:
        state.save_state(self.remote, self.target.remote_app, self.release.release_sha, doc)

    def _migrate_run(self, extra: str, cmd: str, *, timeout: int = 600) -> str:
        """Run a one-shot command in the migrate profile service (owner credential),
        container removed afterwards. ``extra`` adds docker run flags (mounts)."""
        return self._run(
            f"{self.dc} --profile migration run --rm -T {extra} migrate {cmd}", timeout=timeout
        )

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
        gates.check_public_ip_matches_hostname(imds.get("public-ipv4", ""), self.release)
        return imds

    def read_pins(self) -> dict[str, str]:
        text = self._run(
            f"grep -E '^(NLW_IMAGE|NLW_WEB_IMAGE|PUBLIC_HOSTNAME|NLW_CTX_KEYS_DIR|"
            f"NLW_CTX_(API|WORKER|SCHEDULER)_KEY_ID)=' '{self.target.remote_app}/.env.prod'"
        )
        return gates.parse_env_pins(text)

    def read_revision(self) -> str:
        return self._psql("SELECT version_num FROM alembic_version")

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
        out = self._run(
            f"{self.dc} ps --format '{{{{.Service}}}} {{{{.Image}}}}' 2>/dev/null; "
            f"for s in api worker scheduler web; do c=$({self.dc} ps -q $s 2>/dev/null | head -1); "
            '[ -n "$c" ] && echo "$s $(docker inspect '
            '--format \'{{index .RepoDigests 0}}\' "$c")"; done'
        )
        images: dict[str, str] = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and "@sha256:" in parts[1]:
                images[parts[0]] = parts[1]
        return images

    def _require_mutation_authority(self) -> None:
        gates.check_authorization(self.op.authorization)

    # ---- phases -------------------------------------------------------------
    def preflight(self) -> dict[str, Any]:
        """READ-ONLY. Safe to run at any time."""
        self.log(f"target: {self.remote.describe()}")
        imds = self.check_identity()
        self.log(f"instance ok: {imds.get('instance-id')} {imds.get('placement/region')}")
        pins = self.read_pins()
        gates.check_release_pins(pins, self.release, post_pin=False)
        rev = self.read_revision()
        roles = self.read_roles()
        gates.check_roles(roles, require_provisioned=False)
        drain = self.read_drain()
        doc = self._state()
        pinned = pins.get("NLW_IMAGE") == self.release.backend_image
        if not pinned:
            gates.check_current_revision(rev, self.release.expected_current_revision)
        report = {
            "instance_id": imds.get("instance-id"),
            "region": imds.get("placement/region"),
            "current_revision": rev,
            "roles": roles,
            "pinned_to_release": pinned,
            "drain": drain.__dict__,
            "phases_done": sorted(doc["phases"]),
        }
        self.log("preflight: " + json.dumps(report, sort_keys=True))
        return report

    def prepare_roles(self) -> None:
        self._require_mutation_authority()
        self.check_identity()
        doc = self._state()
        state.require_phases(doc, "pin-release")  # the migrate service exists only in the release
        self.verify_checkout()
        out = self._migrate_run("", "python -m nlw.ops.roles ensure")
        self.log(out)
        roles = self.read_roles()
        gates.check_roles(roles, require_provisioned=True)
        state.mark_phase(doc, "prepare-roles", roles=roles)
        self._save(doc)

    def prepare_keys(self, *, keys_dir: str) -> None:
        """Generate the three production key files ON THE HOST via the release
        image running as root (bind-mounting the parent directory). Material
        never leaves the host; only fingerprints come back."""
        self._require_mutation_authority()
        self.check_identity()
        doc = self._state()
        parent = str(Path(keys_dir).parent)
        image = self.release.backend_image
        fps: dict[str, str] = {}
        for cls in KEY_CLASSES:
            out = self._run(
                f"docker run --rm --user 0:0 --network none -v '{parent}:/host{parent}' {image} "
                f"python -m nlw.ctxkeys prepare --dir '/host{keys_dir}' --class {cls} "
                f"--owner {keyfiles.CONTAINER_UID}:{keyfiles.CONTAINER_UID}"
            )
            parts = out.split()
            if len(parts) != 3 or parts[0] != "prepared" or parts[1] != cls:
                raise RolloutStop(f"unexpected prepare output for {cls}")
            fps[cls] = parts[2]
        self.verify_key_files(keys_dir)
        state.mark_phase(doc, "prepare-keys", keys_dir=keys_dir, fingerprints=fps)
        self._save(doc)

    def _stat_in_container(self, keys_dir: str, name: str) -> keyfiles.StatLine:
        """stat through a throwaway container: the CONTAINER's view of owner/mode
        is what the runtime will see (and what a bind mount actually presents)."""
        image = self.release.backend_image
        line = self._run(
            f"docker run --rm --user 0:0 --network none --entrypoint stat "
            f"-v '{keys_dir}:/keys:ro' {image} -c '{keyfiles.STAT_FORMAT}' '/keys/{name}'"
        )
        return keyfiles.parse_stat_line(line)

    def verify_key_files(self, keys_dir: str) -> dict[str, tuple[str, str]]:
        keyfiles.check_key_dir(self._stat_in_container(keys_dir, "."))
        for cls in KEY_CLASSES:
            keyfiles.check_key_file(self._stat_in_container(keys_dir, f"{cls}.key"))
        ids = " ".join(f"--key-id-{c} {self.release.key_ids[c]}" for c in KEY_CLASSES)
        image = self.release.backend_image
        out = self._run(
            f"docker run --rm --user 0:0 --network none -v '{keys_dir}:/keys:ro' {image} "
            f"python -m nlw.ctxkeys fingerprint --dir /keys {ids} --owner {keyfiles.CONTAINER_UID}"
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

    def verify_backup(self) -> None:
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "verify-escrow", "pin-release", "prepare-roles")
        self.verify_checkout()
        raw = self._run(f"{self.target.dc_backup} run --rm -T backup evidence", timeout=600)
        try:
            ev_doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GateError("backup evidence is not valid JSON") from exc
        ev = BackupEvidence(
            repository=str(ev_doc.get("repository", "")),
            metrics_text=str(ev_doc.get("metrics_text", "")),
            snapshot=parse_snapshots_json(ev_doc.get("snapshots")),
            artifact_names=tuple(str(n) for n in ev_doc.get("artifact_names", [])),
        )
        fixture_ok = self.op.allow_fixture_repository and self.remote.describe().startswith("LOCAL")
        try:
            record = evaluate_backup_evidence(
                ev,
                expected_source_revision=self.release.expected_current_revision,
                expected_hostname=None,
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

    def drain(self) -> None:
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "verify-escrow", "pin-release", "verify-backup")
        self.check_identity()
        self.verify_checkout()
        gates.check_release_pins(self.read_pins(), self.release, post_pin=True)
        gates.check_current_revision(self.read_revision(), self.release.expected_current_revision)
        # The edge must run the RELEASE config (maintenance matcher + caddy_maint
        # volume) before the flag means anything: recreate caddy alone, no deps.
        self._run(f"{self.dc} up -d --no-deps --force-recreate caddy", timeout=300)
        # Maintenance mode: Caddy serves 503 while the flag exists (Caddyfile
        # `@maintenance` file matcher on the caddy_maint volume — no reload needed).
        self._run(f"{self.dc} exec -T caddy touch {MAINTENANCE_FLAG}")
        self._run(f"{self.dc} stop scheduler")
        deadline = self.now() + timedelta(seconds=DRAIN_WAIT_S)
        snap = self.read_drain()
        for _ in range(DRAIN_WAIT_S // 5):  # bounded by attempts AND wall clock
            if not (snap.non_terminal_runs or snap.queue_depth) or self.now() >= deadline:
                break
            self._run("sleep 5")
            snap = self.read_drain()
        gates.check_drained(snap)
        self._run(f"{self.dc} stop worker api")
        sessions = self.read_runtime_sessions()
        gates.check_no_runtime_sessions(sessions)
        state.mark_phase(doc, "drain", **snap.__dict__, runtime_sessions=sessions)
        self._save(doc)

    def verify_checkout(self) -> None:
        """The app dir must be a clean checkout of the release SHA."""
        app = self.target.remote_app
        sha = self._run(f"git -C '{app}' rev-parse HEAD")
        if sha != self.release.release_sha:
            raise GateError(f"app dir is at {sha[:12]}, release is {self.release.release_sha[:12]}")
        # The rollout's own state dir is not tracked by the OLD checkout's .gitignore.
        dirty = self._run(f"git -C '{app}' status --porcelain -- . ':(exclude).rollout'")
        if dirty:
            raise GateError("app dir checkout is not clean")

    def pin_release(self, *, keys_dir: str) -> None:
        """PHASE: check out the release SHA in the app dir (reviewed compose files
        travel with the code), write the immutable pins + key ids into .env.prod
        (digests/ids only, backup copy kept) and build the backup image from the
        pinned digest. Running containers are untouched: pins only take effect
        when a service is recreated."""
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "verify-escrow")
        self.check_identity()
        app = self.target.remote_app
        self._run(
            f"set -e; cd '{app}'; git fetch -q origin 2>/dev/null || true; "
            "test -z \"$(git status --porcelain -- . ':(exclude).rollout')\" "
            "|| { echo 'app dir not clean' >&2; exit 3; }; "
            f"git checkout -q --detach {self.release.release_sha}",
            timeout=300,
        )
        self.verify_checkout()
        self._write_env_pins(keys_dir=keys_dir)
        self._run(f"{self.target.dc_backup} build -q backup", timeout=900)
        state.mark_phase(doc, "pin-release", release=self.release.summary())
        self._save(doc)

    def _write_env_pins(self, *, keys_dir: str) -> None:
        """Write the immutable pins + key ids into .env.prod (digests/ids only)."""
        lines = {
            "NLW_IMAGE": self.release.backend_image,
            "NLW_WEB_IMAGE": self.release.web_image,
            "NLW_CTX_KEYS_DIR": keys_dir,
            **{f"NLW_CTX_{c.upper()}_KEY_ID": self.release.key_ids[c] for c in KEY_CLASSES},
        }
        app, tag = self.target.remote_app, self.release.release_sha[:12]
        # Portable (GNU + BSD): rewrite through a temp file instead of `sed -i`.
        # Only digests/ids/paths are written; every other line is preserved.
        script = f'set -e; f=\'{app}/.env.prod\'; umask 077; cp "$f" "$f.bak.{tag}"; '
        pattern = "|".join(lines)
        script += f'grep -Ev \'^({pattern})=\' "$f" > "$f.tmp" || true; '
        for k, v in lines.items():
            script += f"printf '%s=%s\\n' '{k}' '{v}' >> \"$f.tmp\"; "
        script += 'chmod 600 "$f.tmp"; mv "$f.tmp" "$f"'
        self._run(script)
        gates.check_release_pins(self.read_pins(), self.release, post_pin=True)

    def migrate(self, *, keys_dir: str) -> None:
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(
            doc, "prepare-roles", "verify-escrow", "pin-release", "verify-backup", "drain"
        )
        self.check_identity()
        gates.check_no_runtime_sessions(self.read_runtime_sessions())
        gates.check_current_revision(self.read_revision(), self.release.expected_current_revision)
        gates.check_roles(self.read_roles(), require_provisioned=True)
        self.verify_checkout()
        gates.check_release_pins(self.read_pins(), self.release, post_pin=True)
        self._run(f"{self.dc} pull -q migrate api worker scheduler web", timeout=900)
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
        gates.check_no_runtime_sessions(self.read_runtime_sessions())
        gates.check_current_revision(self.read_revision(), self.release.target_revision)
        mount = f"-v '{keys_dir}:/run/nlw/keys:ro' -e NLW_CTX_OPERATOR=rollout"
        for cls in KEY_CLASSES:
            kid = self.release.key_ids[cls]
            out = self._migrate_run(
                mount,
                f"python -m nlw.ctxkeys install --class {cls} --key-id {kid} "
                f"--secret-file /run/nlw/keys/{cls}.key",
            )
            # The installer logs (structlog, stdout) before its result line.
            verdict = [ln for ln in out.splitlines() if ln.startswith(("installed:", "unchanged:"))]
            if not verdict:
                raise RolloutStop(f"unexpected installer output for {cls}")
        for cls in KEY_CLASSES:
            kid = self.release.key_ids[cls]
            out = self._migrate_run(
                mount,
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
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "install-context-keys")
        gates.check_current_revision(self.read_revision(), self.release.target_revision)
        gates.check_release_pins(self.read_pins(), self.release, post_pin=True)
        self._run(f"{self.dc} config >/dev/null")
        self._run(
            f"{self.dc} up -d --force-recreate --no-deps api worker scheduler web", timeout=600
        )
        # Monitoring is part of the release config too (rule mounts, Alertmanager);
        # recreate whatever the active overlay defines.
        services = self._run(f"{self.dc} config --services").split()
        monitoring = [s for s in ("prometheus", "alertmanager") if s in services]
        if monitoring:
            self._run(
                f"{self.dc} up -d --force-recreate --no-deps {' '.join(monitoring)}", timeout=300
            )
        images = self.read_running_images()
        gates.check_running_images(images, self.release)
        self.verify_mount_isolation(keys_dir)
        state.mark_phase(doc, "recreate-runtime", images=images)
        self._save(doc)

    def verify_mount_isolation(self, keys_dir: str) -> None:
        out = self._run(
            f"for s in api worker scheduler web postgres redis caddy prometheus; do "
            f'c=$({self.dc} ps -q $s 2>/dev/null | head -1); [ -z "$c" ] && continue; '
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
            for item in env.split():
                name = item.split("=", 1)[0]
                if name.startswith("NLW_CTX_") and name not in (
                    "NLW_CTX_KEY_ID",
                    "NLW_CTX_KEY_FILE",
                    "NLW_CTX_TTL_S",
                ):
                    raise GateError(f"{svc} environment carries an unexpected NLW_CTX_* variable")
            if svc in RUNTIME_SERVICES:
                # Inside the container: its own key material must not appear in its
                # environment (only the file path/id may). Prints a verdict, never the key.
                verdict = self._run(
                    f"{self.dc} exec -T {svc} sh -c "
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

    def validate(self, *, keys_dir: str) -> None:
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
                    f"$({self.dc} ps -q {svc})"
                )
                if health in ("healthy", "unhealthy"):
                    break
                self._run("sleep 2")
            if health != "healthy":
                raise GateError(f"{svc} is {health!r}, not healthy (signer/readiness check)")
        state.mark_phase(doc, "validate", readiness="signed_context ok")
        self._save(doc)

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

    def reopen(self) -> None:
        self._require_mutation_authority()
        doc = self._state()
        state.require_phases(doc, "validate")
        gates.check_readiness_body(self._run("curl -sS -m 5 http://127.0.0.1:8000/health/ready"))
        self._run(f"{self.dc} exec -T caddy rm -f {MAINTENANCE_FLAG}")
        state.mark_phase(doc, "reopen")
        self._save(doc)
