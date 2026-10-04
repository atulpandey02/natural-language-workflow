"""The rollout state machine drives a SCRIPTED remote (M12A-Prep §C/§D/§H).

No host, no Docker: every command the orchestrator issues is matched against
canned responses and RECORDED, so the tests prove which commands run — and
which never run — under each gate. The headline proof: no database mutation and
no active-config change is possible before the verified backup gate.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import product
from pathlib import Path
from typing import Any

import pytest

from nlw.ops import release_manifest as rm
from nlw.ops.release_provenance import ProvenanceReceipt
from nlw.ops.rollout.gates import AUTHORIZATION_PHRASE, ESCROW_PHRASE, GateError
from nlw.ops.rollout.phases import Operator, Rollout, RolloutStop
from nlw.ops.rollout.remote import CommandResult, LocalRemote, OperatorAlerting, TargetConfig
from nlw.ops.rollout.state import PHASES, PRE_BACKUP_PHASES, StateError

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
SHA = "1eebf2ef19c0286c83bfe8768c908bfd2f40178d"
OLD_SHA = "5151a2cc54cfb63b276bd3b30cf0e683263525ac"
D = "sha256:" + "a" * 64
W = "sha256:" + "b" * 64
REL_DOC: dict[str, Any] = {
    "format_version": 2,
    "kind": "release",
    "deployable": True,
    "generated_by": "ci",
    "created_at": "2026-09-22T10:00:00+00:00",
    "release_sha": SHA,
    "backend_image": f"ghcr.io/o/r@{D}",
    "web_image": f"ghcr.io/o/r/web@{W}",
    "expected_current_revision": "0010_readiness_schema_grant",
    "target_revision": "0016_signed_database_context",
    "environment": "staging",
    "instance_id": "i-0d1e65cdc9401dbb9",
    "region": "us-east-1",
    "compose_project": "app",
    "public_hostname": "32-197-83-193.sslip.io",
    "key_ids": {"api": "stg-api-1", "worker": "stg-worker-1", "scheduler": "stg-sched-1"},
    "ci": {
        "workflow": "Delivery",
        "run_id": "1",
        "run_url": "https://github.com/o/r/actions/runs/1",
    },
}
REL_RAW = json.dumps(REL_DOC, indent=2, sort_keys=True) + "\n"
REL = replace(
    rm.parse_manifest(REL_DOC, raw_bytes=REL_RAW.encode()),
    raw=REL_RAW,
    source_path="release-manifest.json",
)
# Operator Alertmanager authority: host paths OUTSIDE every release checkout.
OVR = "/opt/nlw/docker-compose.operator.yml"
AMCFG = "/opt/nlw/alertmanager/alertmanager.yml"
AMSEC = "/opt/nlw/alertmanager.secrets"
CFG_MOUNT = "/etc/alertmanager/alertmanager.yml"
SEC_MOUNT = "/etc/alertmanager/secrets"
STAT_AM = r"--entrypoint stat -v '/opt/nlw/alertmanager\.secrets:/probe:ro' .* "
FPS_LINES = (
    f"api stg-api-1 {'1' * 64}\nworker stg-worker-1 {'2' * 64}\nscheduler stg-sched-1 {'3' * 64}"
)
OPERATOR = OperatorAlerting(config_path=AMCFG, secrets_dir=AMSEC, override_path=OVR)
TGT = TargetConfig(
    instance_id=REL.instance_id,
    ssh_host="32.197.83.193",
    ssh_user="nlwops",
    ssh_key=Path("/dev/null"),
    remote_app="/opt/nlw/app",
    compose_project="app",
    demo_tools_enabled=False,
    ops_root="/opt/nlw",
    operator_alerting=OPERATOR,
)
TGT_LEGACY_NO_OPERATOR = replace(TGT, operator_alerting=None)
STAGED = "/opt/nlw/releases/" + SHA
IMDS = "instance-id=i-0d1e65cdc9401dbb9\nplacement/region=us-east-1\npublic-ipv4=32.197.83.193\n"
ROLES_M11 = (
    "nlw_app:tff\nnlw_worker:tff\nnlw_scheduler:tff\n"
    "nlw_rls_bypass:fft\nnlw_workspace_bootstrap:fft\n"
)
ROLES_ALL = ROLES_M11 + "nlw_membership_admin:fft\nnlw_ctx_verifier:fff\n"
PINS_ACTIVE = (
    "NLW_IMAGE=ghcr.io/o/r@sha256:"
    + "f" * 64
    + "\nNLW_WEB_IMAGE=ghcr.io/o/r/web@"
    + W
    + "\nPUBLIC_HOSTNAME=32-197-83-193.sslip.io\n"
)
PINS_STAGED = (
    f"NLW_IMAGE={REL.backend_image}\nNLW_WEB_IMAGE={REL.web_image}\n"
    "PUBLIC_HOSTNAME=32-197-83-193.sslip.io\nNLW_CTX_KEYS_DIR=/srv/nlw/ctx-keys\n"
    "NLW_CTX_API_KEY_ID=stg-api-1\nNLW_CTX_WORKER_KEY_ID=stg-worker-1\n"
    "NLW_CTX_SCHEDULER_KEY_ID=stg-sched-1\nDEMO_TOOLS_ENABLED=false\n"
    "PUBLIC_HOSTNAME_FALLBACK=\n"
)
IMAGE_INFO = json.dumps(
    {
        "git_sha": SHA,
        "alembic_head": "0016_signed_database_context",
        "migrations": [f"{n:04d}_x.py" for n in range(1, 17)],
        "modules": {
            m: True
            for m in (
                "nlw.ops.rollout",
                "nlw.ops.roles",
                "nlw.ctxkeys",
                "nlw.backup.__main__",
                "nlw.ops.rollout.smoke",
            )
        },
    }
)
GOOD_EVIDENCE = {
    "repository": "s3:https://s3.eu-west-1.amazonaws.com/nlw-staging/nlw",
    "metrics_text": "nlw_backup_success 1\nnlw_backup_repository_verify_success 1\n"
    "nlw_backup_last_success_timestamp_seconds "
    f"{int((NOW - timedelta(hours=1)).timestamp())}\n",
    "snapshots": [
        {
            "id": "s1",
            "time": (NOW - timedelta(hours=1)).isoformat(),
            "tags": ["nlw-db", "rev-0010_readiness_schema_grant"],
        }
    ],
    "artifact_names": ["nlw.dump", "manifest.json"],
    "manifest": {
        "alembic_revision": "0010_readiness_schema_grant",
        "artifacts": {"nlw.dump": {"bytes": 1, "sha256": "x"}},
        "completed_at": (NOW - timedelta(hours=1)).isoformat(),
        "source": {
            "instance_id": "i-0d1e65cdc9401dbb9",
            "environment": "staging",
            "db_system_identifier": "7311111111111111111",
            "release": OLD_SHA,
        },
    },
}
# Anything that would change the database or the active deployment.
DB_MUTATION = re.compile(
    r"--profile migration run|alembic (up|down)grade|nlw\.ops\.roles ensure|ctxkeys install|"
    r"\b(CREATE|ALTER|GRANT|DROP|INSERT|UPDATE|DELETE)\b"
)
ACTIVE_MUTATION = re.compile(
    r"\bup -d\b|\bstop\b|touch /srv/maint|rm -f /srv/maint|ln -sfn|"
    r"> '/opt/nlw/app/\.env\.prod|/opt/nlw/app/\.env\.prod\.tmp"
)


# A scripted response: text, an exit code (scripted failure), or a function of the
# fake's own recorded history (e.g. the maintenance flag) and the command.
Response = str | int | Callable[["FakeRemote", str], str]
Table = list[tuple[str, Response]]


class FakeRemote:
    """Pattern -> response table; records every command. Unmatched commands fail
    loudly so a phase cannot silently do something the test did not script."""

    is_local = False

    def __init__(self, table: Table, state: dict[str, Any] | None = None) -> None:
        self.table = table
        self.commands: list[str] = []
        self.state_doc: dict[str, Any] = state or {"phases": {}, "evidence": {}}
        self.files: dict[str, str] = {}  # other evidence files written under rollout/

    def describe(self) -> str:
        return "fake"

    def run(self, command: str, *, stdin: str | None = None, timeout: int = 300) -> CommandResult:
        self.commands.append(command)
        if "/opt/nlw/rollout/" in command and "cat >" in command:
            assert stdin is not None
            m = re.search(r"cat > '([^']+)\.tmp'", command)
            assert m is not None
            if m.group(1).endswith(f"/{SHA}.json"):
                self.state_doc = json.loads(stdin)
            else:
                self.files[m.group(1)] = stdin
            return CommandResult(0, "", "")
        if command.startswith("cat '/opt/nlw/rollout/"):
            if "alert-delivery" in command:
                return CommandResult(1, "", "")
            return CommandResult(0, json.dumps(self.state_doc), "")
        for pattern, response in self.table:
            if re.search(pattern, command):
                if isinstance(response, int):
                    return CommandResult(response, "", "scripted failure")
                if callable(response):
                    return CommandResult(0, response(self, command), "")
                return CommandResult(0, response, "")
        raise AssertionError(f"unscripted command: {command[:160]}")

    def ran(self, pattern: str) -> bool:
        return any(re.search(pattern, c) for c in self.commands)


OVERRIDE_YAML = (
    "services:\n  alertmanager:\n    volumes:\n"
    f"      - {AMCFG}:/etc/alertmanager/alertmanager.yml:ro\n"
    f"      - {AMSEC}:/etc/alertmanager/secrets:ro\n"
)
OPERATOR_CFG = (
    'route:\n  receiver: ops-slack\nreceivers:\n  - name: "null"\n  - name: ops-slack\n'
    "    slack_configs:\n      - api_url_file: /etc/alertmanager/secrets/slack.url\n"
)
NULL_CFG = (
    Path(__file__).resolve().parents[2] / "docker/alertmanager/alertmanager.yml"
).read_text()
CFG_SHA = "c" * 64
TGT_OP = TGT
# The N+1 target: the active deployment IS the activation symlink.
TGT_CURRENT = replace(
    TGT_OP, remote_app="/opt/nlw/current", git_remote="https://github.com/o/r.git"
)
PREVIOUS = "/opt/nlw/releases/" + "9" * 40
CADDYFILE_SRC = f"{STAGED}/docker/caddy/Caddyfile"
RENDERED_AM = json.dumps(
    {
        "services": {
            "api": {"environment": {"DEMO_TOOLS_ENABLED": "false"}},
            "caddy": {
                "image": "caddy:2",
                "environment": {
                    "PUBLIC_HOSTNAME": "32-197-83-193.sslip.io",
                    "PUBLIC_HOSTNAME_FALLBACK": "",
                },
                "volumes": [
                    {"type": "bind", "source": CADDYFILE_SRC,
                     "target": "/etc/caddy/Caddyfile", "read_only": True},
                    {"type": "volume", "source": "caddy_data", "target": "/data"},
                ],
            },
            "alertmanager": {
                "volumes": [
                    {"type": "bind", "source": AMCFG, "target": CFG_MOUNT, "read_only": True},
                    {"type": "bind", "source": AMSEC, "target": SEC_MOUNT, "read_only": True},
                    {"type": "volume", "source": "alertmanager_data", "target": "/alertmanager"},
                ]
            }
        }
    }
)  # fmt: skip


def _operator_table(
    *, cfg: str = OPERATOR_CFG, loaded: str | None = None, record: str = "__ABSENT__"
) -> Table:
    """Host + running-container facts for a correctly wired operator Alertmanager."""
    status = json.dumps({"config": {"original": loaded if loaded is not None else cfg}})
    mounts = (
        f"{AMCFG}:/etc/alertmanager/alertmanager.yml:false "
        f"{AMSEC}:{SEC_MOUNT}:false /var/lib/docker/volumes/x/_data:/alertmanager:true"
    )
    return [
        (r"cat '/opt/nlw/docker-compose\.operator\.yml'", OVERRIDE_YAML),
        (r"cat '/opt/nlw/alertmanager/alertmanager\.yml'", cfg),
        (r"sha256sum '/opt/nlw/alertmanager/alertmanager\.yml'", CFG_SHA),
        (
            r"--entrypoint stat -v '/opt/nlw/alertmanager/alertmanager\.yml:/probe/f:ro'",
            "f|regular file|644|0|0|200",
        ),
        (STAT_AM + r"'/probe/\.'", ".|directory|750|0|65534|4096"),
        (STAT_AM + r"'/probe/slack\.url'", "slack.url|regular file|640|0|65534|80"),
        (r"--user 65534:65534 .* -v '/opt/nlw/alertmanager\.secrets:/probe:ro'", "slack.url R"),
        (r"docker inspect --format '\{\{range \.Mounts\}\}[^|]*ps -q alertmanager", mounts),
        (r"readlink -f '/opt/nlw/alertmanager/alertmanager\.yml'", "/private" + AMCFG),
        (r"readlink -f '/opt/nlw/alertmanager\.secrets'", "/private" + AMSEC),
        (r"exec -T alertmanager sha256sum /etc/alertmanager/alertmanager\.yml", CFG_SHA),
        (r"api/v2/status", status),
        (r"exec -T alertmanager sh -c 'for f in", "/etc/alertmanager/secrets/slack.url R"),
        (r"alert-delivery\.json", record),
        (r"config --format json", RENDERED_AM),
    ]  # fmt: skip


MAINT = "/srv/maint/MAINTENANCE"


def _maintenance_on(fake: FakeRemote) -> bool:
    """The edge's maintenance flag as the fake host would have it: closed after a
    recorded drain until a recorded reopen, then toggled by the phase's OWN
    touch/rm commands (so a probe cannot simply agree with what a phase expects)."""
    phases = fake.state_doc.get("phases", {})
    closed_span = PHASES[PHASES.index("drain") : PHASES.index("reopen")]
    on = any(p in phases for p in closed_span) and "reopen" not in phases
    for command in fake.commands:
        if f"touch {MAINT}" in command:
            on = True
        elif f"rm -f {MAINT}" in command:
            on = False
    return on


def _edge_http(fake: FakeRemote, command: str) -> str:
    if _maintenance_on(fake):
        return "503"
    return "404" if "/metrics'" in command else "200"


def _adapted(*hosts: str) -> str:
    route = {"match": [{"host": list(hosts)}], "handle": [{"handler": "subroute"}]}
    return json.dumps({"apps": {"http": {"servers": {"srv0": {"routes": [route]}}}}})


def _edge_table(
    primary: str = "32-197-83-193.sslip.io", fallback: str = "", source: str = CADDYFILE_SRC
) -> Table:
    """A correctly wired edge: Caddyfile validates/adapts to exactly the reviewed
    hosts, the running caddy carries exactly those values and mounts the release
    Caddyfile, and every hostname answers per the maintenance flag."""
    running = (
        f"PUBLIC_HOSTNAME={primary}\nPUBLIC_HOSTNAME_FALLBACK={fallback}\nMOUNT={source}:false"
    )
    return [
        (r"caddy validate --config", ""),
        (r"caddy adapt --config", _adapted(primary, *([fallback] if fallback else []))),
        (r"docker inspect --format .*PUBLIC_HOSTNAME=.*ps -q caddy", running),
        (r"readlink -f '.*/docker/caddy/Caddyfile'", source),
        (r"port caddy 443", "0.0.0.0:443"),
        (r"curl -sk -o /dev/null .*--resolve", _edge_http),
        (r"up -d --no-deps caddy$", ""),
        (r"^sleep 5$", ""),
    ]


def _base_table(
    *,
    roles: str = ROLES_M11,
    staged_pins: str = PINS_STAGED,
    rev: str = "0010_readiness_schema_grant",
) -> Table:
    return [
        (r"169\.254\.169\.254", IMDS),
        (r"docker inspect --format .*DEMO_TOOLS_ENABLED=.*ps -q api", "match"),
        (r"grep -E '\^\(NLW_IMAGE.*'/opt/nlw/app/\.env\.prod'", PINS_ACTIVE),
        (r"grep -E '\^\(NLW_IMAGE.*releases", staged_pins),
        (r"alembic_version", rev),
        (r"pg_control_system", "7311111111111111111"),
        (r"pg_roles WHERE rolname", roles),
        (r"FROM workflow_runs WHERE status IN", "0|0|0"),
        (r"redis-cli llen", "0"),
        (r"pg_stat_activity", "0"),
        (r"git -C '/opt/nlw/app' rev-parse HEAD", OLD_SHA),
        (rf"git -C '{STAGED}' rev-parse HEAD", SHA),
        (rf"git -C '{STAGED}' status --porcelain", ""),
        (r"config --services", "api\nworker\nscheduler\nweb\ncaddy\nprometheus\nalertmanager"),
        # Backup env file: readable by the rollout user, not world-readable.
        (r"ls -ld '/opt/nlw/\.env\.backup' \| cut -c1-10", "-rw-r-----"),
        # Worker connector secrets: absent on this fixture host unless a test says so.
        (r"docker/worker\.secrets\.env", "absent"),
        # <ops_root>/current shape + post-activation readlink.
        (r"echo DIRECTORY; elif \[ -L", "ABSENT"),
        # Pre-activation phases: current is ABSENT on the legacy host.
        (r"if \[ -L '/opt/nlw/current' \]; then readlink", "ABSENT"),
        (r"readlink '/opt/nlw/current'", STAGED),
        *_edge_table(),
        *_operator_table(),
    ]


def _done(*phases: str) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "manifest_sha256": REL.sha256,
        "phases": {p: {} for p in phases},
        "evidence": {},
    }
    # Later phase fixtures have already passed staging under this manifest.
    if any(PHASES.index(p) >= PHASES.index("stage-release") for p in phases):
        doc["phases"]["stage-release"] = {}
        doc["evidence"]["stage-release"] = {
            "demo_tools_enabled": False,
            "public_hostname": REL.public_hostname,
            "public_hostname_fallback": "",
            "release_sha": SHA,
        }
    return doc


RECEIPT = ProvenanceReceipt(
    manifest_sha256=REL.sha256,
    release_sha=SHA,
    backend_digest=REL.backend_digest,
    web_digest=REL.web_digest,
    repository="atulpandey02/natural-language-workflow",
    workflow=".github/workflows/staging.yml",
    ref="refs/heads/main",
    event="push",
    run_id="1234567890",
    artifact_name=f"release-manifest-{SHA}",
    verifier="gh attestation verify",
    verified_at=NOW.isoformat(),
    fixture=False,
    subjects={"manifest": REL.sha256},
)


def _rollout(
    remote: FakeRemote, receipt: ProvenanceReceipt | None = RECEIPT, **op: object
) -> Rollout:
    return Rollout(
        release=REL,
        target=TGT,
        remote=remote,
        operator=Operator(**op),  # type: ignore[arg-type]
        log=lambda _m: None,
        now=lambda: NOW,
        receipt=receipt,
    )


KEYS = "/srv/nlw/ctx-keys"


def _all_phase_calls(r: Rollout) -> dict[str, Any]:
    return {
        "verify-release": r.verify_release,
        "prepare-keys": lambda: r.prepare_keys(keys_dir=KEYS),
        "verify-escrow": lambda: r.verify_escrow(keys_dir=KEYS),
        "stage-release": lambda: r.stage_release(keys_dir=KEYS),
        "backup": r.backup,
        "verify-backup": r.verify_backup,
        "drain": r.drain,
        "prepare-roles": r.prepare_roles,
        "migrate": r.migrate,
        "install-context-keys": lambda: r.install_context_keys(keys_dir=KEYS),
        "recreate-runtime": lambda: r.recreate_runtime(keys_dir=KEYS),
        "validate": lambda: r.validate(keys_dir=KEYS),
        "reopen": r.reopen,
    }


# --- order (§C) ------------------------------------------------------------------
def test_phase_order_puts_backup_verification_before_every_db_mutation() -> None:
    assert PHASES.index("verify-release") == 1
    assert PRE_BACKUP_PHASES[-1] == "verify-backup"
    for p in ("drain", "prepare-roles", "migrate", "install-context-keys", "recreate-runtime"):
        assert p not in PRE_BACKUP_PHASES
    assert PHASES.index("stage-release") < PHASES.index("backup") < PHASES.index("verify-backup")
    assert PHASES.index("verify-backup") < PHASES.index("drain") < PHASES.index("prepare-roles")
    assert (
        PHASES.index("prepare-roles")
        < PHASES.index("migrate")
        < PHASES.index("install-context-keys")
    )


# --- read-only default ---------------------------------------------------------
def test_preflight_is_read_only_and_needs_no_authorization() -> None:
    fake = FakeRemote(_base_table())
    report = _rollout(fake).preflight()
    assert report["current_revision"] == "0010_readiness_schema_grant"
    assert report["active_checkout"] == OLD_SHA
    for c in fake.commands:
        assert not DB_MUTATION.search(c) and not ACTIVE_MUTATION.search(c), c


def test_preflight_stops_on_wrong_instance_before_reading_anything_else() -> None:
    fake = FakeRemote(
        [(r"169\.254\.169\.254", IMDS.replace("i-0d1e65cdc9401dbb9", "i-0000000000000001"))]
    )
    with pytest.raises(GateError, match="instance"):
        _rollout(fake).preflight()
    assert len(fake.commands) == 1


# --- authorization ------------------------------------------------------------
@pytest.mark.parametrize("auth", [None, "", "yes", "AUTHORIZE_M12A"])
def test_mutating_phases_refuse_without_exact_authorization(auth: str | None) -> None:
    fake = FakeRemote(_base_table())
    r = _rollout(fake, authorization=auth)
    for call in _all_phase_calls(r).values():
        with pytest.raises(GateError, match="authorization"):
            call()
    assert fake.commands == []  # nothing was even read


# --- §B: an incapable (old) image is rejected before anything else ---------------
def test_verify_release_rejects_old_image_without_m12a_tooling() -> None:
    table = _base_table() + [
        (r"docker pull -q", ""),
        (
            r'index \.Config\.Labels "org\.opencontainers\.image\.revision"',
            "",
        ),  # old build: no label
    ]
    fake = FakeRemote(table)
    with pytest.raises(GateError, match="older or foreign build"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).verify_release()
    assert not fake.ran(r"image_info") and not fake.ran(r"ctxkeys|nlw\.ops\.roles")
    # Labelled but the probe fails (module missing on the old image).
    table2 = _base_table() + [
        (r"docker pull -q", ""),
        (r'index \.Config\.Labels "org\.opencontainers\.image\.revision"', SHA),
        (r"nlw\.ops\.rollout\.image_info", 1),
    ]
    fake2 = FakeRemote(table2)
    with pytest.raises(RolloutStop):
        _rollout(fake2, authorization=AUTHORIZATION_PHRASE).verify_release()
    assert not any(DB_MUTATION.search(c) or ACTIVE_MUTATION.search(c) for c in fake2.commands)


def test_verify_release_requires_every_command_and_records_evidence() -> None:
    table = _base_table() + [
        (r"docker pull -q", ""),
        (r'index \.Config\.Labels "org\.opencontainers\.image\.revision"', SHA),
        (r"nlw\.ops\.rollout\.image_info", IMAGE_INFO),
        (r"-m nlw\.backup evidence --help", 2),  # one required command missing
        (r"--help", ""),
    ]
    fake = FakeRemote(table)
    with pytest.raises(GateError, match="lacks required command"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).verify_release()
    ok_table = [(p, ("" if "evidence --help" in p else v)) for p, v in table]
    fake2 = FakeRemote(ok_table)
    rec = _rollout(fake2, authorization=AUTHORIZATION_PHRASE).verify_release()
    assert rec["image_git_sha"] == SHA and "verify-release" in fake2.state_doc["phases"]


# --- §C/§D: nothing mutates the database or the active deployment before the gate --
def _pre_backup_table() -> Table:
    return _base_table() + [
        (r"docker pull -q", ""),
        (r'index \.Config\.Labels "org\.opencontainers\.image\.revision"', SHA),
        (r"nlw\.ops\.rollout\.image_info", IMAGE_INFO),
        (r"--help", ""),
        (r"ctxkeys prepare --dir .* --class api", "prepared api " + "1" * 64),
        (r"ctxkeys prepare --dir .* --class worker", "prepared worker " + "2" * 64),
        (r"ctxkeys prepare --dir .* --class scheduler", "prepared scheduler " + "3" * 64),
        (r"--entrypoint stat .* '/keys/\.'", ".|directory|700|0|0|4096"),
        (r"--entrypoint stat .* '/keys/api\.key'", "api.key|regular file|400|10001|10001|65"),
        (r"--entrypoint stat .* '/keys/worker\.key'", "worker.key|regular file|400|10001|10001|65"),
        (
            r"--entrypoint stat .* '/keys/scheduler\.key'",
            "scheduler.key|regular file|400|10001|10001|65",
        ),
        (
            r"ctxkeys fingerprint",
            f"api stg-api-1 {'1' * 64}\nworker stg-worker-1 {'2' * 64}\n"
            f"scheduler stg-sched-1 {'3' * 64}",
        ),
        (r"sha256sum '/opt/nlw/app/\.env\.prod'", "abc"),
        (r"git clone|checkout -q --detach|git -C .* fetch", ""),
        (r"grep -Ev .* > '.*releases.*\.env\.prod\.tmp'", ""),
        (r"config >/dev/null", ""),
        (r"--profile backup build -q backup", ""),
        (r"--profile backup run --rm --no-deps -T -e NLW_BACKUP_SOURCE_INSTANCE_ID", ""),
        (r"--profile backup run --rm --no-deps -T backup evidence", json.dumps(GOOD_EVIDENCE)),
    ]


def _attestation(tmp_path: Path) -> Path:
    doc = {
        "format_version": 1,
        "environment": "staging",
        "release_sha": SHA,
        "keys": [
            {"purpose_class": "api", "key_id": "stg-api-1", "sha256_fingerprint": "1" * 64},
            {"purpose_class": "worker", "key_id": "stg-worker-1", "sha256_fingerprint": "2" * 64},
            {"purpose_class": "scheduler", "key_id": "stg-sched-1", "sha256_fingerprint": "3" * 64},
        ],
        "escrow_verified_at": (NOW - timedelta(hours=2)).isoformat(),
        "operator": "ops-lead",
        "recovery_test_confirmed": True,
        "escrow_location_label": "ops-vault staging ctx-keys 2026-09",
    }
    p = tmp_path / "att.json"
    p.write_text(json.dumps(doc))
    return p


def test_no_db_or_active_mutation_before_verified_backup(tmp_path: Path) -> None:
    fake = FakeRemote(_pre_backup_table())
    r = _rollout(
        fake,
        authorization=AUTHORIZATION_PHRASE,
        escrow_confirmation=ESCROW_PHRASE,
        attestation_path=_attestation(tmp_path),
    )
    r.preflight()
    r.verify_release()
    r.prepare_keys(keys_dir=KEYS)
    r.verify_escrow(keys_dir=KEYS)
    r.stage_release(keys_dir=KEYS)
    r.backup()
    r.verify_backup()
    assert set(fake.state_doc["phases"]) == set(PRE_BACKUP_PHASES) - {"preflight"}
    for c in fake.commands:
        assert not DB_MUTATION.search(c), f"DB mutation before verified backup: {c[:120]}"
        assert not ACTIVE_MUTATION.search(c), (
            f"active deployment touched before verified backup: {c[:120]}"
        )
    # The staged .env.prod was written; the ACTIVE one never was.
    assert fake.ran(rf"> '{STAGED}/\.env\.prod\.tmp'")
    assert not fake.ran(r"/opt/nlw/app/\.env\.prod\.tmp")
    # Backup ran read-only from the staged release with source binding, before drain.
    assert fake.ran(r"NLW_BACKUP_SOURCE_INSTANCE_ID=i-0d1e65cdc9401dbb9")
    assert fake.ran(rf"NLW_BACKUP_SOURCE_RELEASE={OLD_SHA}")


def test_mutating_phases_require_verified_backup_recorded_on_host() -> None:
    fake = FakeRemote(
        _base_table(roles=ROLES_ALL),
        state=_done("verify-release", "prepare-keys", "verify-escrow", "stage-release", "backup"),
    )
    r = _rollout(fake, authorization=AUTHORIZATION_PHRASE)
    for name in ("drain", "prepare-roles", "migrate"):
        with pytest.raises(StateError, match="verify-backup"):
            _all_phase_calls(r)[name]()
    assert not any(DB_MUTATION.search(c) or ACTIVE_MUTATION.search(c) for c in fake.commands)


@pytest.mark.parametrize("enabled", [False, True])
def test_stage_release_records_reviewed_demo_policy(enabled: bool) -> None:
    table = [
        (
            p,
            v.replace("DEMO_TOOLS_ENABLED=false", "DEMO_TOOLS_ENABLED=true")
            if enabled and isinstance(v, str)
            else v,
        )
        for p, v in _pre_backup_table()
    ]
    fake = FakeRemote(table, state=_done("verify-release", "verify-escrow"))
    rollout = _rollout(fake, authorization=AUTHORIZATION_PHRASE)
    rollout.target = replace(TGT, demo_tools_enabled=enabled)
    rollout.stage_release(keys_dir=KEYS)
    assert fake.state_doc["evidence"]["stage-release"]["demo_tools_enabled"] is enabled
    value = "true" if enabled else "false"
    assert fake.ran(rf"'DEMO_TOOLS_ENABLED' '{value}' >> '{STAGED}/\.env\.prod\.tmp'")
    assert not any(ACTIVE_MUTATION.search(c) or DB_MUTATION.search(c) for c in fake.commands)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("active_value", [None, "true", "false", "foreign-manual-value"])
def test_staged_demo_policy_overrides_active_value_without_changing_active_bytes(
    tmp_path: Path, enabled: bool, active_value: str | None
) -> None:
    active = tmp_path / "active"
    active.mkdir()
    target = replace(
        TGT, remote_app=str(active), ops_root=str(tmp_path), demo_tools_enabled=enabled
    )
    staged = Path(target.release_dir(SHA))
    staged.mkdir(parents=True)
    original = b"# active environment\nUNRELATED_SETTING=preserved\n"
    if active_value is not None:
        original += f"DEMO_TOOLS_ENABLED={active_value}\n".encode()
    env_file = active / ".env.prod"
    env_file.write_bytes(original)
    rollout = Rollout(
        release=REL, target=target, remote=LocalRemote(), operator=Operator(), log=lambda _: None
    )
    # Execute only the real env-file rewrite against temporary fixture directories.
    rollout._write_staged_env(keys_dir=KEYS)
    assert env_file.read_bytes() == original
    result = (staged / ".env.prod").read_text()
    assert result.count("DEMO_TOOLS_ENABLED=") == 1
    assert f"DEMO_TOOLS_ENABLED={'true' if enabled else 'false'}\n" in result
    assert result.startswith("# active environment\nUNRELATED_SETTING=preserved\n")
    assert (staged / ".env.prod").stat().st_mode & 0o777 == 0o600
    assert not (staged / ".env.prod.tmp").exists()


@pytest.mark.parametrize("target_value,recorded,pinned", list(product((False, True), repeat=3)))
def test_demo_authority_requires_target_state_and_staged_pin_agreement(
    target_value: bool, recorded: bool, pinned: bool
) -> None:
    doc = _done("stage-release")
    doc["evidence"]["stage-release"]["demo_tools_enabled"] = recorded
    pins = PINS_STAGED.replace(
        "DEMO_TOOLS_ENABLED=false", f"DEMO_TOOLS_ENABLED={str(pinned).lower()}"
    )
    fake = FakeRemote(_base_table(staged_pins=pins), state=doc)
    r = _rollout_op(fake, target=replace(TGT, demo_tools_enabled=target_value))
    if target_value == recorded == pinned:
        assert r._state(require_staged=True)["manifest_sha256"] == REL.sha256
    else:
        with pytest.raises(GateError, match="re-run stage-release"):
            r._state(require_staged=True)
    assert not any(ACTIVE_MUTATION.search(c) or DB_MUTATION.search(c) for c in fake.commands)


@pytest.mark.parametrize("phase", [*PHASES[PHASES.index("stage-release") + 1 :], "go-check"])
@pytest.mark.parametrize("change", ["target", "staged-file", "recorded"])
def test_every_later_phase_refuses_policy_drift_before_mutation(phase: str, change: str) -> None:
    doc = _done(*PHASES[1:])
    pins = PINS_STAGED
    target = TGT
    if change == "target":
        target = replace(TGT, demo_tools_enabled=True)
    elif change == "staged-file":
        pins = pins.replace("DEMO_TOOLS_ENABLED=false", "DEMO_TOOLS_ENABLED=true")
    else:
        doc["evidence"]["stage-release"]["demo_tools_enabled"] = True
    fake = FakeRemote(_base_table(staged_pins=pins), state=doc)
    r = _rollout_op(fake, target=target, authorization=AUTHORIZATION_PHRASE)
    call = r.go_check if phase == "go-check" else _all_phase_calls(r)[phase]
    with pytest.raises(GateError, match="re-run stage-release"):
        call()
    assert not any(ACTIVE_MUTATION.search(c) or DB_MUTATION.search(c) for c in fake.commands)


@pytest.mark.parametrize("binding", ["missing-manifest", "foreign-manifest", "foreign-release"])
def test_staged_demo_policy_cannot_use_unbound_or_foreign_state(binding: str) -> None:
    doc = _done("stage-release")
    if binding == "missing-manifest":
        doc.pop("manifest_sha256")
    elif binding == "foreign-manifest":
        doc["manifest_sha256"] = "f" * 64
    else:
        doc["evidence"]["stage-release"]["release_sha"] = "f" * 40
    fake = FakeRemote([], state=doc)
    with pytest.raises((StateError, GateError)):
        _rollout(fake)._state(require_staged=True)
    assert len(fake.commands) == 1  # only the state read, no host mutation


@pytest.mark.parametrize(
    "value", [None, "TRUE", "", "1", "false # comment", '"false"', "false\nDEMO_TOOLS_ENABLED=true"]
)
def test_noncanonical_or_missing_staged_pin_fails(value: str | None) -> None:
    line = "" if value is None else f"DEMO_TOOLS_ENABLED={value}\n"
    pins = PINS_STAGED.replace("DEMO_TOOLS_ENABLED=false\n", line)
    fake = FakeRemote(_base_table(staged_pins=pins), state=_done("stage-release"))
    with pytest.raises(GateError, match="re-run stage-release"):
        _rollout(fake)._state(require_staged=True)


def test_restaging_reviewed_change_updates_bound_state_and_requires_fresh_activation() -> None:
    class StagingRemote(FakeRemote):
        def run(
            self, command: str, *, stdin: str | None = None, timeout: int = 300
        ) -> CommandResult:
            if "'DEMO_TOOLS_ENABLED' 'true' >>" in command:
                self.table = [
                    (
                        p,
                        v.replace("DEMO_TOOLS_ENABLED=false", "DEMO_TOOLS_ENABLED=true")
                        if isinstance(v, str)
                        else v,
                    )
                    for p, v in self.table
                ]
            return super().run(command, stdin=stdin, timeout=timeout)

    fake = StagingRemote(_pre_backup_table(), state=_done(*PHASES[1:]))
    r = _rollout_op(
        fake, target=replace(TGT, demo_tools_enabled=True), authorization=AUTHORIZATION_PHRASE
    )
    with pytest.raises(GateError, match="re-run stage-release"):
        r.backup()
    r.stage_release(keys_dir=KEYS)
    doc = r._state(require_staged=True)
    assert doc["manifest_sha256"] == REL.sha256
    assert doc["evidence"]["stage-release"]["release_sha"] == SHA
    assert doc["evidence"]["stage-release"]["demo_tools_enabled"] is True
    assert not ({"recreate-runtime", "validate", "reopen"} & doc["phases"].keys())
    r.backup()  # progression permitted only after the explicit re-stage
    assert not any(ACTIVE_MUTATION.search(c) or DB_MUTATION.search(c) for c in fake.commands)


def test_restaging_an_active_release_cannot_rewrite_its_environment() -> None:
    fake = FakeRemote(
        [(r"if \[ -L '/opt/nlw/current'", STAGED)] + _pre_backup_table(),
        state=_done("verify-release", "verify-escrow", "stage-release"),
    )
    with pytest.raises(GateError, match="cannot re-stage the active release"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).stage_release(keys_dir=KEYS)
    assert not fake.ran(r"\.env\.prod\.tmp|git clone")


@pytest.mark.parametrize(
    "service",
    [
        "api",
        "worker",
        "scheduler",
        "web",
        "postgres",
        "redis",
        "caddy",
        "backup",
        "restore",
        "migrate",
        "prometheus",
        "alertmanager",
    ],
)
def test_rendered_demo_scope_mismatch_stops_before_recreation(service: str) -> None:
    rendered = json.loads(RENDERED_AM)
    rendered["services"].setdefault(service, {})["environment"] = {"DEMO_TOOLS_ENABLED": "true"}
    fake = FakeRemote(
        [(r"--profile '\*' config --format json", json.dumps(rendered))] + _activation_table(),
        state=_done("install-context-keys"),
    )
    with pytest.raises(GateError, match="rendered demo-tool policy/scope mismatch"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).recreate_runtime(keys_dir=KEYS)
    assert not fake.ran(r"up -d|ln -sfn")


@pytest.mark.parametrize("observed", ["mismatch", "", "match\nmatch"])
@pytest.mark.parametrize("phase", ["recreate-runtime", "validate", "reopen", "go-check"])
def test_running_demo_mismatch_never_reopens_traffic(phase: str, observed: str) -> None:
    fake = FakeRemote(
        [(r"docker inspect --format .*DEMO_TOOLS_ENABLED=.*ps -q api", observed)]
        + _activation_table(),
        state=_done(*PHASES[1:]),
    )
    r = _rollout(fake, authorization=AUTHORIZATION_PHRASE)
    call = r.go_check if phase == "go-check" else _all_phase_calls(r)[phase]
    with pytest.raises(GateError, match="running API demo-tool policy mismatch"):
        call()
    # Even previously successful validation cannot authorize reopening after drift.
    with pytest.raises(GateError, match="running API demo-tool policy mismatch"):
        r.reopen()
    assert not fake.ran(r"rm -f /srv/maint/MAINTENANCE")
    probe = next(c for c in fake.commands if "range .Config.Env" in c)
    assert "{{json .Config.Env}}" not in probe and "{{println .}}" not in probe


def test_prepare_roles_is_the_first_db_mutation_and_needs_drain() -> None:
    fake = FakeRemote(
        _base_table(),
        state=_done(
            "verify-release",
            "prepare-keys",
            "verify-escrow",
            "stage-release",
            "backup",
            "verify-backup",
        ),
    )
    with pytest.raises(StateError, match="drain"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).prepare_roles()
    assert not fake.ran(r"nlw\.ops\.roles ensure")


# --- §F: forged/foreign/stale evidence is refused inside the phase ------------
@pytest.mark.parametrize(
    "mutate, msg",
    [
        (
            lambda e: e["manifest"]["source"].update(db_system_identifier="7300000000000000000"),
            "another database cluster",
        ),
        (
            lambda e: e["manifest"]["source"].update(instance_id="i-0000000000000001"),
            "another host",
        ),
        (lambda e: e["manifest"]["source"].update(environment="production"), "another environment"),
        (lambda e: e["manifest"]["source"].update(release="f" * 40), "active checkout"),
        (lambda e: e["manifest"].update(alembic_revision="0015_x"), "source revision"),
        (lambda e: e.update(manifest=None), "no manifest"),
        (lambda e: e.update(repository="s3:http://minio:9000/nlwdrill"), "https|fixture"),
    ],
)
def test_verify_backup_refuses_unbound_or_fixture_evidence(mutate: Any, msg: str) -> None:
    ev = json.loads(json.dumps(GOOD_EVIDENCE))
    mutate(ev)
    table = _base_table() + [
        (r"--profile backup run --rm --no-deps -T backup evidence", json.dumps(ev))
    ]
    fake = FakeRemote(
        table, state=_done("verify-release", "prepare-keys", "verify-escrow", "stage-release")
    )
    r = _rollout(
        fake, authorization=AUTHORIZATION_PHRASE, allow_fixture_repository=True
    )  # not local: ignored
    with pytest.raises(GateError, match=msg):
        r.verify_backup()
    assert "verify-backup" not in fake.state_doc["phases"]


def test_stale_evidence_is_refused() -> None:
    table = _base_table() + [
        (r"--profile backup run --rm --no-deps -T backup evidence", json.dumps(GOOD_EVIDENCE))
    ]
    fake = FakeRemote(
        table, state=_done("verify-release", "prepare-keys", "verify-escrow", "stage-release")
    )
    r = Rollout(
        release=REL,
        target=TGT,
        remote=fake,
        operator=Operator(authorization=AUTHORIZATION_PHRASE),
        log=lambda _m: None,
        now=lambda: NOW + timedelta(hours=30),
    )
    with pytest.raises(GateError, match="too old"):
        r.verify_backup()


# --- drain / roles / migrate / recreate gates ----------------------------------
def test_drain_stops_on_non_terminal_work_and_never_stops_api() -> None:
    table = _base_table()
    table = [(p, ("2|0|0" if "workflow_runs" in p else v)) for p, v in table]
    table += [
        (r"up -d --no-deps --force-recreate caddy", ""),
        (r"exec -T caddy touch", ""),
        (r"\bstop scheduler\b", ""),
        (r"^sleep", ""),
    ]
    fake = FakeRemote(
        table,
        state=_done(
            "verify-release",
            "prepare-keys",
            "verify-escrow",
            "stage-release",
            "backup",
            "verify-backup",
        ),
    )
    with pytest.raises(GateError, match="non-terminal"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).drain()
    assert fake.ran(r"stop scheduler") and not fake.ran(r"stop worker api")
    assert fake.ran(
        rf"cd '{STAGED}' && env -u DEMO_TOOLS_ENABLED -u PUBLIC_HOSTNAME "
        r"-u PUBLIC_HOSTNAME_FALLBACK -u NLW_LLM_PROVIDER -u NLW_LLM_MODEL -u NLW_LLM_API_KEY "
        r"docker compose -p app .* "
        r"up -d --no-deps --force-recreate caddy"
    )


def test_open_runtime_sessions_block_roles_and_migration() -> None:
    table = [(p, ("3" if p == r"pg_stat_activity" else v)) for p, v in _base_table(roles=ROLES_ALL)]
    done = _done(
        "verify-release",
        "prepare-keys",
        "verify-escrow",
        "stage-release",
        "backup",
        "verify-backup",
        "drain",
        "prepare-roles",
    )
    fake = FakeRemote(table, state=done)
    r = _rollout(fake, authorization=AUTHORIZATION_PHRASE)
    with pytest.raises(GateError, match="session"):
        r.prepare_roles()
    with pytest.raises(GateError, match="session"):
        r.migrate()
    assert not fake.ran("--profile migration run")


def test_migrate_refuses_when_staged_dir_is_not_the_release_checkout() -> None:
    table = [
        (p, ("0" * 40 if f"git -C '{STAGED}' rev-parse HEAD" in p else v))
        for p, v in _base_table(roles=ROLES_ALL)
    ]
    done = _done(
        "verify-release",
        "prepare-keys",
        "verify-escrow",
        "stage-release",
        "backup",
        "verify-backup",
        "drain",
        "prepare-roles",
    )
    fake = FakeRemote(table, state=done)
    with pytest.raises(GateError, match="release is"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).migrate()
    assert not fake.ran(r"--profile migration run")


def test_partial_key_install_never_recreates_runtimes() -> None:
    table = _base_table(roles=ROLES_ALL, rev="0016_signed_database_context") + [
        (r"ctxkeys install --class api", "installed: stg-api-1 (api)"),
        (r"ctxkeys install --class worker", "installed: stg-worker-1 (worker)"),
        (r"ctxkeys install --class scheduler", 1),  # third install FAILS
    ]
    fake = FakeRemote(table, state=_done("migrate"))
    r = _rollout(fake, authorization=AUTHORIZATION_PHRASE)
    with pytest.raises(RolloutStop):
        r.install_context_keys(keys_dir=KEYS)
    assert not fake.ran(r"up -d") and not fake.ran(r"ln -sfn")
    with pytest.raises(StateError, match="install-context-keys"):
        r.recreate_runtime(keys_dir=KEYS)
    assert not fake.ran(r"up -d") and not fake.ran(r"ln -sfn")


def test_recreate_runtime_activates_only_after_keys_and_rejects_old_image() -> None:
    old = "ghcr.io/o/r@sha256:" + "f" * 64
    table = _base_table(roles=ROLES_ALL, rev="0016_signed_database_context") + [
        (r"config >/dev/null", ""),
        (r"ln -sfn", ""),
        (r"up -d --force-recreate", ""),
        (
            r"join \.RepoDigests",
            f"api {old}\nworker {REL.backend_image}\nscheduler {REL.backend_image}\n"
            f"web {REL.web_image}",
        ),
    ]
    fake = FakeRemote(table, state=_done("install-context-keys"))
    with pytest.raises(GateError, match="api is running"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).recreate_runtime(keys_dir=KEYS)
    assert fake.ran(rf"ln -sfn '{STAGED}' '/opt/nlw/current'")


def test_reopen_blocked_without_signed_context_readiness() -> None:
    table = _base_table() + [
        (
            r"curl -sS -m 5 http://127.0.0.1:8000/health/ready",
            '{"status":"ready","checks":{"postgres":"ok"}}',
        )
    ]
    fake = FakeRemote(table, state=_done("validate"))
    with pytest.raises(GateError, match="signed_context"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).reopen()
    assert not fake.ran(r"rm -f /srv/maint/MAINTENANCE")


def test_null_operator_config_is_refused_and_technical_reopen_records_the_open_gate() -> None:
    # The committed null receiver can never be the operator's configuration.
    fake = FakeRemote(_reopen_table(cfg=NULL_CFG), state=_done("validate"))
    with pytest.raises(GateError, match="null receiver"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).reopen()
    assert not fake.ran(r"rm -f /srv/maint/MAINTENANCE")
    # A real, credentialed receiver without a confirmed controlled delivery: the
    # technical deployment reopens, the launch gate is RECORDED, go-check is NO-GO.
    fake2 = FakeRemote(_reopen_table(), state=_done("validate"))
    r = _rollout(fake2, authorization=AUTHORIZATION_PHRASE)
    assert r.reopen() == ["alert delivery unverified"]
    ev = fake2.state_doc["evidence"]["reopen"]["alerting"]
    assert ev["delivery_verified"] is False and ev["alertmanager_reachable"] is True
    assert ev["rules_loaded"] is True and ev["receiver_is_null"] is False
    with pytest.raises(GateError, match="no verified controlled test"):
        r.go_check()


# --- provenance receipt + manifest-digest binding (ADR-025) ---------------------------
def test_verify_release_refuses_without_a_provenance_receipt_for_this_manifest() -> None:
    fake = FakeRemote(_base_table())
    with pytest.raises(GateError, match="provenance was not verified"):
        _rollout(fake, receipt=None, authorization=AUTHORIZATION_PHRASE).verify_release()
    other = replace(RECEIPT, manifest_sha256="0" * 64)
    with pytest.raises(GateError, match="provenance was not verified"):
        _rollout(fake, receipt=other, authorization=AUTHORIZATION_PHRASE).verify_release()
    assert not any("docker pull" in c for c in fake.commands)  # nothing was staged


def test_verify_release_stores_manifest_and_receipt_as_evidence() -> None:
    fake = FakeRemote(_pre_backup_table())
    _rollout(fake, authorization=AUTHORIZATION_PHRASE).verify_release()
    assert fake.files[f"/opt/nlw/rollout/{SHA}.manifest.json"] == REL_RAW
    receipt = json.loads(fake.files[f"/opt/nlw/rollout/{SHA}.receipt.json"])
    assert receipt["manifest_sha256"] == REL.sha256 and receipt["fixture"] is False
    saved = fake.state_doc
    assert saved["manifest_sha256"] == REL.sha256
    assert saved["evidence"]["verify-release"]["provenance"]["run_id"] == "1234567890"
    assert "://" not in json.dumps(saved)


def test_state_recorded_for_another_manifest_invalidates_every_phase() -> None:
    """Replacing the manifest file after phases ran (same release SHA, different
    bytes) must not let the earlier evidence carry over."""
    stale = _done("verify-backup")
    stale["manifest_sha256"] = "1" * 64  # recorded for different bytes
    fake = FakeRemote(_base_table(), state=stale)
    r = _rollout(
        fake,
        authorization=AUTHORIZATION_PHRASE,
        escrow_confirmation=ESCROW_PHRASE,
        attestation_path=Path("/nonexistent/attestation.json"),
    )
    with pytest.raises(StateError, match="different release manifest"):
        r.preflight()
    for call in _all_phase_calls(r).values():
        with pytest.raises(StateError, match="different release manifest"):
            call()
    assert not any("ctxkeys prepare" in c for c in fake.commands)  # no host files either
    assert not any(DB_MUTATION.search(c) or ACTIVE_MUTATION.search(c) for c in fake.commands)


# --- final audit: legacy-host first rollout -------------------------------------------
def _stage_table() -> Table:
    return _base_table() + [
        (
            r"ctxkeys fingerprint",
            f"api stg-api-1 {'1' * 64}\nworker stg-worker-1 {'2' * 64}\n"
            f"scheduler stg-sched-1 {'3' * 64}",
        ),
        (r"sha256sum '/opt/nlw/app/\.env\.prod'", "abc"),
        (r"git clone|checkout -q --detach|git -C .* fetch", ""),
        (r"grep -Ev .* > '.*releases.*\.env\.prod\.tmp'", ""),
        (r"config >/dev/null", ""),
        (r"--profile backup build -q backup", ""),
    ]


def test_one_shot_migrate_runs_never_converge_dependencies() -> None:
    """Reproduced with Compose v5: `run` from the staged directory recreates the
    live postgres container (diverged relative bind mount) unless --no-deps."""
    from nlw.ops.rollout import phases as ph

    src = Path(ph.__file__).read_text()
    body = src[src.index("def _migrate_run(") : src.index("def _image_python(")]
    assert "--profile migration run --rm --no-deps -T" in body
    table = _base_table(roles=ROLES_ALL) + [(r"nlw\.ops\.roles ensure", "ok")]
    fake = FakeRemote(table, state=_done("verify-backup", "drain"))
    _rollout(fake, authorization=AUTHORIZATION_PHRASE).prepare_roles()
    runs = [c for c in fake.commands if "--profile migration run" in c]
    assert runs and all("--no-deps" in c for c in runs)


def test_preflight_stops_when_backup_env_file_is_unreadable_or_world_readable() -> None:
    for mode, msg in (("MISSING_OR_UNREADABLE", "not readable"), ("-rw-r--r--", "world-readable")):
        table = [(r"ls -ld '/opt/nlw/\.env\.backup' \| cut -c1-10", mode)] + _base_table()
        fake = FakeRemote(table)
        with pytest.raises(GateError, match=msg):
            _rollout(fake).preflight()
        # The check never reads the file's contents.
        assert not fake.ran(r"cat '/opt/nlw/\.env\.backup'|grep .*\.env\.backup")


def test_preflight_records_backup_env_mode_and_backup_phase_rechecks(tmp_path: Path) -> None:
    fake = FakeRemote(_base_table())
    assert _rollout(fake).preflight()["backup_env_mode"] == "-rw-r-----"
    table = [
        (r"ls -ld '/opt/nlw/\.env\.backup' \| cut -c1-10", "MISSING_OR_UNREADABLE")
    ] + _stage_table()
    fake = FakeRemote(table, state=_done("stage-release"))
    with pytest.raises(GateError, match="not readable"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).backup()
    assert not fake.ran(r"--profile backup run")


def test_stage_release_carries_worker_connector_secrets_when_present() -> None:
    table = [(r"docker/worker\.secrets\.env", "staged")] + _stage_table()
    fake = FakeRemote(table, state=_done("verify-release", "verify-escrow"))
    _rollout(fake, authorization=AUTHORIZATION_PHRASE).stage_release(keys_dir=KEYS)
    cmd = next(c for c in fake.commands if "worker.secrets.env" in c)
    assert "umask 077" in cmd and "chmod 600" in cmd and ".tmp" in cmd and "mv " in cmd
    assert f"'{STAGED}/docker/worker.secrets.env" in cmd
    assert "'/opt/nlw/app/docker/worker.secrets.env'" in cmd
    assert fake.state_doc["evidence"]["stage-release"]["worker_env_file"] == "staged"
    # Absent on the host -> recorded as such (never invented).
    fake2 = FakeRemote(_stage_table(), state=_done("verify-release", "verify-escrow"))
    _rollout(fake2, authorization=AUTHORIZATION_PHRASE).stage_release(keys_dir=KEYS)
    assert fake2.state_doc["evidence"]["stage-release"]["worker_env_file"] == "absent"


def test_recreate_runtime_refuses_a_real_directory_at_current_and_verifies_the_link() -> None:
    base = _base_table(roles=ROLES_ALL, rev="0016_signed_database_context") + [
        (r"config >/dev/null", ""),
        (r"ln -sfn", ""),
        (r"up -d --force-recreate", ""),
    ]
    fake = FakeRemote(
        [(r"echo DIRECTORY; elif \[ -L", "DIRECTORY")] + base, state=_done("install-context-keys")
    )
    with pytest.raises(GateError, match="not a symlink"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).recreate_runtime(keys_dir=KEYS)
    assert not fake.ran(r"ln -sfn") and not fake.ran(r"up -d")
    # The link is verified after it is written: a wrong target stops before recreate.
    fake2 = FakeRemote(
        [(r"readlink '/opt/nlw/current'", "/opt/nlw/app")] + base,
        state=_done("install-context-keys"),
    )
    with pytest.raises(GateError, match="not the staged release"):
        _rollout(fake2, authorization=AUTHORIZATION_PHRASE).recreate_runtime(keys_dir=KEYS)
    assert fake2.ran(r"ln -sfn") and not fake2.ran(r"up -d")


def test_activation_and_key_install_recheck_host_identity() -> None:
    wrong = "instance-id=i-0000000000000000\nplacement/region=us-east-1\npublic-ipv4=1.2.3.4\n"
    base = _base_table(roles=ROLES_ALL, rev="0016_signed_database_context")
    table = [(r"169\.254\.169\.254", wrong)] + base
    for phase, state_ in (
        ("install-context-keys", "migrate"),
        ("recreate-runtime", "install-context-keys"),
    ):
        fake = FakeRemote(table, state=_done(state_))
        r = _rollout(fake, authorization=AUTHORIZATION_PHRASE)
        with pytest.raises(GateError, match="instance"):
            _all_phase_calls(r)[phase]()
        assert not fake.ran(r"ctxkeys install|ln -sfn|up -d")


def test_preflight_refuses_an_empty_backup_env_file() -> None:
    table = [(r"ls -ld '/opt/nlw/\.env\.backup' \| cut -c1-10", "EMPTY")] + _base_table()
    fake = FakeRemote(table)
    with pytest.raises(GateError, match="is empty"):
        _rollout(fake).preflight()


def test_pre_activation_phases_refuse_a_host_activated_for_another_release() -> None:
    """A LEGACY target (remote_app = /opt/nlw/app) on a host whose current ->
    releases/<other>: evidence and the staged env would derive from the obsolete
    legacy checkout. Fail closed, naming the follows-current configuration."""
    other = "/opt/nlw/releases/" + "9" * 40
    foreign = [(r"if \[ -L '/opt/nlw/current' \]; then readlink", other)]
    with pytest.raises(GateError, match="already points at"):
        _rollout(FakeRemote(foreign + _base_table())).preflight()
    fake = FakeRemote(foreign + _stage_table(), state=_done("verify-release", "verify-escrow"))
    with pytest.raises(GateError, match="NLW_STAGING_REMOTE_APP=/opt/nlw/current"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).stage_release(keys_dir=KEYS)
    assert not fake.ran(r"git clone|releases.*\.env\.prod")
    for phase in ("backup", "verify-backup"):
        fake = FakeRemote(foreign + _stage_table(), state=_done("stage-release"))
        with pytest.raises(GateError, match="already points at"):
            _all_phase_calls(_rollout(fake, authorization=AUTHORIZATION_PHRASE))[phase]()
        assert not fake.ran(r"--profile backup run")
    # Re-running a pre-activation phase for THIS release after its own activation
    # (current -> this staged dir) is allowed; the report records the shape.
    this = [(r"if \[ -L '/opt/nlw/current' \]; then readlink", STAGED)]
    assert _rollout(FakeRemote(this + _base_table())).preflight()["current_link"] == "THIS_RELEASE"
    assert _rollout(FakeRemote(_base_table())).preflight()["current_link"] == "ABSENT"
    # A real directory (or file) at current cannot be switched atomically: its own
    # explicit message, before any phase touches the host.
    plain = [(r"if \[ -L '/opt/nlw/current' \]; then readlink", "NOT_A_SYMLINK")]
    with pytest.raises(GateError, match="exists but is not a symlink"):
        _rollout(FakeRemote(plain + _base_table())).preflight()


# --- post-rollout hotfix: reproduced on the first real staging rollout ------------------
# Operator Alertmanager authority (host paths OUTSIDE every release checkout) and the
# effective configuration of the RUNNING container; individual key-file mounts;
# N -> N+1 rollouts that follow <ops_root>/current.
def _rollout_op(remote: FakeRemote, target: TargetConfig = TGT_OP, **op: object) -> Rollout:
    return Rollout(
        release=REL,
        target=target,
        remote=remote,
        operator=Operator(**op),  # type: ignore[arg-type]
        log=lambda _m: None,
        now=lambda: NOW,
        receipt=RECEIPT,
    )


def _reopen_table(**kw: Any) -> Table:
    return (
        _operator_table(**kw)
        + _base_table()
        + [
            (
                r"curl -sS -m 5 http://127.0.0.1:8000/health/ready",
                '{"status":"ready","checks":{"signed_context":"ok"}}',
            ),
            (
                r"api/v1/rules",
                json.dumps(
                    {"data": {"groups": [{"name": "nlw-backup"}, {"name": "nlw-signed-context"}]}}
                ),
            ),
            (
                r"api/v1/alertmanagers",
                json.dumps(
                    {
                        "data": {
                            "activeAlertmanagers": [
                                {"url": "http://alertmanager:9093/api/v2/alerts"}
                            ]
                        }
                    }
                ),
            ),
            (r"9093/-/healthy", "OK"),
            (r"exec -T caddy rm -f /srv/maint/MAINTENANCE", ""),
        ]
    )


# J.1 / J.2 — defect 1: the migrate container runs as uid 10001 and cannot traverse the
# root:root 0700 key directory; only the required key FILE may be mounted.
def test_key_install_and_check_mount_only_each_required_key_file() -> None:
    table = _base_table(roles=ROLES_ALL, rev="0016_signed_database_context") + [
        (r"ctxkeys install --class (\w+)", "installed: k"),
        (r"ctxkeys check --class (\w+)", "ok: k"),
        (r"FROM ctx_keys WHERE status", "3"),
        (r"FROM ctx_key_events", "0"),
    ]
    fake = FakeRemote(table, state=_done("migrate"))
    _rollout_op(fake, authorization=AUTHORIZATION_PHRASE).install_context_keys(keys_dir=KEYS)
    one_shots = [c for c in fake.commands if "ctxkeys install" in c or "ctxkeys check" in c]
    assert len(one_shots) == 6
    for cmd in one_shots:
        cls = re.search(r"--class (\w+)", cmd).group(1)  # type: ignore[union-attr]
        assert f"-v '{KEYS}/{cls}.key:/run/nlw/keys/{cls}.key:ro'" in cmd
        assert f"--secret-file /run/nlw/keys/{cls}.key" in cmd
        assert f"'{KEYS}:/run/nlw/keys" not in cmd, "the whole 0700 key directory was mounted"
        assert cmd.count("/run/nlw/keys/") == 2, "exactly one key mounted per one-shot"
        assert "--no-deps" in cmd
    assert not fake.ran(r"chmod|chown")  # no permission workaround on the host
    assert fake.state_doc["phases"].get("install-context-keys")


# J.3 / J.4 — defect 3: reopen/go-check evaluate the RUNNING Alertmanager (mounts,
# mounted bytes, loaded config), never the committed null file in the staged checkout.
def test_reopen_and_go_check_evaluate_the_running_alertmanager_not_the_staged_file() -> None:
    fake = FakeRemote(_reopen_table(), state=_done("validate"))
    r = _rollout_op(fake, authorization=AUTHORIZATION_PHRASE)
    assert r.reopen() == ["alert delivery unverified"]  # no controlled-delivery record yet
    ev = fake.state_doc["evidence"]["reopen"]["alerting"]
    assert ev["receiver"] == "ops-slack" and ev["receiver_is_null"] is False
    assert ev["credential_files_present"] is True and ev["delivery_verified"] is False
    assert ev["config_source"] == "running-alertmanager" and ev["delivery_status"] == "absent"
    assert not fake.ran(r"cat '.*releases/.*/docker/alertmanager/alertmanager\.yml'")
    assert fake.ran(r"api/v2/status") and fake.ran(r"exec -T alertmanager sha256sum")
    with pytest.raises(GateError, match="no verified controlled test"):
        r.go_check()
    # A fresh, matching, confirmed record closes the gate — the only way it closes.
    good = json.dumps(
        {
            "receiver": "ops-slack",
            "delivered_at": (NOW - timedelta(hours=2)).isoformat(),
            "confirmed_by": "ops-lead",
        }
    )
    fake2 = FakeRemote(_reopen_table(record="__OK__\n" + good), state=_done("validate"))
    r2 = _rollout_op(fake2, authorization=AUTHORIZATION_PHRASE)
    assert r2.reopen() == []
    r2.go_check()
    assert fake2.state_doc["evidence"]["reopen"]["alerting"]["delivery_status"] == "verified"


@pytest.mark.parametrize(
    "record, status, msg",
    [
        ("__UNREADABLE__", "unreadable", "not readable"),
        ("__OK__\n{not json", "malformed", "malformed"),
        ("__OK__\n[1, 2]", "malformed", "malformed"),
    ],
)
def test_unreadable_or_malformed_delivery_evidence_fails_closed(
    record: str, status: str, msg: str
) -> None:
    fake = FakeRemote(_reopen_table(record=record), state=_done("validate"))
    with pytest.raises(GateError, match=msg):
        _rollout_op(fake, authorization=AUTHORIZATION_PHRASE).reopen()
    assert not fake.ran(r"rm -f /srv/maint/MAINTENANCE")
    fake2 = FakeRemote(_reopen_table(record=record), state=_done("reopen"))
    with pytest.raises(GateError, match=msg):
        _rollout_op(fake2, authorization=AUTHORIZATION_PHRASE).go_check()


@pytest.mark.parametrize(
    "over, status",
    [
        ({"delivered_at": (NOW - timedelta(days=8)).isoformat()}, "stale"),
        ({"receiver": "null"}, "receiver-mismatch"),
        ({"receiver": "other-team"}, "receiver-mismatch"),
        ({"confirmed_by": ""}, "unconfirmed"),
        ({"delivered_at": "2026-09-20T10:00:00"}, "stale"),  # naive timestamp never counts
    ],
)
def test_stale_or_mismatched_delivery_evidence_never_verifies(
    over: dict[str, str], status: str
) -> None:
    doc = {
        "receiver": "ops-slack",
        "delivered_at": (NOW - timedelta(hours=2)).isoformat(),
        "confirmed_by": "ops",
    }
    doc.update(over)
    fake = FakeRemote(_reopen_table(record="__OK__\n" + json.dumps(doc)), state=_done("validate"))
    r = _rollout_op(fake, authorization=AUTHORIZATION_PHRASE)
    assert r.reopen() == ["alert delivery unverified"]
    assert fake.state_doc["evidence"]["reopen"]["alerting"]["delivery_status"] == status
    with pytest.raises(GateError, match=status):
        r.go_check()


def test_committed_null_config_cannot_misrepresent_the_running_config() -> None:
    # (a) the running container LOADED the null config while the operator file is real:
    fake = FakeRemote(_reopen_table(loaded=NULL_CFG), state=_done("validate"))
    with pytest.raises(GateError, match="loaded configuration"):
        _rollout_op(fake, authorization=AUTHORIZATION_PHRASE).reopen()
    assert not fake.ran(r"rm -f /srv/maint/MAINTENANCE")
    # (b) the container mounts the committed staged file, not the operator file:
    staged_mounts = (
        f"{STAGED}/docker/alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:false "
        f"{AMSEC}:/etc/alertmanager/secrets:false"
    )
    table = [
        (r"docker inspect --format '\{\{range \.Mounts\}\}[^|]*ps -q alertmanager", staged_mounts)
    ] + _reopen_table()
    fake2 = FakeRemote(table, state=_done("validate"))
    with pytest.raises(GateError, match="mount"):
        _rollout_op(fake2, authorization=AUTHORIZATION_PHRASE).reopen()
    # (c) mounted bytes differ from the operator file (edited after the container started):
    table3 = [(r"exec -T alertmanager sha256sum", "d" * 64)] + _reopen_table()
    with pytest.raises(GateError, match="differ"):
        _rollout_op(
            FakeRemote(table3, state=_done("validate")), authorization=AUTHORIZATION_PHRASE
        ).reopen()
    # (d) the OPERATOR file itself routes to null: refused outright (never a "technical" reopen).
    with pytest.raises(GateError, match="null receiver"):
        _rollout_op(
            FakeRemote(_reopen_table(cfg=NULL_CFG), state=_done("validate")),
            authorization=AUTHORIZATION_PHRASE,
        ).reopen()


# J.5 / J.6 — the operator override is required BEFORE Alertmanager is recreated and
# every recreation keeps the external config + secrets mounts.
def _activation_table(**kw: Any) -> Table:
    return (
        _operator_table(**kw)
        + _base_table(roles=ROLES_ALL, rev="0016_signed_database_context")
        + [
            (r"config >/dev/null", ""),
            (r"ln -sfn", ""),
            (r"up -d --force-recreate", ""),
            (
                r"join \.RepoDigests",
                f"api {REL.backend_image}\nworker {REL.backend_image}\n"
                f"scheduler {REL.backend_image}\nweb {REL.web_image}",
            ),
            (
                r"for s in api worker scheduler web postgres redis caddy prometheus alertmanager",
                "",
            ),
            (r"docker ps -a --filter name=app-migrate", ""),
        ]
    )


def test_missing_operator_override_fails_before_alertmanager_recreation() -> None:
    for phase, done in (("preflight", None), ("recreate-runtime", "install-context-keys")):
        fake = FakeRemote(_activation_table(), state=_done(done) if done else None)
        r = _rollout_op(fake, target=TGT_LEGACY_NO_OPERATOR, authorization=AUTHORIZATION_PHRASE)
        with pytest.raises(GateError, match="operator Alertmanager configuration is required"):
            if phase == "preflight":
                r.preflight()
            else:
                r.recreate_runtime(keys_dir=KEYS)
        assert not fake.ran(r"up -d|ln -sfn")
    # Configured but the override file is missing/unreadable -> stop before activation.
    fake = FakeRemote(
        [(r"cat '/opt/nlw/docker-compose\.operator\.yml'", "__UNREADABLE__")] + _activation_table(),
        state=_done("install-context-keys"),
    )
    with pytest.raises(GateError, match="override"):
        _rollout_op(fake, authorization=AUTHORIZATION_PHRASE).recreate_runtime(keys_dir=KEYS)
    assert not fake.ran(r"up -d|ln -sfn")
    # The rendered Compose config no longer carries the operator mounts (override
    # dropped from the invocation) -> stop before activation.
    rendered_null = json.dumps(
        {
            "services": {
                "alertmanager": {
                    "volumes": [
                        {
                            "type": "bind",
                            "source": f"{STAGED}/docker/alertmanager/alertmanager.yml",
                            "target": "/etc/alertmanager/alertmanager.yml",
                            "read_only": True,
                        }
                    ]
                }
            }
        }
    )
    fake2 = FakeRemote(
        [(r"config --format json", rendered_null)] + _activation_table(),
        state=_done("install-context-keys"),
    )
    with pytest.raises(GateError, match="rendered"):
        _rollout_op(fake2, authorization=AUTHORIZATION_PHRASE).recreate_runtime(keys_dir=KEYS)
    assert not fake2.ran(r"up -d|ln -sfn")


def test_running_mount_sources_accept_only_the_operator_path_or_its_realpath() -> None:
    # Docker Desktop (rehearsal) reports /host_mnt<realpath>; Linux reports the path.
    desktop = (
        f"/host_mnt/private{AMCFG}:/etc/alertmanager/alertmanager.yml:false "
        f"/host_mnt/private{AMSEC}:/etc/alertmanager/secrets:false"
    )
    table = [(r"docker inspect --format '\{\{range \.Mounts\}\}[^|]*ps -q alertmanager", desktop)]
    fake = FakeRemote(table + _reopen_table(), state=_done("validate"))
    assert _rollout_op(fake, authorization=AUTHORIZATION_PHRASE).reopen() == [
        "alert delivery unverified"
    ]
    # A different directory that merely shares the prefix is still a disagreement.
    other = desktop.replace(f"/host_mnt/private{AMSEC}:", f"/host_mnt/private{AMSEC}-old:")
    table2 = [(r"docker inspect --format '\{\{range \.Mounts\}\}[^|]*ps -q alertmanager", other)]
    with pytest.raises(GateError, match="mount disagreement"):
        _rollout_op(
            FakeRemote(table2 + _reopen_table(), state=_done("validate")),
            authorization=AUTHORIZATION_PHRASE,
        ).reopen()


def test_recreation_uses_the_operator_override_and_verifies_the_running_mounts() -> None:
    fake = FakeRemote(_activation_table(), state=_done("install-context-keys"))
    _rollout_op(fake, authorization=AUTHORIZATION_PHRASE).recreate_runtime(keys_dir=KEYS)
    ups = [c for c in fake.commands if "up -d --force-recreate" in c]
    assert ups and all(f"-f {OVR}" in c for c in ups), ups
    assert any("alertmanager" in c for c in ups)
    assert fake.ran(r"docker inspect --format '\{\{range \.Mounts\}\}[^|]*ps -q alertmanager")
    assert (
        fake.state_doc["evidence"]["recreate-runtime"]["alertmanager"]["config_source"]
        == "running-alertmanager"
    )
    # Every reviewed Compose invocation from a release directory carries the override.
    assert f"-f {OVR}" in TGT_OP.dc_in(STAGED) and f"-f {OVR}" in TGT_CURRENT.dc
    # ...except the LEGACY active checkout (no alertmanager service there): exec/stop only.
    assert f"-f {OVR}" not in TGT_OP.dc


# J.7 — the host-side permission matrix (probed through a root container; readability
# proved as the Alertmanager user 65534). Nothing world-readable, nothing inline.
@pytest.mark.parametrize(
    "pattern, line, msg",
    [
        (r"'/probe/slack\.url'", "slack.url|regular file|644|0|65534|80", "world-readable"),
        (
            r"'/probe/slack\.url'",
            "slack.url|regular file|600|0|0|80",
            "readable by the Alertmanager user",
        ),
        (r"'/probe/slack\.url'", "slack.url|regular file|640|0|65534|0", "empty"),
        (r"'/probe/slack\.url'", "slack.url|symbolic link|777|0|0|20", "regular file"),
        (r"'/probe/\.'", ".|directory|755|0|65534|4096", "world"),
        (r"'/probe/\.'", ".|directory|700|0|0|4096", "readable by the Alertmanager user"),
        (r"alertmanager\.yml:/probe/f:ro'", "f|regular file|664|0|0|200", "writable"),
        (r"alertmanager\.yml:/probe/f:ro'", "f|regular file|644|1000|1000|200", "owned by root"),
    ],
)
def test_permission_matrix_fails_closed(pattern: str, line: str, msg: str) -> None:
    table = [(pattern, line)] + _base_table()
    if "readable by the Alertmanager user" in msg:
        table = [
            (r"--user 65534:65534 .* -v '/opt/nlw/alertmanager\.secrets:/probe:ro'", "slack.url X")
        ] + table
    with pytest.raises(GateError, match=msg):
        _rollout_op(FakeRemote(table)).preflight()


def test_inline_credential_and_foreign_credential_paths_are_refused() -> None:
    inline = "route:\n  receiver: s\nreceivers:\n  - name: s\n    slack_configs:\n      - api_url: https://hooks.example.invalid/x\n"
    with pytest.raises(GateError, match="inline credential"):
        _rollout_op(FakeRemote(_operator_table(cfg=inline) + _base_table())).preflight()
    outside = OPERATOR_CFG.replace(
        "/etc/alertmanager/secrets/slack.url", "/etc/alertmanager/alertmanager.yml"
    )
    with pytest.raises(GateError, match="secrets mount"):
        _rollout_op(FakeRemote(_operator_table(cfg=outside) + _base_table())).preflight()
    # Operator config placed INSIDE a release checkout is not operator authority.
    inside = replace(OPERATOR, config_path=f"{STAGED}/docker/alertmanager/alertmanager.yml")
    with pytest.raises(GateError, match="release"):
        _rollout_op(
            FakeRemote(_base_table()), target=replace(TGT, operator_alerting=inside)
        ).preflight()


# J.9 — the second rollout follows <ops_root>/current and expects the live revision.
def test_second_rollout_follows_current_and_expects_the_live_revision() -> None:
    from nlw.ops.rollout.remote import parse_target_env

    tgt = parse_target_env(
        (Path(__file__).resolve().parents[2] / "deploy/staging/target.env").read_text()
    )
    assert tgt["NLW_STAGING_REMOTE_APP"] == "/opt/nlw/current"
    assert tgt["NLW_STAGING_CURRENT_REVISION"] == "0024_dataset_lifecycle"
    assert (
        tgt["NLW_STAGING_COMPOSE_PROJECT"] == "app"
        and tgt["NLW_STAGING_INSTANCE_ID"] == "i-0d1e65cdc9401dbb9"
    )
    assert all(
        k in tgt
        for k in (
            "NLW_STAGING_ALERTMANAGER_CONFIG",
            "NLW_STAGING_ALERTMANAGER_SECRETS_DIR",
            "NLW_STAGING_COMPOSE_OVERRIDE",
        )
    )
    assert not re.search(
        r"(?i)(password|secret_key|token|hooks\.slack)",
        "\n".join(f"{k}={v}" for k, v in tgt.items()),
    )
    # current -> the PREVIOUS release is the normal N state: preflight passes and reads the
    # active checkout through current; pins/sha/env all come from the active release.
    cur = [
        (r"if \[ -L '/opt/nlw/current' \]; then readlink", PREVIOUS),
        (r"grep -E '\^\(NLW_IMAGE.*'/opt/nlw/current/\.env\.prod'", PINS_ACTIVE),
        (r"git -C '/opt/nlw/current' rev-parse HEAD", OLD_SHA),
    ]
    fake = FakeRemote(cur + _base_table())
    report = _rollout_op(fake, target=TGT_CURRENT).preflight()
    assert report["current_link"] == "PREVIOUS_RELEASE" and report["active_checkout"] == OLD_SHA
    assert not fake.ran(r"/opt/nlw/app")
    # stage-release clones from current and fetches the release from the reviewed git remote.
    stage = (
        cur
        + [
            (r"sha256sum '/opt/nlw/current/\.env\.prod'", "abc"),
            (r"git clone -q '/opt/nlw/current'", ""),
            (r"git -C .* fetch -q 'https://github\.com/o/r\.git'", ""),
            (r"checkout -q --detach", ""),
            (r"grep -Ev .* > '.*releases.*\.env\.prod\.tmp'", ""),
            (r"docker/worker\.secrets\.env", "staged"),
            (r"config >/dev/null", ""),
            (r"--profile backup build -q backup", ""),
            (
                r"ctxkeys fingerprint",
                FPS_LINES,
            ),
        ]
        + _base_table()
    )
    fake2 = FakeRemote(stage, state=_done("verify-release", "verify-escrow"))
    _rollout_op(fake2, target=TGT_CURRENT, authorization=AUTHORIZATION_PHRASE).stage_release(
        keys_dir=KEYS
    )
    assert fake2.ran(r"git clone -q '/opt/nlw/current' '/opt/nlw/releases/")
    assert fake2.ran(r"fetch -q 'https://github\.com/o/r\.git'")
    assert fake2.ran(r"grep -Ev .* '/opt/nlw/current/\.env\.prod' > ")
    assert fake2.ran(r"cp '/opt/nlw/current/docker/worker\.secrets\.env'")
    assert not fake2.ran(r"/opt/nlw/app")
    # A legacy layout under a follows-current target is a configuration error, not a rollout.
    legacy = FakeRemote(
        [(r"if \[ -L '/opt/nlw/current' \]; then readlink", "ABSENT")] + cur[1:] + _base_table()
    )
    with pytest.raises(GateError, match="no activated release"):
        _rollout_op(legacy, target=TGT_CURRENT).preflight()
    # And the reverse: a legacy target on a host that already has an activated release.
    act = FakeRemote(
        [(r"if \[ -L '/opt/nlw/current' \]; then readlink", PREVIOUS)]
        + _base_table()
        + _operator_table()
    )
    with pytest.raises(GateError, match="NLW_STAGING_REMOTE_APP=/opt/nlw/current"):
        _rollout_op(act).preflight()


def test_code_only_release_migrates_as_a_verified_noop() -> None:
    """expected == target (no new migration): migrate still runs `alembic upgrade
    head` through the staged one-shot, verifies the revision and records the
    phase; a database at another revision is refused exactly as before."""
    same = replace(REL, expected_current_revision="0016_signed_database_context")
    table = _base_table(roles=ROLES_ALL, rev="0016_signed_database_context") + [
        (r"--profile migration run --rm --no-deps -T  migrate $", ""),
        (r"FROM pg_policies", "61|0"),
        (r"tablename=", "nlw_ctx_verifier"),
        (r"proname=.*create_workspace_for_current_user", "1|t"),
        (r"has_table_privilege", "f"),
    ]
    fake = FakeRemote(table, state=_done("verify-backup", "drain", "prepare-roles"))
    r = Rollout(
        release=same,
        target=TGT,
        remote=fake,
        operator=Operator(authorization=AUTHORIZATION_PHRASE),
        log=lambda _m: None,
        now=lambda: NOW,
        receipt=RECEIPT,
    )
    r.migrate()
    assert (
        fake.ran(r"--profile migration run --rm --no-deps -T  migrate")
        and "migrate" in fake.state_doc["phases"]
    )
    behind = FakeRemote(
        _base_table(roles=ROLES_ALL, rev="0015_membership_approval_sod"),
        state=_done("verify-backup", "drain", "prepare-roles"),
    )
    r2 = Rollout(
        release=same,
        target=TGT,
        remote=behind,
        operator=Operator(authorization=AUTHORIZATION_PHRASE),
        log=lambda _m: None,
        now=lambda: NOW,
        receipt=RECEIPT,
    )
    with pytest.raises(GateError, match="unknown migration state"):
        r2.migrate()
    assert not behind.ran(r"--profile migration run")


def test_prepare_keys_reuses_existing_host_keys_on_a_follow_up_release() -> None:
    """N+1 keeps the installed keys: prepare-keys must verify + fingerprint the
    existing files instead of refusing (`ctxkeys prepare` never overwrites)."""
    table: Table = [
        (r"ctxkeys prepare", 1),  # would refuse: the files exist
        (r"--entrypoint stat .* '/keys/\.'", ".|directory|700|0|0|4096"),
        (
            r"--entrypoint stat .* '/keys/(api|worker|scheduler)\.key'",
            "api.key|regular file|400|10001|10001|65",
        ),
        (
            r"ctxkeys fingerprint",
            FPS_LINES,
        ),
        *_base_table(),
    ]
    fake = FakeRemote(table, state=_done("verify-release"))
    _rollout_op(fake, target=TGT_CURRENT, authorization=AUTHORIZATION_PHRASE).prepare_keys(
        keys_dir=KEYS
    )
    assert not fake.ran(r"ctxkeys prepare")
    ev = fake.state_doc["evidence"]["prepare-keys"]
    assert ev["reused_existing"] is True and set(ev["fingerprints"]) == {
        "api",
        "worker",
        "scheduler",
    }
    # A PARTIAL set is never silently completed.
    partial: Table = [
        (r"--entrypoint stat .* '/keys/scheduler\.key'", 1),
        *table,
    ]
    with pytest.raises(GateError, match="partial"):
        _rollout_op(
            FakeRemote(partial, state=_done("verify-release")),
            target=TGT_CURRENT,
            authorization=AUTHORIZATION_PHRASE,
        ).prepare_keys(keys_dir=KEYS)


# --- public edge: reviewed primary (manifest) + sslip fallback (target) -----------
EDGE_PRIMARY = "app.nlwplatform.com"
EDGE_FALLBACK = "32-197-83-193.sslip.io"
EDGE_IP = "32.197.83.193"
REL_EDGE_DOC = {**REL_DOC, "public_hostname": EDGE_PRIMARY}
REL_EDGE_RAW = json.dumps(REL_EDGE_DOC, indent=2, sort_keys=True) + "\n"
REL_EDGE = replace(
    rm.parse_manifest(REL_EDGE_DOC, raw_bytes=REL_EDGE_RAW.encode()),
    raw=REL_EDGE_RAW,
    source_path="release-manifest.json",
)
TGT_EDGE = replace(TGT, public_hostname=EDGE_PRIMARY, public_hostname_fallback=EDGE_FALLBACK)
PINS_STAGED_EDGE = PINS_STAGED.replace(
    "PUBLIC_HOSTNAME=32-197-83-193.sslip.io\n", f"PUBLIC_HOSTNAME={EDGE_PRIMARY}\n"
).replace("PUBLIC_HOSTNAME_FALLBACK=\n", f"PUBLIC_HOSTNAME_FALLBACK={EDGE_FALLBACK}\n")


def _rendered_edge(**caddy_env: str) -> str:
    doc = json.loads(RENDERED_AM)
    doc["services"]["caddy"]["environment"] = {
        "PUBLIC_HOSTNAME": EDGE_PRIMARY,
        "PUBLIC_HOSTNAME_FALLBACK": EDGE_FALLBACK,
        **caddy_env,
    }
    return json.dumps(doc)


def _edge_first(*extra: tuple[str, Response], pins: str = PINS_STAGED_EDGE) -> Table:
    """Scripted responses for a correctly wired custom-domain edge; ``extra``
    entries are matched FIRST (a test's deviation from the good edge)."""
    return [
        *extra,
        (r"config --format json", _rendered_edge()),
        (r"grep -E '\^\(NLW_IMAGE.*releases", pins),
        *_edge_table(EDGE_PRIMARY, EDGE_FALLBACK),
    ]


def _done_edge(*phases: str) -> dict[str, Any]:
    doc = _done(*phases)
    doc["manifest_sha256"] = REL_EDGE.sha256
    if "stage-release" in doc["evidence"]:
        doc["evidence"]["stage-release"].update(
            public_hostname=EDGE_PRIMARY, public_hostname_fallback=EDGE_FALLBACK
        )
    return doc


def _edge_rollout(
    fake: FakeRemote,
    *,
    target: TargetConfig = TGT_EDGE,
    resolve: Any = lambda _h: {EDGE_IP},
    **op: object,
) -> Rollout:
    return Rollout(
        release=REL_EDGE,
        target=target,
        remote=fake,
        operator=Operator(**op),  # type: ignore[arg-type]
        log=lambda _m: None,
        now=lambda: NOW,
        receipt=RECEIPT,
        resolve=resolve,
    )


def _no_mutation(fake: FakeRemote) -> bool:
    return not any(ACTIVE_MUTATION.search(c) or DB_MUTATION.search(c) for c in fake.commands)


def test_edge_preflight_binds_primary_dns_and_accepts_the_active_fallback() -> None:
    fake = FakeRemote(_edge_first() + _base_table())
    report = _edge_rollout(fake).preflight()
    assert report["edge"] == {
        "primary": EDGE_PRIMARY,
        "fallback": EDGE_FALLBACK,
        "primary_a_records": [EDGE_IP],
        "active_hostname": "32-197-83-193.sslip.io",  # the sslip-only release being replaced
    }
    assert _no_mutation(fake)


@pytest.mark.parametrize(
    "resolved,msg",
    [(set(), "no IPv4 A record"), ({"104.16.0.1"}, "not this instance")],
)
def test_edge_preflight_refuses_missing_or_foreign_dns(resolved: set[str], msg: str) -> None:
    fake = FakeRemote(_edge_first() + _base_table())
    with pytest.raises(GateError, match=msg):
        _edge_rollout(fake, resolve=lambda _h: resolved).preflight()
    assert _no_mutation(fake)


def test_edge_identity_refuses_a_fallback_that_no_longer_encodes_the_instance() -> None:
    imds = "instance-id=i-0d1e65cdc9401dbb9\nplacement/region=us-east-1\npublic-ipv4=3.3.3.3\n"
    fake = FakeRemote(_edge_first((r"169\.254\.169\.254", imds)) + _base_table())
    with pytest.raises(GateError, match="does not encode the instance public IPv4"):
        _edge_rollout(fake, resolve=lambda _h: {"3.3.3.3"}).preflight()


def test_edge_identity_refuses_a_target_primary_that_differs_from_the_manifest() -> None:
    fake = FakeRemote(_edge_first() + _base_table())
    target = replace(TGT_EDGE, public_hostname="other.nlwplatform.com")
    with pytest.raises(GateError, match="differs from the attested release"):
        _edge_rollout(fake, target=target).preflight()


def test_edge_preflight_refuses_an_unknown_active_hostname() -> None:
    active = PINS_ACTIVE.replace("PUBLIC_HOSTNAME=32-197-83-193.sslip.io", "PUBLIC_HOSTNAME=x.io")
    fake = FakeRemote(
        _edge_first((r"grep -E '\^\(NLW_IMAGE.*'/opt/nlw/app/\.env\.prod'", active)) + _base_table()
    )
    with pytest.raises(GateError, match="unknown edge state"):
        _edge_rollout(fake).preflight()


def test_edge_stage_release_writes_canonical_values_and_validates_the_caddyfile() -> None:
    fake = FakeRemote(
        _edge_first() + _pre_backup_table(), state=_done_edge("verify-release", "verify-escrow")
    )
    _edge_rollout(fake, authorization=AUTHORIZATION_PHRASE).stage_release(keys_dir=KEYS)
    tmp = rf">> '{STAGED}/\.env\.prod\.tmp'"
    assert fake.ran(rf"'PUBLIC_HOSTNAME' '{re.escape(EDGE_PRIMARY)}' {tmp}")
    assert fake.ran(rf"'PUBLIC_HOSTNAME_FALLBACK' '{re.escape(EDGE_FALLBACK)}' {tmp}")
    evidence = fake.state_doc["evidence"]["stage-release"]
    assert evidence["public_hostname"] == EDGE_PRIMARY
    assert evidence["public_hostname_fallback"] == EDGE_FALLBACK
    assert fake.ran(r"caddy validate --config") and fake.ran(r"caddy adapt --config")
    assert fake.ran(r"--network none -e PUBLIC_HOSTNAME=app\.nlwplatform\.com")
    assert _no_mutation(fake)


@pytest.mark.parametrize(
    "active_lines",
    [
        "",
        "PUBLIC_HOSTNAME=32-197-83-193.sslip.io\n",
        "PUBLIC_HOSTNAME=evil.example\nexport PUBLIC_HOSTNAME_FALLBACK=1-2-3-4.sslip.io\n",
        " PUBLIC_HOSTNAME = evil.example\nPUBLIC_HOSTNAME_FALLBACK=\nPUBLIC_HOSTNAME_FALLBACK=x\n",
    ],
)
def test_edge_staged_env_never_inherits_hostnames_from_the_active_release(
    tmp_path: Path, active_lines: str
) -> None:
    active = tmp_path / "active"
    active.mkdir()
    target = replace(TGT_EDGE, remote_app=str(active), ops_root=str(tmp_path))
    staged = Path(target.release_dir(SHA))
    staged.mkdir(parents=True)
    original = f"# active\nUNRELATED_SETTING=kept\n{active_lines}".encode()
    (active / ".env.prod").write_bytes(original)
    rollout = Rollout(
        release=REL_EDGE, target=target, remote=LocalRemote(), operator=Operator(), log=print
    )
    rollout._write_staged_env(keys_dir=KEYS)
    assert (active / ".env.prod").read_bytes() == original  # active stays byte-identical
    text = (staged / ".env.prod").read_text()
    edge = [ln for ln in text.splitlines() if "PUBLIC_HOSTNAME" in ln]
    assert edge == [f"PUBLIC_HOSTNAME={EDGE_PRIMARY}", f"PUBLIC_HOSTNAME_FALLBACK={EDGE_FALLBACK}"]
    assert "UNRELATED_SETTING=kept" in text
    pins = rollout.read_pins(str(staged))  # the gate's own reader accepts the result
    assert pins["PUBLIC_HOSTNAME"] == EDGE_PRIMARY


@pytest.mark.parametrize("phase", [*PHASES[PHASES.index("stage-release") + 1 :], "go-check"])
@pytest.mark.parametrize(
    "change",
    [
        "target-fallback",
        "target-no-fallback",
        "staged-file",
        "recorded-fallback",
        "recorded-primary",
    ],
)
def test_edge_every_later_phase_refuses_reviewed_state_or_file_drift(
    phase: str, change: str
) -> None:
    doc = _done_edge(*PHASES[1:])
    target, pins = TGT_EDGE, PINS_STAGED_EDGE
    if change == "target-fallback":
        target = replace(TGT_EDGE, public_hostname_fallback="1-2-3-4.sslip.io")
    elif change == "target-no-fallback":
        target = replace(TGT_EDGE, public_hostname_fallback=None)
    elif change == "staged-file":
        pins = pins.replace(EDGE_FALLBACK, "1-2-3-4.sslip.io")
    elif change == "recorded-fallback":
        doc["evidence"]["stage-release"]["public_hostname_fallback"] = "1-2-3-4.sslip.io"
    else:
        doc["evidence"]["stage-release"]["public_hostname"] = "old.nlwplatform.com"
    fake = FakeRemote(_edge_first(pins=pins) + _activation_table(), state=doc)
    r = _edge_rollout(fake, target=target, authorization=AUTHORIZATION_PHRASE)
    call = r.go_check if phase == "go-check" else _all_phase_calls(r)[phase]
    with pytest.raises(GateError, match="re-run stage-release"):
        call()
    assert _no_mutation(fake)


def test_edge_restaging_records_the_new_reviewed_values_and_resets_activation() -> None:
    doc = _done_edge(*PHASES[1:])
    doc["evidence"]["stage-release"]["public_hostname_fallback"] = "1-2-3-4.sslip.io"
    fake = FakeRemote(_edge_first() + _pre_backup_table(), state=doc)
    _edge_rollout(fake, authorization=AUTHORIZATION_PHRASE).stage_release(keys_dir=KEYS)
    assert fake.state_doc["evidence"]["stage-release"]["public_hostname_fallback"] == EDGE_FALLBACK
    assert not ({"recreate-runtime", "validate", "reopen"} & fake.state_doc["phases"].keys())


_DRAIN_EXTRA: Table = [
    (r"up -d --no-deps --force-recreate caddy", ""),
    (r"exec -T caddy touch", ""),
    (r"\bstop scheduler\b", ""),
    (r"\bstop worker api\b", ""),
    (r"^sleep", ""),
]
_BACKED_UP = ("verify-release", "prepare-keys", "verify-escrow", "stage-release", "backup")


@pytest.mark.parametrize(
    "deviation,msg",
    [
        ((r"config --format json", _rendered_edge(PUBLIC_HOSTNAME="evil.example")), "scope"),
        (
            (
                r"config --format json",
                json.dumps(
                    {
                        **json.loads(_rendered_edge()),
                        "services": {
                            **json.loads(_rendered_edge())["services"],
                            "web": {"environment": {"PUBLIC_HOSTNAME_FALLBACK": EDGE_FALLBACK}},
                        },
                    }
                ),
            ),
            "scope",
        ),
        (
            (r"config --format json", _rendered_edge().replace(CADDYFILE_SRC, "/tmp/Caddyfile")),
            "does not mount this release",
        ),
        ((r"caddy validate --config", 1), "does not validate"),
        ((r"caddy adapt --config", _adapted(EDGE_PRIMARY, EDGE_FALLBACK, "x.io")), "!= reviewed"),
        ((r"caddy adapt --config", _adapted(EDGE_PRIMARY)), "!= reviewed"),
    ],
)
def test_edge_drain_refuses_an_unreviewed_edge_before_touching_caddy(
    deviation: tuple[str, Response], msg: str
) -> None:
    fake = FakeRemote(
        _edge_first(deviation) + _base_table() + _DRAIN_EXTRA,
        state=_done_edge(*_BACKED_UP, "verify-backup"),
    )
    with pytest.raises(GateError, match=msg):
        _edge_rollout(fake, authorization=AUTHORIZATION_PHRASE).drain()
    assert not fake.ran(r"up -d|touch /srv/maint|stop scheduler")


def test_edge_drain_refuses_primary_dns_drift_before_touching_caddy() -> None:
    fake = FakeRemote(
        _edge_first() + _base_table() + _DRAIN_EXTRA,
        state=_done_edge(*_BACKED_UP, "verify-backup"),
    )
    with pytest.raises(GateError, match="not this instance"):
        _edge_rollout(
            fake, resolve=lambda _h: {"104.16.0.1"}, authorization=AUTHORIZATION_PHRASE
        ).drain()
    assert not fake.ran(r"up -d|touch /srv/maint|stop scheduler")


def test_edge_drain_verifies_both_hostnames_before_closing_traffic() -> None:
    fake = FakeRemote(
        _edge_first() + _base_table() + _DRAIN_EXTRA,
        state=_done_edge(*_BACKED_UP, "verify-backup"),
    )
    _edge_rollout(fake, authorization=AUTHORIZATION_PHRASE).drain()
    probes = [c for c in fake.commands if "curl -sk" in c]
    for host in (EDGE_PRIMARY, EDGE_FALLBACK):
        assert any(f"--resolve '{host}:443:127.0.0.1'" in c and "/login'" in c for c in probes)
        assert any(f"'https://{host}:443/metrics'" in c for c in probes)
    first_probe = next(i for i, c in enumerate(fake.commands) if "curl -sk" in c)
    touch = next(i for i, c in enumerate(fake.commands) if "touch /srv/maint" in c)
    assert first_probe < touch  # proven while the old runtime still serves


def test_edge_drain_stops_before_closing_traffic_when_a_hostname_does_not_answer() -> None:
    def fallback_down(fake: FakeRemote, command: str) -> str:
        return "000" if EDGE_FALLBACK in command else _edge_http(fake, command)

    fake = FakeRemote(
        _edge_first((r"curl -sk -o /dev/null .*--resolve", fallback_down))
        + _base_table()
        + _DRAIN_EXTRA,
        state=_done_edge(*_BACKED_UP, "verify-backup"),
    )
    with pytest.raises(GateError, match="edge route behavior mismatch"):
        _edge_rollout(fake, authorization=AUTHORIZATION_PHRASE).drain()
    assert fake.ran(r"up -d --no-deps --force-recreate caddy")
    assert not fake.ran(r"touch /srv/maint|stop scheduler|stop worker")
    assert "drain" not in fake.state_doc["phases"]


_UNTIL = {
    "recreate-runtime": "install-context-keys",
    "validate": "recreate-runtime",
    "reopen": "validate",
    "go-check": "reopen",
}


@pytest.mark.parametrize("phase", list(_UNTIL))
@pytest.mark.parametrize(
    "running",
    [
        "NOT_RUNNING",
        f"PUBLIC_HOSTNAME={EDGE_PRIMARY}\nMOUNT={CADDYFILE_SRC}:false",
        f"PUBLIC_HOSTNAME={EDGE_PRIMARY}\nPUBLIC_HOSTNAME_FALLBACK=1-2-3-4.sslip.io\n"
        f"MOUNT={CADDYFILE_SRC}:false",
        f"PUBLIC_HOSTNAME={EDGE_PRIMARY}\nPUBLIC_HOSTNAME_FALLBACK={EDGE_FALLBACK}\n"
        "MOUNT=/opt/nlw/releases/old/docker/caddy/Caddyfile:false",
        f"PUBLIC_HOSTNAME={EDGE_PRIMARY}\nPUBLIC_HOSTNAME_FALLBACK={EDGE_FALLBACK}\n"
        f"MOUNT={CADDYFILE_SRC}:true",
    ],
)
def test_edge_running_mismatch_blocks_activation_validate_reopen_and_go_check(
    phase: str, running: str
) -> None:
    upto = PHASES[: PHASES.index(_UNTIL[phase]) + 1][1:]
    fake = FakeRemote(
        _edge_first((r"docker inspect --format .*PUBLIC_HOSTNAME=.*ps -q caddy", running))
        + _activation_table()
        + _reopen_table()
        + [(r"exec -T caddy touch", "")],
        state=_done_edge(*upto),
    )
    r = _edge_rollout(fake, authorization=AUTHORIZATION_PHRASE)
    call = r.go_check if phase == "go-check" else _all_phase_calls(r)[phase]
    with pytest.raises(GateError, match="keep traffic closed"):
        call()
    assert not fake.ran(r"rm -f /srv/maint/MAINTENANCE")  # traffic never reopened
    assert phase not in fake.state_doc["phases"] or phase == "go-check"
    probe = next(c for c in fake.commands if "ps -q caddy" in c and "docker inspect" in c)
    assert "{{json .Config.Env}}" not in probe and "{{println .}}{{end}}{{end}}" not in probe[:40]


def test_edge_reopen_proves_both_hostnames_and_recloses_when_opening_fails() -> None:
    fake = FakeRemote(
        _edge_first() + _reopen_table() + [(r"exec -T caddy touch", "")],
        state=_done_edge("validate"),
    )
    _edge_rollout(fake, authorization=AUTHORIZATION_PHRASE).reopen()
    assert fake.state_doc["evidence"]["reopen"]["edge_hosts"] == sorted(
        [EDGE_PRIMARY, EDGE_FALLBACK]
    )

    def broken_when_open(fake: FakeRemote, command: str) -> str:
        return "503" if _maintenance_on(fake) else "502"

    fake2 = FakeRemote(
        _edge_first((r"curl -sk -o /dev/null .*--resolve", broken_when_open))
        + _reopen_table()
        + [(r"exec -T caddy touch", "")],
        state=_done_edge("validate"),
    )
    with pytest.raises(GateError, match="edge route behavior mismatch"):
        _edge_rollout(fake2, authorization=AUTHORIZATION_PHRASE).reopen()
    removed = next(i for i, c in enumerate(fake2.commands) if "rm -f /srv/maint" in c)
    assert any("touch /srv/maint" in c for c in fake2.commands[removed:])  # closed again
    assert "reopen" not in fake2.state_doc["phases"]


def test_edge_go_check_proves_both_hostnames_serve_the_open_routes() -> None:
    good = json.dumps(
        {
            "receiver": "ops-slack",
            "delivered_at": (NOW - timedelta(hours=2)).isoformat(),
            "confirmed_by": "ops-lead",
        }
    )
    fake = FakeRemote(
        _edge_first() + _reopen_table(record="__OK__\n" + good), state=_done_edge(*PHASES[1:])
    )
    _edge_rollout(fake).go_check()
    codes = {c.split("'https://")[1].split("'")[0] for c in fake.commands if "curl -sk" in c}
    assert codes == {
        f"{h}:443{p}" for h in (EDGE_PRIMARY, EDGE_FALLBACK) for p in ("/login", "/metrics")
    }


def test_edge_state_evidence_carries_hostnames_but_no_secret() -> None:
    fake = FakeRemote(
        _edge_first() + _pre_backup_table(), state=_done_edge("verify-release", "verify-escrow")
    )
    _edge_rollout(fake, authorization=AUTHORIZATION_PHRASE).stage_release(keys_dir=KEYS)
    blob = json.dumps(fake.state_doc)
    assert EDGE_PRIMARY in blob and EDGE_FALLBACK in blob
    for needle in ("password", "secret", "token", "://"):
        assert needle not in blob


def test_edge_rendered_mount_compares_cleaned_paths_without_widening() -> None:
    # Reproduced in the disposable rehearsal: TMPDIR ends in '/', so the staged path
    # holds '//'; Compose renders the CLEANED path. Equal after normalization only.
    target = replace(TGT_EDGE, ops_root="/opt/nlw/")
    fake = FakeRemote(_edge_first() + _base_table())
    r = _edge_rollout(fake, target=target)
    assert "//releases/" in r.staged
    r.check_rendered_edge()
    moved = _rendered_edge().replace(
        CADDYFILE_SRC, "/opt/nlw/releases/other/docker/caddy/Caddyfile"
    )
    fake2 = FakeRemote(_edge_first((r"config --format json", moved)) + _base_table())
    with pytest.raises(GateError, match="does not mount this release"):
        _edge_rollout(fake2, target=target).check_rendered_edge()


def test_migrate_refuses_an_ungated_workspace_bootstrap() -> None:
    """Phase 2 B01: after `alembic upgrade head` the live bootstrap must enforce
    creation grants; a host still running the ungated body is NO-GO."""
    same = replace(REL, expected_current_revision="0016_signed_database_context")
    table = _base_table(roles=ROLES_ALL, rev="0016_signed_database_context") + [
        (r"--profile migration run --rm --no-deps -T  migrate $", ""),
        (r"FROM pg_policies", "61|0"),
        (r"tablename=", "nlw_ctx_verifier"),
        (r"proname=.*create_workspace_for_current_user", "1|f"),
        (r"has_table_privilege", "f"),
    ]
    r = Rollout(
        release=same,
        target=TGT,
        remote=FakeRemote(table, state=_done("verify-backup", "drain", "prepare-roles")),
        operator=Operator(authorization=AUTHORIZATION_PHRASE),
        log=lambda _m: None,
        now=lambda: NOW,
        receipt=RECEIPT,
    )
    with pytest.raises(GateError, match="does not enforce creation grants"):
        r.migrate()
