"""The rollout state machine drives a SCRIPTED remote (M12A-Prep §C/§H; tests
O.1, O.5, O.11, O.14, O.15, O.16). No host, no Docker: every command the
orchestrator issues is matched against canned responses, so the tests prove
WHICH commands run (and which never run) under each gate.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from nlw.ops.rollout.gates import AUTHORIZATION_PHRASE, ESCROW_PHRASE, GateError
from nlw.ops.rollout.phases import Operator, Rollout, RolloutStop
from nlw.ops.rollout.release import parse_release
from nlw.ops.rollout.remote import CommandResult, TargetConfig
from nlw.ops.rollout.state import StateError

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
D = "sha256:" + "a" * 64
W = "sha256:" + "b" * 64
REL = parse_release(
    {
        "format_version": 1,
        "environment": "staging",
        "release_sha": "1eebf2ef19c0286c83bfe8768c908bfd2f40178d",
        "backend_image": f"ghcr.io/o/r@{D}",
        "web_image": f"ghcr.io/o/r/web@{W}",
        "expected_current_revision": "0010_readiness_schema_grant",
        "target_revision": "0016_signed_database_context",
        "instance_id": "i-0d1e65cdc9401dbb9",
        "region": "us-east-1",
        "compose_project": "app",
        "public_hostname": "32-197-83-193.sslip.io",
        "key_ids": {"api": "stg-api-1", "worker": "stg-worker-1", "scheduler": "stg-sched-1"},
    }
)
TGT = TargetConfig(
    instance_id=REL.instance_id,
    ssh_host="32.197.83.193",
    ssh_user="nlwops",
    ssh_key=Path("/dev/null"),
    remote_app="/opt/nlw/app",
    compose_project="app",
)
IMDS = "instance-id=i-0d1e65cdc9401dbb9\nplacement/region=us-east-1\npublic-ipv4=32.197.83.193\n"
ROLES_M11 = (
    "nlw_app:tff\nnlw_worker:tff\nnlw_scheduler:tff\n"
    "nlw_rls_bypass:fft\nnlw_workspace_bootstrap:fft\n"
)
ROLES_ALL = ROLES_M11 + "nlw_membership_admin:fft\nnlw_ctx_verifier:fff\n"
PINS_PRE = (
    "NLW_IMAGE=ghcr.io/o/r@sha256:"
    + "f" * 64
    + "\nNLW_WEB_IMAGE=ghcr.io/o/r/web@"
    + W
    + "\nPUBLIC_HOSTNAME=32-197-83-193.sslip.io\n"
)
PINS_POST = (
    f"NLW_IMAGE={REL.backend_image}\nNLW_WEB_IMAGE={REL.web_image}\nPUBLIC_HOSTNAME=32-197-83-193.sslip.io\n"
    "NLW_CTX_KEYS_DIR=/srv/nlw/ctx-keys\nNLW_CTX_API_KEY_ID=stg-api-1\n"
    "NLW_CTX_WORKER_KEY_ID=stg-worker-1\nNLW_CTX_SCHEDULER_KEY_ID=stg-sched-1\n"
)


class FakeRemote:
    """Pattern -> response table; records every command. Unmatched commands fail
    loudly so a phase cannot silently do something the test did not script."""

    def __init__(
        self, table: list[tuple[str, str | int]], state: dict[str, Any] | None = None
    ) -> None:
        self.table = table
        self.commands: list[str] = []
        self.state_doc: dict[str, Any] = state or {"phases": {}, "evidence": {}}

    def describe(self) -> str:
        return "fake"

    def run(self, command: str, *, stdin: str | None = None, timeout: int = 300) -> CommandResult:
        self.commands.append(command)
        if ".rollout/" in command and "cat >" in command:
            assert stdin is not None
            self.state_doc = json.loads(stdin)
            return CommandResult(0, "", "")
        if command.startswith("cat '/opt/nlw/app/.rollout/"):
            return CommandResult(0, json.dumps(self.state_doc), "")
        for pattern, response in self.table:
            if re.search(pattern, command):
                if isinstance(response, int):
                    return CommandResult(response, "", "scripted failure")
                return CommandResult(0, response, "")
        raise AssertionError(f"unscripted command: {command[:160]}")

    def ran(self, pattern: str) -> bool:
        return any(re.search(pattern, c) for c in self.commands)


def _base_table(
    *, roles: str = ROLES_M11, pins: str = PINS_PRE, rev: str = "0010_readiness_schema_grant"
) -> list[tuple[str, str | int]]:
    return [
        (r"169\.254\.169\.254", IMDS),
        (r"grep -E '\^\(NLW_IMAGE", pins),
        (r"alembic_version", rev),
        (r"pg_roles WHERE rolname", roles),
        (r"FROM workflow_runs WHERE status IN", "0|0|0"),
        (r"redis-cli llen", "0"),
        (r"pg_stat_activity", "0"),
        (r"git -C '/opt/nlw/app' rev-parse HEAD", REL.release_sha),
        (r"git -C '/opt/nlw/app' status --porcelain", ""),
        (r"config --services", "api\nworker\nscheduler\nweb\ncaddy\nprometheus\nalertmanager"),
    ]


def _rollout(remote: FakeRemote, **op: object) -> Rollout:
    return Rollout(
        release=REL,
        target=TGT,
        remote=remote,
        operator=Operator(**op),  # type: ignore[arg-type]
        log=lambda _m: None,
        now=lambda: NOW,
    )


MUTATING = (
    r"\bup -d\b|\bstop\b|--profile migration run|alembic (up|down)grade|ctxkeys install|"
    r"ctxkeys prepare|sed -i|>> |touch |rm -f|\bpull\b"
)


# --- O.1 default invocation is read-only ---------------------------------------
def test_preflight_is_read_only_and_needs_no_authorization() -> None:
    fake = FakeRemote(_base_table())
    report = _rollout(fake).preflight()
    assert report["current_revision"] == "0010_readiness_schema_grant"
    assert report["pinned_to_release"] is False
    assert not any(re.search(MUTATING, c) for c in fake.commands), fake.commands


def test_preflight_stops_on_wrong_instance_before_reading_anything_else() -> None:
    fake = FakeRemote(
        [(r"169\.254\.169\.254", IMDS.replace("i-0d1e65cdc9401dbb9", "i-0000000000000001"))]
    )
    with pytest.raises(GateError, match="instance"):
        _rollout(fake).preflight()
    assert len(fake.commands) == 1


# --- O.5 every mutating phase requires the exact phrase ------------------------
@pytest.mark.parametrize("auth", [None, "", "yes", "AUTHORIZE_M12A"])
def test_mutating_phases_refuse_without_exact_authorization(auth: str | None) -> None:
    fake = FakeRemote(_base_table())
    r = _rollout(fake, authorization=auth)
    for call in (
        r.prepare_roles,
        lambda: r.prepare_keys(keys_dir="/srv/nlw/ctx-keys"),
        lambda: r.verify_escrow(keys_dir="/srv/nlw/ctx-keys"),
        r.verify_backup,
        r.drain,
        lambda: r.migrate(keys_dir="/srv/nlw/ctx-keys"),
        lambda: r.install_context_keys(keys_dir="/srv/nlw/ctx-keys"),
        lambda: r.recreate_runtime(keys_dir="/srv/nlw/ctx-keys"),
        lambda: r.validate(keys_dir="/srv/nlw/ctx-keys"),
        r.reopen,
    ):
        with pytest.raises(GateError, match="authorization"):
            call()
    assert fake.commands == []  # nothing was even read


def test_verify_escrow_requires_exact_escrow_phrase_and_attestation() -> None:
    fake = FakeRemote(_base_table(), state={"phases": {"prepare-keys": {}}, "evidence": {}})
    r = _rollout(fake, authorization=AUTHORIZATION_PHRASE, escrow_confirmation="yes")
    with pytest.raises(GateError, match="escrow confirmation"):
        r.verify_escrow(keys_dir="/srv/nlw/ctx-keys")
    r2 = _rollout(fake, authorization=AUTHORIZATION_PHRASE, escrow_confirmation=ESCROW_PHRASE)
    with pytest.raises(GateError, match="attestation file"):
        r2.verify_escrow(keys_dir="/srv/nlw/ctx-keys")


# --- phase ordering: each mutation requires the earlier evidence on THIS host --
def test_migrate_refuses_without_backup_escrow_and_drain_evidence() -> None:
    fake = FakeRemote(
        _base_table(roles=ROLES_ALL), state={"phases": {"prepare-roles": {}}, "evidence": {}}
    )
    r = _rollout(fake, authorization=AUTHORIZATION_PHRASE)
    with pytest.raises(StateError, match="verify-escrow"):
        r.migrate(keys_dir="/srv/nlw/ctx-keys")
    assert not fake.ran("alembic|--profile migration")


# --- O.11 runtime sessions block migration ------------------------------------
def test_open_runtime_sessions_block_migration() -> None:
    table = _base_table(roles=ROLES_ALL)
    table = [(p, ("3" if p == r"pg_stat_activity" else v)) for p, v in table]
    done: dict[str, Any] = {
        "phases": {
            p: {}
            for p in (
                "prepare-roles",
                "prepare-keys",
                "verify-escrow",
                "pin-release",
                "verify-backup",
                "drain",
            )
        },
        "evidence": {},
    }
    fake = FakeRemote(table, state=done)
    with pytest.raises(GateError, match="session"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).migrate(keys_dir="/srv/nlw/ctx-keys")
    assert not fake.ran("--profile migration run")


# --- drain: non-terminal work stops before runtimes are touched -------------
def test_drain_stops_on_non_terminal_work_and_never_stops_api() -> None:
    table = _base_table()
    table = [(p, ("2|0|0" if "workflow_runs" in p else v)) for p, v in table]
    table = [(p, (PINS_POST if "NLW_IMAGE" in p else v)) for p, v in table]
    table += [
        (r"up -d --no-deps --force-recreate caddy", ""),
        (r"exec -T caddy touch", ""),
        (r"\bstop scheduler\b", ""),
        (r"^sleep", ""),
    ]
    done: dict[str, Any] = {
        "phases": {"verify-escrow": {}, "pin-release": {}, "verify-backup": {}},
        "evidence": {},
    }
    fake = FakeRemote(table, state=done)
    with pytest.raises(GateError, match="non-terminal"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).drain()
    assert fake.ran(r"stop scheduler") and not fake.ran(r"stop worker api")


# --- O.14 partial key installation cannot start runtimes ----------------------
def test_partial_key_install_never_recreates_runtimes() -> None:
    table = _base_table(roles=ROLES_ALL, pins=PINS_POST, rev="0016_signed_database_context")
    table += [
        (r"ctxkeys install --class api", "installed: stg-api-1 (api)"),
        (r"ctxkeys install --class worker", "installed: stg-worker-1 (worker)"),
        (r"ctxkeys install --class scheduler", 1),  # third install FAILS
    ]
    done: dict[str, Any] = {"phases": {"migrate": {}}, "evidence": {}}
    fake = FakeRemote(table, state=done)
    r = _rollout(fake, authorization=AUTHORIZATION_PHRASE)
    with pytest.raises(RolloutStop):
        r.install_context_keys(keys_dir="/srv/nlw/ctx-keys")
    assert not fake.ran(r"up -d")
    # And recreate-runtime cannot be entered without the install phase recorded.
    with pytest.raises(StateError, match="install-context-keys"):
        r.recreate_runtime(keys_dir="/srv/nlw/ctx-keys")
    assert not fake.ran(r"up -d")


# --- O.15 old runtime cannot be (re)started after migration 0016 -------------
def test_recreate_runtime_rejects_old_image_and_pre_pin_env() -> None:
    old = "ghcr.io/o/r@sha256:" + "f" * 64
    table = _base_table(roles=ROLES_ALL, pins=PINS_POST, rev="0016_signed_database_context")
    table += [
        (r"config >/dev/null", ""),
        (r"up -d --force-recreate", ""),
        (
            r"index \.RepoDigests 0",
            f"api {old}\nworker {REL.backend_image}\n"
            f"scheduler {REL.backend_image}\nweb {REL.web_image}",
        ),
    ]
    done: dict[str, Any] = {"phases": {"install-context-keys": {}}, "evidence": {}}
    fake = FakeRemote(table, state=done)
    with pytest.raises(GateError, match="api is running"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).recreate_runtime(
            keys_dir="/srv/nlw/ctx-keys"
        )
    # Pre-pin .env.prod (old digests) is refused BEFORE any container is touched.
    fake2 = FakeRemote(
        _base_table(roles=ROLES_ALL, pins=PINS_PRE, rev="0016_signed_database_context"), state=done
    )
    with pytest.raises(GateError, match="digest"):
        _rollout(fake2, authorization=AUTHORIZATION_PHRASE).recreate_runtime(
            keys_dir="/srv/nlw/ctx-keys"
        )
    assert not fake2.ran(r"up -d")


# --- O.16 reopen requires signed-context readiness ------------------------------
def test_reopen_blocked_without_signed_context_readiness() -> None:
    table = _base_table() + [
        (
            r"curl -sS -m 5 http://127.0.0.1:8000/health/ready",
            '{"status":"ready","checks":{"postgres":"ok"}}',
        )
    ]
    fake = FakeRemote(table, state={"phases": {"validate": {}}, "evidence": {}})
    with pytest.raises(GateError, match="signed_context"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).reopen()
    assert not fake.ran(r"rm -f /srv/maint/MAINTENANCE")


def test_reopen_removes_maintenance_only_after_ready() -> None:
    table = _base_table() + [
        (
            r"curl -sS -m 5 http://127.0.0.1:8000/health/ready",
            '{"status":"ready","checks":{"signed_context":"ok","postgres":"ok"}}',
        ),
        (r"exec -T caddy rm -f /srv/maint/MAINTENANCE", ""),
    ]
    fake = FakeRemote(table, state={"phases": {"validate": {}}, "evidence": {}})
    _rollout(fake, authorization=AUTHORIZATION_PHRASE).reopen()
    assert fake.ran(r"rm -f /srv/maint/MAINTENANCE")
    assert "reopen" in fake.state_doc["phases"]


# --- backup gate inside the phase: fixture repository refused on a real target --
def test_verify_backup_refuses_fixture_repository_on_real_target() -> None:
    evidence = {
        "repository": "s3:http://minio:9000/nlwdrill",
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
        "artifact_names": ["nlw.dump"],
    }
    table = _base_table() + [
        (r"--profile backup run --rm -T backup evidence", json.dumps(evidence))
    ]
    fake = FakeRemote(
        table,
        state={
            "phases": {"verify-escrow": {}, "pin-release": {}, "prepare-roles": {}},
            "evidence": {},
        },
    )
    r = _rollout(
        fake, authorization=AUTHORIZATION_PHRASE, allow_fixture_repository=True
    )  # ignored: not LOCAL
    with pytest.raises(GateError, match="https|fixture"):
        r.verify_backup()


# --- pin-release: checkout + pins happen BEFORE the backup, never in migrate ----
def test_pin_release_checks_out_release_and_writes_digests_only() -> None:
    table = _base_table() + [
        (r"git checkout -q --detach", ""),
        (r"cp \"\$f\" \"\$f\.bak", ""),
        (r"--profile backup build -q backup", ""),
    ]
    # After the pin script runs, the pins read back as the release.
    fake = FakeRemote(
        table,
        state={
            "phases": {"verify-escrow": {}, "pin-release": {}, "prepare-roles": {}},
            "evidence": {},
        },
    )
    calls = {"n": 0}
    orig_run = fake.run

    def run(command: str, *, stdin: str | None = None, timeout: int = 300) -> CommandResult:
        if "grep -E '^(NLW_IMAGE" in command:
            calls["n"] += 1
            return CommandResult(0, PINS_POST if calls["n"] > 0 else PINS_PRE, "")
        return orig_run(command, stdin=stdin, timeout=timeout)

    fake.run = run  # type: ignore[method-assign]
    _rollout(fake, authorization=AUTHORIZATION_PHRASE).pin_release(keys_dir="/srv/nlw/ctx-keys")
    joined = "\n".join(fake.commands)
    assert f"git checkout -q --detach {REL.release_sha}" in joined
    assert f"'NLW_IMAGE' '{REL.backend_image}'" in joined and "stg-worker-1" in joined
    assert not any(re.search(r"alembic|ctxkeys install|up -d", c) for c in fake.commands)
    assert "pin-release" in fake.state_doc["phases"]


def test_migrate_refuses_when_app_dir_is_not_the_release_checkout() -> None:
    table = _base_table(roles=ROLES_ALL, pins=PINS_POST)
    table = [(p, ("0" * 40 if "rev-parse HEAD" in p else v)) for p, v in table]
    done: dict[str, Any] = {
        "phases": {
            p: {}
            for p in ("prepare-roles", "verify-escrow", "pin-release", "verify-backup", "drain")
        },
        "evidence": {},
    }
    fake = FakeRemote(table, state=done)
    with pytest.raises(GateError, match="release is"):
        _rollout(fake, authorization=AUTHORIZATION_PHRASE).migrate(keys_dir="/srv/nlw/ctx-keys")
    assert not fake.ran(r"--profile migration run")
