"""Rollout gates are pure and fail closed (M12A-Prep §B/§C/§D/§F/§G, tests O.2–O.16).

Every gate takes plain values already read from the host; these tests feed it
the exact failure shapes the rollout must stop on. No host, no Docker.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from nlw.ops.rollout import gates, keyfiles, state
from nlw.ops.rollout.attestation import (
    AttestationError,
    parse_attestation,
    verify_attestation,
)
from nlw.ops.rollout.backup_evidence import (
    BackupEvidence,
    BackupEvidenceError,
    SnapshotEvidence,
    SourceBinding,
    check_repository_is_off_host,
    evaluate_backup_evidence,
    parse_snapshots_json,
)
from nlw.ops.rollout.gates import GateError
from nlw.ops.rollout.release import ReleaseSpecError, load_release, parse_release
from nlw.ops.rollout.remote import TargetConfigError, parse_target_env

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
D = "sha256:" + "a" * 64
W = "sha256:" + "b" * 64


def _release_doc(**over: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "format_version": 2,
        "kind": "release",
        "deployable": True,
        "generated_by": "ci",
        "created_at": "2026-09-22T10:00:00+00:00",
        "ci": {
            "workflow": "Delivery",
            "run_id": "1",
            "run_url": "https://github.com/o/r/actions/runs/1",
        },
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
    doc.update(over)
    return doc


REL = parse_release(_release_doc())


# --- release identity (§B) ---------------------------------------------------
def test_committed_example_is_rejected_and_target_env_is_consistent() -> None:
    with pytest.raises(ReleaseSpecError, match="not a deployable"):
        load_release(ROOT / "deploy" / "staging" / "release.example.json")
    tgt = parse_target_env((ROOT / "deploy" / "staging" / "target.env").read_text())
    assert tgt["NLW_STAGING_INSTANCE_ID"] == REL.instance_id
    assert tgt["NLW_STAGING_CURRENT_REVISION"] == "0010_readiness_schema_grant"
    assert tgt["NLW_STAGING_OPS_ROOT"] == "/opt/nlw"


@pytest.mark.parametrize(
    "over",
    [
        {"backend_image": "ghcr.io/o/r:latest"},  # mutable tag is never authority
        {"backend_image": "ghcr.io/o/r:sha-1eebf2e"},
        {"release_sha": "1eebf2e"},
        {"instance_id": "32.197.83.193"},  # an IP is not an identity
        {"expected_current_revision": "0016_signed_database_context"},  # nothing to roll
        {"key_ids": {"api": "k", "worker": "k", "scheduler": "k"}},  # not unique
        {"key_ids": {"api": "stg-api-1", "worker": "stg-worker-1"}},
        {"format_version": 1},
    ],
)
def test_release_rejects_mutable_or_malformed_identity(over: dict[str, object]) -> None:
    with pytest.raises(ReleaseSpecError):
        parse_release(_release_doc(**over))


def test_target_env_rejects_e2e_overlay_and_bad_instance() -> None:
    text = (ROOT / "deploy" / "staging" / "target.env").read_text()
    with pytest.raises(TargetConfigError):
        parse_target_env(text.replace("i-0d1e65cdc9401dbb9", "staging-box"))


# --- identity + pins (§B, O.2, O.3) --------------------------------------------
def test_wrong_instance_id_fails() -> None:
    with pytest.raises(GateError, match="instance"):
        gates.check_instance_identity("i-0000000000000001", "us-east-1", REL)
    with pytest.raises(GateError, match="region"):
        gates.check_instance_identity(REL.instance_id, "eu-west-1", REL)
    with pytest.raises(GateError, match="could not read"):
        gates.check_instance_identity("", "us-east-1", REL)


def test_changed_public_ip_fails_sslip_hostname() -> None:
    gates.check_public_ip_matches_hostname("32.197.83.193", REL)
    with pytest.raises(GateError, match="address changed"):
        gates.check_public_ip_matches_hostname("54.196.254.101", REL)


def test_wrong_release_digest_fails() -> None:
    pins = gates.parse_env_pins(
        "POSTGRES_PASSWORD=never-read\n"
        f"NLW_IMAGE=ghcr.io/o/r@sha256:{'c' * 64}\nNLW_WEB_IMAGE=ghcr.io/o/r/web@{W}\n"
        "PUBLIC_HOSTNAME=32-197-83-193.sslip.io\nNLW_CTX_KEYS_DIR=/srv/nlw/ctx-keys\n"
        "NLW_CTX_API_KEY_ID=stg-api-1\nNLW_CTX_WORKER_KEY_ID=stg-worker-1\n"
        "NLW_CTX_SCHEDULER_KEY_ID=stg-sched-1\n"
    )
    assert "POSTGRES_PASSWORD" not in pins  # secrets are never parsed out
    gates.check_release_pins(pins, REL, post_pin=False)  # hostname only, pre-pin
    with pytest.raises(GateError, match="backend digest"):
        gates.check_release_pins(pins, REL, post_pin=True)
    pins["NLW_IMAGE"] = REL.backend_image
    gates.check_release_pins(pins, REL, post_pin=True)
    pins["NLW_CTX_WORKER_KEY_ID"] = "other"
    with pytest.raises(GateError, match="WORKER_KEY_ID"):
        gates.check_release_pins(pins, REL, post_pin=True)


# --- migration state (O.4) -------------------------------------------------------
def test_unexpected_current_migration_fails() -> None:
    gates.check_current_revision("0010_readiness_schema_grant\n", "0010_readiness_schema_grant")
    with pytest.raises(GateError, match="unknown migration state"):
        gates.check_current_revision("0015_membership_approval_sod", "0010_readiness_schema_grant")
    with pytest.raises(GateError, match="could not read"):
        gates.check_current_revision("", "0010_readiness_schema_grant")


# --- authorization (O.5) -----------------------------------------------------
@pytest.mark.parametrize(
    "phrase",
    [
        None,
        "",
        "yes",
        "y",
        "AUTHORIZE",
        " AUTHORIZE_M12A_SIGNED_CONTEXT_STAGING_DEPLOYMENT",
        "authorize_m12a_signed_context_staging_deployment",
    ],
)
def test_missing_or_inexact_authorization_fails(phrase: str | None) -> None:
    with pytest.raises(GateError):
        gates.check_authorization(phrase)
    with pytest.raises(GateError):
        gates.check_escrow_confirmation(phrase)


def test_exact_phrases_pass() -> None:
    gates.check_authorization("AUTHORIZE_M12A_SIGNED_CONTEXT_STAGING_DEPLOYMENT")
    gates.check_escrow_confirmation("SIGNED_CONTEXT_KEYS_ESCROWED_AND_RECOVERY_TESTED")


# --- escrow attestation (§F, O.6, O.7) ---------------------------------------
def _att(**over: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "format_version": 1,
        "environment": "staging",
        "release_sha": REL.release_sha,
        "keys": [
            {"purpose_class": "api", "key_id": "stg-api-1", "sha256_fingerprint": "1" * 64},
            {"purpose_class": "worker", "key_id": "stg-worker-1", "sha256_fingerprint": "2" * 64},
            {"purpose_class": "scheduler", "key_id": "stg-sched-1", "sha256_fingerprint": "3" * 64},
        ],
        "escrow_verified_at": "2026-09-22T11:00:00Z",
        "operator": "ops-lead",
        "recovery_test_confirmed": True,
        "escrow_location_label": "ops-vault:staging/ctx-keys/2026-09",
    }
    doc.update(over)
    return doc


HOST_FPS = {
    "api": ("stg-api-1", "1" * 64),
    "worker": ("stg-worker-1", "2" * 64),
    "scheduler": ("stg-sched-1", "3" * 64),
}


def test_attestation_matches_host_fingerprints() -> None:
    att = parse_attestation(_att())
    verify_attestation(att, REL, HOST_FPS, now=NOW)
    assert "sha256_fingerprint" in json.dumps(att.summary())


def test_fingerprint_mismatch_fails() -> None:
    att = parse_attestation(_att())
    bad = dict(HOST_FPS, worker=("stg-worker-1", "f" * 64))
    with pytest.raises(AttestationError, match="worker"):
        verify_attestation(att, REL, bad, now=NOW)


def test_attestation_rejects_secret_bearing_or_incomplete_docs() -> None:
    with pytest.raises(AttestationError, match="secret-bearing"):
        parse_attestation(_att(escrow_location_label="s3://bucket?token=abc"))
    with pytest.raises(AttestationError):
        parse_attestation(_att(recovery_test_confirmed="yes"))
    with pytest.raises(AttestationError):
        parse_attestation(_att(keys=_att()["keys"][:2]))  # type: ignore[index]
    with pytest.raises(AttestationError, match="future"):
        verify_attestation(
            parse_attestation(_att(escrow_verified_at="2026-09-22T13:00:00Z")),
            REL,
            HOST_FPS,
            now=NOW,
        )
    with pytest.raises(AttestationError, match="older"):
        verify_attestation(
            parse_attestation(_att(escrow_verified_at="2026-06-01T00:00:00Z")),
            REL,
            HOST_FPS,
            now=NOW,
        )
    with pytest.raises(AttestationError, match="release_sha"):
        verify_attestation(parse_attestation(_att(release_sha="0" * 40)), REL, HOST_FPS, now=NOW)


# --- backup evidence (§G, O.8, O.9) ------------------------------------------
GOOD_METRICS = (
    "nlw_backup_success 1\nnlw_backup_repository_verify_success 1\n"
    "nlw_backup_retention_success 1\n"
    f"nlw_backup_last_success_timestamp_seconds {int((NOW - timedelta(hours=1)).timestamp())}\n"
)
SNAP = SnapshotEvidence(
    snapshot_id="abc123",
    time=NOW - timedelta(hours=1),
    hostname="ip-172-31-28-155",
    tags=("nlw-db", "rev-0010_readiness_schema_grant"),
)


def _ev(**over: object) -> BackupEvidence:
    kw: dict[str, object] = {
        "repository": "s3:https://s3.eu-west-1.amazonaws.com/nlw-staging-backups/nlw",
        "metrics_text": GOOD_METRICS,
        "snapshot": SNAP,
        "artifact_names": ("nlw.dump", "globals.sql", "manifest.json"),
        "manifest": {
            "alembic_revision": "0010_readiness_schema_grant",
            "artifacts": {"nlw.dump": {"bytes": 1, "sha256": "x"}},
            "completed_at": (NOW - timedelta(hours=1)).isoformat(),
            "source": {
                "instance_id": "i-0d1e65cdc9401dbb9",
                "environment": "staging",
                "db_system_identifier": "7311111111111111111",
                "release": "5151a2cc54cfb63b276bd3b30cf0e683263525ac",
            },
        },
    }
    kw.update(over)
    return BackupEvidence(**kw)  # type: ignore[arg-type]


BINDING = SourceBinding(
    instance_id="i-0d1e65cdc9401dbb9",
    environment="staging",
    db_system_identifier="7311111111111111111",
    source_revision="0010_readiness_schema_grant",
    source_release="5151a2cc54cfb63b276bd3b30cf0e683263525ac",
)


def _eval(ev: BackupEvidence, **over: object) -> dict[str, object]:
    kw: dict[str, object] = {"binding": BINDING, "max_age": timedelta(hours=26), "now": NOW}
    kw.update(over)
    return evaluate_backup_evidence(ev, **kw)  # type: ignore[arg-type]


def test_verified_offhost_backup_passes_and_record_has_no_credentials() -> None:
    rec = _eval(_ev(repository="s3:https://AKIA:secret@s3.eu-west-1.amazonaws.com/b/nlw"))
    assert rec["snapshot_id"] == "abc123" and "secret" not in json.dumps(rec)


@pytest.mark.parametrize(
    "repo",
    [
        "s3:http://minio:9000/nlwdrill",  # MinIO fixture
        "s3:https://minio.internal.example/b",
        "s3:https://127.0.0.1:9000/b",
        "s3:https://10.0.0.5/b",
        "/var/backups/nlw",  # same-host path
        "local:/srv/backups",
        "sftp:nlwops@localhost:/backups",
        "s3:https://s3.eu-west-1.amazonaws.com/",  # no bucket
    ],
)
def test_local_fixture_or_same_host_repository_cannot_satisfy_gate(repo: str) -> None:
    with pytest.raises(BackupEvidenceError):
        check_repository_is_off_host(repo)
    with pytest.raises(BackupEvidenceError):
        _eval(_ev(repository=repo))


def test_missing_old_or_unverified_backup_fails() -> None:
    with pytest.raises(BackupEvidenceError, match="did not succeed"):
        _eval(
            _ev(metrics_text=GOOD_METRICS.replace("nlw_backup_success 1", "nlw_backup_success 0"))
        )
    with pytest.raises(BackupEvidenceError, match="verification"):
        _eval(_ev(metrics_text=GOOD_METRICS.replace("verify_success 1", "verify_success 0")))
    with pytest.raises(BackupEvidenceError, match="no verified"):
        _eval(_ev(metrics_text="nlw_backup_success 1\nnlw_backup_repository_verify_success 1\n"))
    with pytest.raises(BackupEvidenceError, match="too old"):
        _eval(_ev(), now=NOW + timedelta(hours=30))
    with pytest.raises(BackupEvidenceError, match="no restic snapshot"):
        _eval(_ev(snapshot=None))
    with pytest.raises(BackupEvidenceError, match="source revision"):
        _eval(
            _ev(snapshot=SnapshotEvidence("x", SNAP.time, SNAP.hostname, ("nlw-db", "rev-0015_x")))
        )
    with pytest.raises(BackupEvidenceError, match="another host"):
        _eval(
            _ev(),
            binding=SourceBinding(
                "i-0000000000000001",
                "staging",
                "7311111111111111111",
                "0010_readiness_schema_grant",
                None,
            ),
        )
    with pytest.raises(BackupEvidenceError, match="another database"):
        _eval(
            _ev(),
            binding=SourceBinding(
                "i-0d1e65cdc9401dbb9",
                "staging",
                "7399999999999999999",
                "0010_readiness_schema_grant",
                None,
            ),
        )
    with pytest.raises(BackupEvidenceError, match="another environment"):
        _eval(
            _ev(),
            binding=SourceBinding(
                "i-0d1e65cdc9401dbb9",
                "production",
                "7311111111111111111",
                "0010_readiness_schema_grant",
                None,
            ),
        )
    with pytest.raises(BackupEvidenceError, match="active checkout"):
        _eval(
            _ev(),
            binding=SourceBinding(
                "i-0d1e65cdc9401dbb9",
                "staging",
                "7311111111111111111",
                "0010_readiness_schema_grant",
                "f" * 40,
            ),
        )
    with pytest.raises(BackupEvidenceError, match="no manifest"):
        _eval(_ev(manifest={}))
    with pytest.raises(BackupEvidenceError, match="key-like"):
        _eval(_ev(artifact_names=("nlw.dump", "api.key")))
    # A local pg_dump with no repository snapshot never counts.
    with pytest.raises(BackupEvidenceError):
        _eval(_ev(repository="/var/backups/nlw.dump", snapshot=None))


def test_parse_snapshots_picks_newest() -> None:
    doc = [
        {"id": "old", "time": "2026-09-20T00:00:00Z", "tags": ["nlw-db"]},
        {
            "id": "new",
            "time": "2026-09-22T00:00:00Z",
            "tags": ["nlw-db", "rev-0010_x"],
            "hostname": "h",
        },
    ]
    snap = parse_snapshots_json(doc)
    assert snap is not None and snap.snapshot_id == "new" and snap.source_revision == "0010_x"
    assert parse_snapshots_json([]) is None


# --- drain / sessions / roles (O.10, O.11, O.12) -----------------------------
def test_non_terminal_work_blocks_drain() -> None:
    gates.check_drained(gates.DrainSnapshot(0, 0, 0, 0))
    for snap in (
        gates.DrainSnapshot(1, 0, 0, 0),
        gates.DrainSnapshot(0, 1, 0, 0),
        gates.DrainSnapshot(0, 0, 1, 0),
        gates.DrainSnapshot(0, 0, 0, 3),
    ):
        with pytest.raises(GateError, match="drain not clean"):
            gates.check_drained(snap)


def test_runtime_sessions_block_migration() -> None:
    gates.check_no_runtime_sessions(0)
    with pytest.raises(GateError, match="session"):
        gates.check_no_runtime_sessions(2)


def test_incompatible_role_attributes_fail() -> None:
    pre = gates.parse_role_lines(
        "nlw_app:tff\nnlw_worker:tff\nnlw_scheduler:tff\nnlw_rls_bypass:fft\nnlw_workspace_bootstrap:fft\n"
    )
    gates.check_roles(pre, require_provisioned=False)  # M11 state is acceptable pre-upgrade
    with pytest.raises(GateError, match="missing"):
        gates.check_roles(pre, require_provisioned=True)
    bad = dict(pre, nlw_ctx_verifier="fft")  # BYPASSRLS on the verifier is incompatible
    with pytest.raises(GateError, match="nlw_ctx_verifier"):
        gates.check_roles(bad, require_provisioned=False)
    widened = dict(pre, nlw_app="ttf")
    with pytest.raises(GateError, match="nlw_app"):
        gates.check_roles(widened, require_provisioned=False)
    extra = dict(pre, nlw_backdoor="tft")
    with pytest.raises(GateError, match="unexpected"):
        gates.check_roles(extra, require_provisioned=False)
    with pytest.raises(GateError, match="unparseable"):
        gates.parse_role_lines("nlw_app:true")


# --- key files (O.13) ----------------------------------------------------------
def test_key_file_placement_rules() -> None:
    good = keyfiles.parse_stat_line("api.key|regular file|400|10001|10001|65")
    keyfiles.check_key_file(good)
    for line, msg in (
        ("api.key|symbolic link|777|10001|10001|20", "symlink"),
        ("api.key|directory|700|0|0|4096", "not a regular"),
        ("api.key|regular file|644|10001|10001|65", "mode"),
        ("api.key|regular file|400|1000|1000|65", "uid"),
        ("api.key|regular file|400|10001|10001|0", "too small"),
    ):
        with pytest.raises(GateError, match=msg):
            keyfiles.check_key_file(keyfiles.parse_stat_line(line))
    keyfiles.check_key_dir(keyfiles.parse_stat_line(".|directory|700|0|0|4096"))
    with pytest.raises(GateError, match="mode"):
        keyfiles.check_key_dir(keyfiles.parse_stat_line(".|directory|755|0|0|4096"))
    fps = keyfiles.parse_fingerprint_lines(
        "api a 1\n" + "\n".join(f"{c} id-{c} {'a' * 64}" for c in ("api", "worker", "scheduler"))
    )
    assert set(fps) == {"api", "worker", "scheduler"}
    with pytest.raises(GateError, match="missing"):
        keyfiles.parse_fingerprint_lines("api id " + "a" * 64)


# --- cutover / images / readiness (O.14, O.15, O.16) ---------------------------
def test_policy_cutover_requires_51_signed_and_zero_legacy() -> None:
    gates.check_policy_cutover(51, 0, expected_policies=51)
    with pytest.raises(GateError, match="unsigned"):
        gates.check_policy_cutover(51, 3, expected_policies=51)
    with pytest.raises(GateError, match="live policies"):
        gates.check_policy_cutover(41, 34, expected_policies=51)


def test_old_runtime_image_cannot_pass_after_migration() -> None:
    old = f"ghcr.io/o/r@sha256:{'f' * 64}"
    images = {
        "api": old,
        "worker": REL.backend_image,
        "scheduler": REL.backend_image,
        "web": REL.web_image,
    }
    with pytest.raises(GateError, match="api is running"):
        gates.check_running_images(images, REL)
    images["api"] = REL.backend_image
    gates.check_running_images(images, REL)
    with pytest.raises(GateError, match="web"):
        gates.check_running_images({**images, "web": "ghcr.io/o/r/web@sha256:" + "e" * 64}, REL)


def test_missing_signed_context_readiness_blocks_reopen() -> None:
    gates.check_readiness_body('{"status":"ready","checks":{"signed_context":"ok"}}')
    with pytest.raises(GateError, match="signed_context"):
        gates.check_readiness_body('{"status":"ready","checks":{"postgres":"ok","schema":"ok"}}')
    with pytest.raises(GateError, match="not 'ready'"):
        gates.check_readiness_body('{"status":"not_ready","checks":{"signed_context":"down"}}')


# --- state file never carries secrets ---------------------------------------
def test_state_rejects_secret_bearing_values() -> None:
    doc = {
        "phases": {},
        "evidence": {"x": {"note": "AUTHORIZE_M12A_SIGNED_CONTEXT_STAGING_DEPLOYMENT"}},
    }
    with pytest.raises(state.StateError):
        state.assert_state_is_secret_free(doc)
    with pytest.raises(state.StateError):
        state.assert_state_is_secret_free({"repo": "s3://k:s@host/b"})
    ok: dict[str, Any] = {"phases": {}, "evidence": {}}
    state.mark_phase(ok, "drain", non_terminal_runs=0)
    state.assert_state_is_secret_free(ok)
    assert state.phase_done(ok, "drain") and not state.phase_done(ok, "migrate")
    with pytest.raises(state.StateError):
        state.require_phases(ok, "migrate")


def test_report_legacy_connector_bindings_surfaces_count_without_claiming_protection() -> None:
    zero = gates.report_legacy_connector_bindings(0)
    assert "0 legacy" in zero and "identity-pinned" in zero
    some = gates.report_legacy_connector_bindings(7)
    assert "7 LEGACY" in some
    assert "NOT identity-pinned" in some  # never claims they are protected
    assert "Re-materialize" in some
    with pytest.raises(GateError):
        gates.report_legacy_connector_bindings(-1)
    # The go-live query is a plain read-only count.
    assert gates.LEGACY_CONNECTOR_BINDING_SQL.lower().startswith("select count(*)")
    assert "connector_bindings is null" in gates.LEGACY_CONNECTOR_BINDING_SQL.lower()
