"""Dataset ingest runtime boundary (ADR-031): pure checks, no database.

Envelopes, the signed purpose, the migration's verifier text, runtime import
and environment isolation, shutdown behaviour, and the optional ``ingest`` key
class through manifest, attestation, fingerprint and rollout gates.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
import yaml

from nlw import ctxkeys
from nlw.datasets import envelope as envelopes
from nlw.ops import release_manifest as rm
from nlw.ops.rollout import gates, keyfiles
from nlw.ops.rollout.attestation import AttestationError, parse_attestation, verify_attestation
from nlw.ops.rollout.gates import GateError
from nlw.tenancy.signing import (
    PURPOSE_DB_ROLE,
    ContextSigner,
    ContextSigningError,
    Purpose,
    SecretBytes,
)

ROOT = Path(__file__).resolve().parents[2]
# Hex letters on purpose: canonical (lower-case) form is part of the contract.
T, D, V, R = (uuid.UUID(f"{c * 8}-0000-4000-8000-00000000000{c}") for c in "abcd")
SHA = "c" * 64


def _env(**over: Any) -> envelopes.WorkEnvelope:
    fields: dict[str, Any] = {
        "request_id": R,
        "tenant_id": T,
        "dataset_id": D,
        "version_id": V,
        "content_sha256": SHA,
        "requested_at_us": 1_790_000_000_000_000,
    }
    fields.update(over)
    return envelopes.WorkEnvelope(**fields, envelope_sha256=envelopes.envelope_digest(**fields))


# --- envelopes ----------------------------------------------------------------------


def test_envelope_canonical_message_is_length_prefixed_and_versioned() -> None:
    msg = envelopes.canonical_message(
        request_id=R, tenant_id=T, dataset_id=D, version_id=V, content_sha256=SHA,
        requested_at_us=12,
    )  # fmt: skip
    assert msg == (
        b"nlwingest1" + b"1:1"
        + f"36:{R}36:{T}36:{D}36:{V}".encode()
        + b"64:" + SHA.encode() + b"2:12"
    )  # fmt: skip


def test_envelope_round_trips_and_refuses_tampering() -> None:
    env = _env()
    assert envelopes.parse(env.to_json()) == env
    doc = json.loads(env.to_json())
    for field, value in (
        ("version_id", str(uuid.UUID(int=9))),
        ("tenant_id", str(uuid.UUID(int=9))),
        ("content_sha256", "d" * 64),
        ("requested_at_us", env.requested_at_us + 1),
    ):
        with pytest.raises(envelopes.TamperedEnvelope):
            envelopes.parse(json.dumps({**doc, field: value}))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: {**d, "extra": 1},
        lambda d: {k: v for k, v in d.items() if k != "request_id"},
        lambda d: {**d, "v": "2"},
        lambda d: {**d, "tenant_id": d["tenant_id"].upper()},  # not canonical
        lambda d: {**d, "requested_at_us": True},
        lambda d: {**d, "requested_at_us": "1"},
        lambda d: {**d, "content_sha256": "C" * 64},
        lambda d: {**d, "envelope_sha256": "x"},
    ],
)
def test_envelope_parsing_is_strict(mutate: Any) -> None:
    doc = json.loads(_env().to_json())
    with pytest.raises(envelopes.MalformedEnvelope):
        envelopes.parse(json.dumps(mutate(doc)))
    with pytest.raises(envelopes.MalformedEnvelope):
        envelopes.parse(b"x" * (envelopes.MAX_ENVELOPE_BYTES + 1))


def test_envelope_freshness_is_bounded_both_ways() -> None:
    env = _env()
    at = env.requested_at_us
    envelopes.check_fresh(env, now_us=at)
    envelopes.check_fresh(env, now_us=at + envelopes.MAX_ENVELOPE_AGE_S * 1_000_000)
    with pytest.raises(envelopes.StaleEnvelope):
        envelopes.check_fresh(env, now_us=at + envelopes.MAX_ENVELOPE_AGE_S * 1_000_000 + 1)
    with pytest.raises(envelopes.StaleEnvelope, match="future"):
        envelopes.check_fresh(env, now_us=at - 61_000_000)


# --- signed purpose ---------------------------------------------------------------------


def test_the_ingest_purpose_is_bound_to_nlw_ingest_and_one_version() -> None:
    assert PURPOSE_DB_ROLE[Purpose.DATASET_INGEST] == "nlw_ingest"
    assert list(PURPOSE_DB_ROLE.values()).count("nlw_ingest") == 1
    signer = ContextSigner(Purpose.DATASET_INGEST, "k1", SecretBytes(b"k" * 32))
    ctx = signer.sign(tenant_id=T, run_id=V)
    assert (ctx.db_role, ctx.tenant_id, ctx.run_id, ctx.user_id) == ("nlw_ingest", T, V, None)
    for ids in ({"tenant_id": T}, {"run_id": V}, {"user_id": T, "tenant_id": T, "run_id": V}):
        with pytest.raises(ContextSigningError):
            signer.sign(**ids)
    with pytest.raises(ContextSigningError):  # cannot claim another runtime's role
        ContextSigner(Purpose.DATASET_INGEST, "k1", SecretBytes(b"k" * 32), db_role="nlw_worker")


def _migration(name: str) -> Any:
    import importlib.util

    path = ROOT / "migrations" / "versions" / name
    spec = importlib.util.spec_from_file_location(f"_t_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_verifier_is_extended_in_place_by_exactly_the_ingest_rules() -> None:
    m26 = _migration("0026_dataset_ingest_role.py")
    original = (ROOT / "migrations/versions/0016_signed_database_context.py").read_text()
    assert m26.CLAIMS_0016.strip("\n") in original  # the downgrade target is verbatim
    new = m26.claims_0026()
    old = m26.CLAIMS_0016.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION")
    diff = list(difflib.ndiff(old.split("\n"), new.split("\n")))
    added = sorted(ln[2:].strip() for ln in diff if ln.startswith("+ "))
    removed = [ln[2:].strip() for ln in diff if ln.startswith("- ")]
    assert removed == [  # the only change to an existing line: the purpose list
        "('api_identity', 'api_request', 'worker_execution', 'scheduler_reconcile')"
    ]
    assert added == sorted(
        [
            "('api_identity', 'api_request', 'worker_execution', 'scheduler_reconcile',",
            "'dataset_ingest')",
            "OR (purpose = 'dataset_ingest' AND role <> 'nlw_ingest')",
            "IF purpose = 'dataset_ingest' AND (usr <> '' OR ten = '' OR run = '')",
            "THEN RETURN NULL; END IF;",
            "WHEN 'dataset_ingest' THEN 'ingest'",
        ]
    )
    assert "SECURITY DEFINER" in new and new.count("SECURITY DEFINER") == 1
    source = (ROOT / "migrations/versions/0026_dataset_ingest_role.py").read_text()
    assert "SECURITY DEFINER" not in source.replace(m26.CLAIMS_0016, "").replace(
        "same SECURITY DEFINER", ""
    ).replace("no new SECURITY DEFINER", "").replace("No new SECURITY DEFINER", "")


# --- runtime isolation ----------------------------------------------------------------------

_RUNTIME_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "APP_ENV": "local",
    "DATABASE_URL": "postgresql+psycopg://nlw_ingest:x@127.0.0.1:1/nlw",
    "REDIS_URL": "redis://127.0.0.1:1/0",
}
_FORBIDDEN_MODULES = (
    "nlw.worker",
    "nlw.engine",
    "nlw.connectors",
    "nlw.planner",
    "nlw.secrets",
    "nlw.tools",
    "nlw.api",
    "nlw.scheduler",
    "anthropic",
)


def _python(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        env=_RUNTIME_ENV,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_the_ingest_runtime_imports_no_worker_connector_planner_or_model_code() -> None:
    out = _python(
        "import sys, nlw.ingest_service.actors\n"
        f"bad = sorted(m for m in sys.modules if m.startswith({_FORBIDDEN_MODULES!r}))\n"
        "print('BAD=' + ','.join(bad))"
    )
    assert out.returncode == 0, out.stderr[-2000:]
    assert "BAD=\n" in out.stdout or out.stdout.strip() == "BAD=", out.stdout


def test_the_api_side_imports_no_ingest_runtime() -> None:
    out = _python(
        "import sys, nlw.datasets.processing_requests, nlw.datasets.envelope\n"
        "print('ACTORS=' + str('nlw.ingest_service.actors' in sys.modules))"
    )
    assert out.returncode == 0, out.stderr[-2000:]
    assert "ACTORS=False" in out.stdout


def test_shutdown_requeues_without_starting_work() -> None:
    out = _python(
        "import asyncio, dramatiq\n"
        "import nlw.ingest_service.actors as a\n"
        "calls = []\n"
        "async def fake(**kw):\n"
        "    calls.append(kw); return 'profiled'\n"
        "a.processing.process_envelope = fake\n"
        "a.StopFlagMiddleware().before_worker_shutdown(None, None)\n"
        "assert a._stopping.is_set()\n"
        "try:\n"
        "    a.process_dataset_version.fn('{}')\n"
        "    print('NO-RETRY')\n"
        "except dramatiq.Retry:\n"
        "    print('RETRY calls=%d' % len(calls))\n"
        "print('QUEUE=' + a.process_dataset_version.queue_name)\n"
    )
    assert out.returncode == 0, out.stderr[-2000:]
    assert "RETRY calls=0" in out.stdout and "QUEUE=dataset_ingest" in out.stdout


def test_the_runtime_refuses_to_boot_without_a_dataset_store() -> None:
    out = _python(
        "import nlw.ingest_service.actors as a\n"
        "from nlw.core.config import get_settings\n"
        "try:\n"
        "    a._boot_checks(get_settings())\n"
        "except a.IngestBootRefused as exc:\n"
        "    print('REFUSED', exc)\n"
    )
    assert out.returncode == 0, out.stderr[-2000:]
    assert "REFUSED ingest boot refused: no dataset store is configured" in out.stdout


def _compose(name: str) -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load((ROOT / name).read_text())
    return doc


def test_the_ingest_service_is_isolated_and_opt_in() -> None:
    svc = _compose("docker-compose.yml")["services"]["ingest"]
    assert svc["profiles"] == ["ingest"]
    assert svc["command"] == [
        "dramatiq", "nlw.ingest_service.actors", "--queues", "dataset_ingest",
        "--processes", "1", "--threads", "1",
    ]  # fmt: skip
    assert svc["init"] is True and svc["read_only"] is True
    assert svc["cap_drop"] == ["ALL"] and "no-new-privileges:true" in svc["security_opt"]
    assert "ports" not in svc and "expose" not in svc and "env_file" not in svc
    assert set(svc["environment"]) == {
        "APP_ENV",
        "LOG_LEVEL",
        "DATABASE_URL",
        "REDIS_URL",
        "NLW_CTX_KEY_ID",
        "NLW_CTX_KEY_FILE",
        "DATASET_STORAGE_BACKEND",
        "DATASET_STORAGE_ROOT",
    }
    assert svc["environment"]["DATABASE_URL"].startswith("postgresql+psycopg://nlw_ingest:")
    assert svc["environment"]["NLW_CTX_KEY_FILE"] == "/run/nlw/keys/ingest.key"
    mounts = [v for v in svc["volumes"] if ".key" in v]
    assert mounts == ["./docker/ctx-keys/ingest.key:/run/nlw/keys/ingest.key:ro"]
    blob = json.dumps(svc)
    for forbidden in ("MIGRATION", "LLM", "DEMO_TOOLS", "SUPABASE", "secrets.env", "api.key",
                      "worker.key", "scheduler.key", "RESTIC", "ALERTMANAGER", "AWS"):  # fmt: skip
        assert forbidden not in blob, forbidden
    # No other service mounts the ingest key, and no deployed Compose has the runtime.
    for name in ("docker-compose.yml", "docker-compose.prod.yml", "docker-compose.staging.yml",
                 "docker-compose.e2e.yml", "docker-compose.rehearsal.yml"):  # fmt: skip
        services = _compose(name).get("services") or {}
        for sname, s in services.items():
            if sname != "ingest" or name != "docker-compose.yml":
                assert "ingest.key" not in json.dumps(s), (name, sname)
        if name != "docker-compose.yml":
            assert "ingest" not in services, name


def test_the_healthcheck_and_readiness_know_the_ingest_purpose() -> None:
    from nlw.ops import healthcheck
    from nlw.tenancy import readiness

    assert healthcheck._ROLE_PURPOSE["nlw_ingest"] is Purpose.DATASET_INGEST
    signer = ContextSigner(Purpose.DATASET_INGEST, "k1", SecretBytes(b"k" * 32))
    signer.sign(**readiness._sentinel(signer))  # a valid shape


# --- optional ingest key class through the release protocol ---------------------------------

TARGET = (ROOT / "deploy/staging/target.env").read_text()


def _manifest(**key_ids: str) -> rm.ReleaseManifest:
    doc: dict[str, Any] = {
        "format_version": 2,
        "kind": "release",
        "deployable": True,
        "generated_by": "ci",
        "created_at": "2026-10-07T10:00:00+00:00",
        "ci": {
            "workflow": "Delivery",
            "run_id": "1",
            "run_url": "https://github.com/o/r/actions/runs/1",
        },
        "environment": "staging",
        "release_sha": "1" * 40,
        "backend_image": "ghcr.io/o/r@sha256:" + "a" * 64,
        "web_image": "ghcr.io/o/r/web@sha256:" + "b" * 64,
        "expected_current_revision": "0025_dataset_ingestion",
        "target_revision": "0026_dataset_ingest_role",
        "instance_id": "i-0d1e65cdc9401dbb9",
        "region": "us-east-1",
        "compose_project": "app",
        "public_hostname": "app.nlwplatform.com",
        "key_ids": key_ids,
    }
    return rm.parse_manifest(doc)


THREE = {"api": "stg-api-1", "worker": "stg-worker-1", "scheduler": "stg-sched-1"}


def test_the_staging_target_and_its_releases_are_unchanged_three_key() -> None:
    assert "NLW_STAGING_KEY_ID_INGEST" not in TARGET
    m = _manifest(**THREE)
    assert m.key_classes == ("api", "worker", "scheduler") and not m.declares_ingest
    gates.check_ingest_not_declared(m)


def test_a_manifest_may_declare_ingest_and_the_rollout_refuses_it() -> None:
    m = _manifest(**THREE, ingest="stg-ingest-1")
    assert m.key_classes == ("api", "worker", "scheduler", "ingest") and m.declares_ingest
    with pytest.raises(GateError, match="O-6"):
        gates.check_ingest_not_declared(m)
    for bad in (
        {"api": "a1", "worker": "w1", "ingest": "i1"},  # a required class missing
        {**THREE, "ingest": "stg-api-1"},  # not unique
        {**THREE, "other": "x1"},
    ):
        with pytest.raises(rm.ReleaseManifestError):
            _manifest(**bad)


def _att(keys: list[tuple[str, str, str]]) -> dict[str, Any]:
    return {
        "format_version": 1,
        "environment": "staging",
        "release_sha": "1" * 40,
        "keys": [{"purpose_class": c, "key_id": k, "sha256_fingerprint": f} for c, k, f in keys],
        "escrow_verified_at": "2026-10-07T11:00:00Z",
        "operator": "ops-lead",
        "recovery_test_confirmed": True,
        "escrow_location_label": "ops-vault:staging/ctx-keys/2026-10",
    }


KEYS3 = [("api", "stg-api-1", "1" * 64), ("worker", "stg-worker-1", "2" * 64),
         ("scheduler", "stg-sched-1", "3" * 64)]  # fmt: skip
KEY_INGEST = ("ingest", "stg-ingest-1", "4" * 64)


def test_escrow_attestation_covers_exactly_the_releases_key_classes() -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 10, 7, 12, tzinfo=UTC)
    m3, m4 = _manifest(**THREE), _manifest(**THREE, ingest="stg-ingest-1")
    host3 = {c: (k, f) for c, k, f in KEYS3}
    host4 = {**host3, "ingest": KEY_INGEST[1:]}
    verify_attestation(parse_attestation(_att(KEYS3)), m3, host3, now=now)
    verify_attestation(parse_attestation(_att([*KEYS3, KEY_INGEST])), m4, host4, now=now)
    with pytest.raises(AttestationError):  # a 4-key attestation for a 3-key release
        verify_attestation(parse_attestation(_att([*KEYS3, KEY_INGEST])), m3, host4, now=now)
    with pytest.raises(AttestationError):  # an ingest release with a 3-key attestation
        verify_attestation(parse_attestation(_att(KEYS3)), m4, host4, now=now)
    with pytest.raises(AttestationError):  # the host lacks the ingest key file
        verify_attestation(parse_attestation(_att([*KEYS3, KEY_INGEST])), m4, host3, now=now)
    with pytest.raises(AttestationError):  # ingest replacing a required class
        parse_attestation(_att([KEYS3[0], KEYS3[1], KEY_INGEST]))
    with pytest.raises(AttestationError):  # independent keys
        parse_attestation(_att([*KEYS3, ("ingest", "stg-ingest-1", "1" * 64)]))


def test_fingerprint_lines_must_match_the_release_classes() -> None:
    lines3 = "\n".join(f"{c} {k} {f}" for c, k, f in KEYS3)
    lines4 = lines3 + "\n" + " ".join(KEY_INGEST)
    assert set(keyfiles.parse_fingerprint_lines(lines3)) == {"api", "worker", "scheduler"}
    four = keyfiles.parse_fingerprint_lines(lines4, ("api", "worker", "scheduler", "ingest"))
    assert four["ingest"] == KEY_INGEST[1:]
    with pytest.raises(GateError):
        keyfiles.parse_fingerprint_lines(lines3, ("api", "worker", "scheduler", "ingest"))
    with pytest.raises(GateError):
        keyfiles.parse_fingerprint_lines(lines4, ("api", "worker", "ingest"))


def _key_dir(tmp: Path, classes: tuple[str, ...]) -> Path:
    for c in classes:
        p = tmp / f"{c}.key"
        p.write_text(hashlib.sha256(c.encode()).hexdigest())
        p.chmod(0o400)
    return tmp


def test_ctxkeys_ingest_is_optional_and_explicit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    uid = str(os.getuid())
    three = ("api", "worker", "scheduler")
    _key_dir(tmp_path, three)
    args = ["--dir", str(tmp_path), "--owner", uid, "--key-id-api", "k-api", "--key-id-worker",
            "k-worker", "--key-id-scheduler", "k-sched"]  # fmt: skip
    assert ctxkeys.main(["fingerprint", *args]) == 0
    assert [ln.split()[0] for ln in capsys.readouterr().out.splitlines()] == list(three)
    assert ctxkeys.main(["verify-files", "--dir", str(tmp_path), "--owner", uid]) == 0
    # Naming ingest makes its file required ...
    assert ctxkeys.main(["fingerprint", *args, "--key-id-ingest", "k-ingest"]) == 1
    assert ctxkeys.main(["verify-files", "--dir", str(tmp_path), "--owner", uid,
                         "--include-ingest"]) == 1  # fmt: skip
    _key_dir(tmp_path, ("ingest",))
    capsys.readouterr()
    assert ctxkeys.main(["fingerprint", *args, "--key-id-ingest", "k-ingest"]) == 0
    assert [ln.split()[0] for ln in capsys.readouterr().out.splitlines()] == [*three, "ingest"]
    assert "ingest" in ctxkeys._CLASSES and three == ctxkeys.REQUIRED_CLASSES


def test_the_role_gate_requires_a_dormant_ingest_role() -> None:
    base = {**gates.EXPECTED_ROLES}
    gates.check_roles(base, require_provisioned=True)
    with pytest.raises(GateError, match="nlw_ingest"):  # LOGIN on a deployed target
        gates.check_roles({**base, "nlw_ingest": "tff"}, require_provisioned=True)
    with pytest.raises(GateError, match="nlw_ingest"):
        gates.check_roles({**base, "nlw_ingest": "fft"}, require_provisioned=True)
    without = {k: v for k, v in base.items() if k != "nlw_ingest"}
    gates.check_roles(without, require_provisioned=False)  # before prepare-roles
    with pytest.raises(GateError, match="nlw_ingest is missing"):
        gates.check_roles(without, require_provisioned=True)
    assert "nlw_ingest" in gates.RUNTIME_ROLES


def test_the_api_cannot_route_an_envelope_through_a_non_ingest_signer() -> None:
    import asyncio

    from nlw.ingest_service import processing

    signer = ContextSigner(Purpose.WORKER_EXECUTION, "k1", SecretBytes(b"k" * 32))

    async def noop(_: object) -> None:
        return None

    async def go() -> None:
        maker: Any = None  # never reached: the signer is refused first
        await processing.in_ingest_context(maker, signer, _env(), noop)

    with pytest.raises(ValueError, match="dataset_ingest"):
        asyncio.run(go())


def test_the_ingest_grant_gate_detects_missing_and_excessive_privileges() -> None:
    from nlw.ops.roles import EXPECTED_INGEST_GRANTS

    exact = "\n".join(sorted(EXPECTED_INGEST_GRANTS))
    gates.check_ingest_grants(exact)
    with pytest.raises(GateError, match="missing dataset_events:INSERT"):
        gates.check_ingest_grants(exact.replace("dataset_events:INSERT", ""))
    for extra in (
        "dataset_versions:DELETE",
        "datasets:UPDATE",
        "dataset_semantic_revisions:INSERT",
        "dataset_versions:UPDATE:content_sha256",
        "connectors:SELECT",
        "ctx_keys:SELECT",
    ):
        with pytest.raises(GateError, match=f"extra {extra}"):
            gates.check_ingest_grants(exact + "\n" + extra)
