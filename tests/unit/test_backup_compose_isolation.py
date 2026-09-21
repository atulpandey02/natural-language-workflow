"""Backup/restore credential isolation in the rendered Compose topology (P2).

Proves the runtime services (api/worker/scheduler/web/migrate) never receive
object-storage, repository-encryption, or backup/restore DB credentials, and that
the backup/restore jobs are one-shot, profile-gated, hardened, and port-free.
"""

from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[2]

# Any env key that carries backup/restore/object-storage/repo-encryption secrets.
_BACKUP_CRED_PREFIXES = ("RESTIC_", "AWS_", "NLW_BACKUP_", "NLW_RESTORE_")
_RUNTIME_SERVICES = ("api", "worker", "scheduler", "web", "migrate")


def _load(name: str) -> dict[str, Any]:
    with (ROOT / name).open() as f:
        return cast(dict[str, Any], yaml.safe_load(f))  # resolves YAML merge (<<) anchors


def _env_keys(service: dict[str, Any]) -> set[str]:
    env = service.get("environment", {})
    if isinstance(env, list):  # "KEY=VALUE" form
        return {item.split("=", 1)[0] for item in env}
    return set(env or {})


def _is_backup_cred(key: str) -> bool:
    if key in ("AWS_DEFAULT_REGION",):  # region is not a secret; still not on runtime
        return True
    return any(key.startswith(p) for p in _BACKUP_CRED_PREFIXES)


def test_runtime_services_never_receive_backup_credentials() -> None:
    compose = _load("docker-compose.prod.yml")
    for svc in _RUNTIME_SERVICES:
        keys = _env_keys(compose["services"][svc])
        leaked = sorted(k for k in keys if _is_backup_cred(k))
        assert not leaked, f"{svc} leaks backup/restore credentials: {leaked}"


def test_backup_service_is_oneshot_profiled_hardened_and_credentialed() -> None:
    b = _load("docker-compose.prod.yml")["services"]["backup"]
    assert b["profiles"] == ["backup"]  # never on a normal `up`
    assert b["restart"] == "no"
    assert b["read_only"] is True
    assert b["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in b["security_opt"]
    assert "ports" not in b  # no exposed ports
    keys = _env_keys(b)
    for required in ("RESTIC_REPOSITORY", "RESTIC_PASSWORD", "NLW_BACKUP_DATABASE_URL"):
        assert required in keys, required
    # Credentials arrive via environment, not on the command line (process listing).
    assert b["command"] == ["backup"]


def test_restore_service_is_oneshot_profiled_hardened_and_confirmation_gated() -> None:
    r = _load("docker-compose.prod.yml")["services"]["restore"]
    assert r["profiles"] == ["restore"]
    assert r["restart"] == "no"
    assert r["read_only"] is True
    assert "no-new-privileges:true" in r["security_opt"]
    assert "ports" not in r
    keys = _env_keys(r)
    for required in (
        "NLW_RESTORE_DATABASE_URL",
        "NLW_RESTORE_TARGET_ID",
        "NLW_RESTORE_CONFIRM",
        # (B) scoped runtime-state guard + (C) restore-ready gate.
        "NLW_RESTORE_COMPOSE_PROJECT",
        "NLW_RESTORE_GATE_FILE",
    ):
        assert required in keys, required


def test_restore_run_does_not_pull_up_runtime_services() -> None:
    # `docker compose run restore` starts only restore + its depends_on chain. If a
    # runtime service were a restore dependency it would start alongside — assert none
    # are, so the restore invocation cannot bring api/worker/scheduler/web up.
    r = _load("docker-compose.prod.yml")["services"]["restore"]
    deps = r.get("depends_on", {})
    dep_names = set(deps.keys()) if isinstance(deps, dict) else set(deps)
    assert not (dep_names & {"api", "worker", "scheduler", "web"}), dep_names


def test_runtime_services_do_not_require_a_dr_gate_by_default() -> None:
    # (C) Normal (non-restore) deployments must be operable without a DR gate: no
    # runtime service sets NLW_RESTORE_MODE. (Also covered structurally by the
    # no-NLW_RESTORE_* credential test.)
    compose = _load("docker-compose.prod.yml")
    for svc in ("api", "worker", "scheduler", "web"):
        assert "NLW_RESTORE_MODE" not in _env_keys(compose["services"][svc])


def test_backup_service_has_single_execution_lock_on_a_shared_volume() -> None:
    # (A) the lock lives on a shared runtime volume so two CONTAINERS contend.
    b = _load("docker-compose.prod.yml")["services"]["backup"]
    assert "NLW_BACKUP_LOCK_FILE" in _env_keys(b)
    mounts = b.get("volumes", [])
    assert any("/run/nlw" in m for m in mounts), mounts


def test_backup_and_restore_use_separate_object_storage_env_vars() -> None:
    # Backup writer and restore reader use DIFFERENT interpolation vars, so the
    # operator can provision separate (least-privilege) credentials.
    text = (ROOT / "docker-compose.prod.yml").read_text()
    assert "BACKUP_AWS_ACCESS_KEY_ID" in text
    assert "RESTORE_AWS_ACCESS_KEY_ID" in text


def test_backup_restore_not_started_on_default_up() -> None:
    compose = _load("docker-compose.prod.yml")
    for svc in ("backup", "restore"):
        assert compose["services"][svc].get("profiles"), f"{svc} must be profile-gated"
