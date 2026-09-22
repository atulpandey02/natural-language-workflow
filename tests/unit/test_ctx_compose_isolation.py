"""Rendered-Compose isolation of the signed-context keys (M11.5 P3B).

Each runtime class receives EXACTLY its own key file, mounted read-only into
exactly one service; no other service (web, migrate, backup, restore, caddy,
postgres, redis, prometheus) receives any key file or key id, and nothing key-
related lives in the shared ``x-app-env`` anchor. Production requires the key id
and key directory (fail-closed render); dev defaults exist for the local stack.
"""

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
_KEY_ENV = ("NLW_CTX_KEY_ID", "NLW_CTX_KEY_FILE")
_HOLDERS = {"api": "api.key", "worker": "worker.key", "scheduler": "scheduler.key"}


def _load(name: str) -> dict[str, Any]:
    with (ROOT / name).open() as f:
        data: dict[str, Any] = yaml.safe_load(f)  # resolves YAML merge anchors
        return data


def _env(service: dict[str, Any]) -> dict[str, str]:
    env = service.get("environment", {}) or {}
    if isinstance(env, list):
        return dict(i.split("=", 1) for i in env)
    return dict(env)


def _volumes(service: dict[str, Any]) -> list[str]:
    return [str(v) for v in (service.get("volumes") or [])]


def _assert_isolation(compose: dict[str, Any], *, require_fail_closed: bool) -> None:
    services = compose["services"]
    for name, svc in services.items():
        env, vols = _env(svc), _volumes(svc)
        key_mounts = [v for v in vols if "/run/nlw/keys/" in v]
        if name in _HOLDERS:
            assert env.get("NLW_CTX_KEY_FILE") == f"/run/nlw/keys/{_HOLDERS[name]}", name
            assert "NLW_CTX_KEY_ID" in env, name
            # Exactly ONE key mount, read-only, for THIS class only.
            assert len(key_mounts) == 1, (name, key_mounts)
            assert key_mounts[0].endswith(f"/run/nlw/keys/{_HOLDERS[name]}:ro"), key_mounts
            assert f"/{_HOLDERS[name]}:" in key_mounts[0]
            if require_fail_closed:
                assert ":?" in env["NLW_CTX_KEY_ID"], f"{name} key id must be required in prod"
        else:
            assert not any(k in env for k in _KEY_ENV), f"{name} must not receive a key id/file"
            assert key_mounts == [], f"{name} must not mount a key file"
    # The three holders use three DIFFERENT key ids (env expressions) and files.
    ids = {_env(services[h])["NLW_CTX_KEY_ID"] for h in _HOLDERS}
    assert len(ids) == 3, ids


def test_dev_compose_isolates_keys() -> None:
    _assert_isolation(_load("docker-compose.yml"), require_fail_closed=False)


def test_prod_compose_isolates_keys_and_fails_closed() -> None:
    _assert_isolation(_load("docker-compose.prod.yml"), require_fail_closed=True)
    raw = (ROOT / "docker-compose.prod.yml").read_text()
    # Nothing key-related in the shared anchor block.
    anchor = raw.split("x-app-env:", 1)[1].split("x-app-hardening:", 1)[0]
    assert "NLW_CTX" not in anchor and "/run/nlw/keys" not in anchor
    # The key directory is a required host path (no silent default in prod).
    assert "${NLW_CTX_KEYS_DIR:?" in raw


def test_dev_compose_anchor_has_no_key_material() -> None:
    raw = (ROOT / "docker-compose.yml").read_text()
    anchor = raw.split("x-app-env:", 1)[1].split("x-app-hardening:", 1)[0]
    assert "NLW_CTX" not in anchor and "/run/nlw/keys" not in anchor


def test_backup_and_restore_receive_no_signing_key() -> None:
    prod = _load("docker-compose.prod.yml")["services"]
    for name in ("backup", "restore", "migrate", "web", "caddy", "postgres", "redis"):
        if name not in prod:
            continue
        env, vols = _env(prod[name]), _volumes(prod[name])
        assert not any(k.startswith("NLW_CTX") for k in env), name
        assert not any("ctx-keys" in v or "/run/nlw/keys" in v for v in vols), name


def test_env_prod_example_documents_key_provisioning() -> None:
    text = (ROOT / ".env.prod.example").read_text()
    for var in (
        "NLW_CTX_KEYS_DIR",
        "NLW_CTX_API_KEY_ID",
        "NLW_CTX_WORKER_KEY_ID",
        "NLW_CTX_SCHEDULER_KEY_ID",
    ):
        assert var in text, var
    assert "openssl rand -hex 32" in text and "signed-context-keys.md" in text
    # Never a key VALUE in the example.
    assert "NLW_CTX_KEY_FILE=" not in text and "NLW_CTX_API_KEY=" not in text


def test_key_files_are_gitignored() -> None:
    assert "docker/ctx-keys/" in (ROOT / ".gitignore").read_text()
