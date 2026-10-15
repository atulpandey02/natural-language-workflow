"""O-6 dormant staging configuration (ADR-038): reviewed, rendered and pinned,
and provably inert. No host, no AWS."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from nlw.core.config import Settings
from nlw.ops.rollout import remote
from nlw.storage.s3_credentials import read_credentials_file

ROOT = Path(__file__).resolve().parents[2]
OVERLAY = "docker-compose.datasets.yml"
SYSTEMD = ROOT / "docker/systemd"
PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"

_spec = importlib.util.spec_from_file_location(
    "nlw_aws_credential_refresh", ROOT / "scripts/ops/nlw_aws_credential_refresh.py"
)
assert _spec is not None and _spec.loader is not None
refresher = importlib.util.module_from_spec(_spec)
sys.modules["nlw_aws_credential_refresh"] = refresher
_spec.loader.exec_module(refresher)


def _required(*names: str) -> set[str]:
    found: set[str] = set()
    for name in names:
        found |= set(re.findall(r"\$\{([A-Z0-9_]+):\?", (ROOT / name).read_text()))
    return found


def _render(*profiles: str, overlay: bool = True) -> dict[str, Any]:
    files = ["docker-compose.prod.yml", "docker-compose.staging.yml"]
    if overlay:
        files.append(OVERLAY)
    env = {k: f"dummy-{k}" for k in _required(*files)}
    env["NLW_CTX_KEYS_DIR"] = "/srv/nlw/ctx-keys"
    args = ["docker", "compose"]
    for f in files:
        args += ["-f", f]
    for profile in profiles:
        args += ["--profile", profile]
    p = subprocess.run(
        [*args, "config", "--format", "json"], cwd=ROOT, env={**env, "PATH": PATH},
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    if p.returncode != 0:
        if "docker" in p.stderr.lower() and "not found" in p.stderr.lower():
            pytest.skip("docker compose unavailable")
        raise AssertionError(p.stderr[-400:])
    doc: dict[str, Any] = json.loads(p.stdout)
    return doc


@pytest.fixture(scope="module")
def services() -> dict[str, Any]:
    return dict(_render("datasets", "operator")["services"])


def _aws_mounts(service: dict[str, Any]) -> list[tuple[str, str, bool]]:
    return [
        (str(v.get("source")), str(v.get("target")), bool(v.get("read_only")))
        for v in service.get("volumes") or []
        if "/run/nlw/aws" in str(v.get("source")) + str(v.get("target"))
    ]


# --- never part of the reviewed rollout -------------------------------------------


def test_the_rollout_never_renders_the_dataset_overlay() -> None:
    assert OVERLAY not in json.dumps(remote.__dict__.get("DEFAULT_COMPOSE_FILES", ""))
    for directory in ("src", "scripts", ".github"):
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and path.suffix in (".py", ".sh", ".yml", ".yaml", ".json"):
                assert OVERLAY not in path.read_text(errors="ignore"), path
    rollout = (ROOT / "src/nlw/ops/rollout/remote.py").read_text()
    assert '"docker-compose.prod.yml", "docker-compose.staging.yml"' in rollout


def test_without_the_overlay_staging_is_exactly_as_reviewed() -> None:
    reviewed = _render(overlay=False)["services"]
    assert not {"ingest", "ingest-dispatch", "operator", "node-exporter-datasets"} & set(reviewed)
    assert "DATASETS_API_ENABLED" not in reviewed["api"].get("environment", {})
    assert not _aws_mounts(reviewed["api"])


# --- the overlay: inert, isolated, hardened ---------------------------------------


def test_dataset_runtimes_run_only_under_their_profiles() -> None:
    default = _render()["services"]
    assert not {"ingest", "ingest-dispatch", "operator", "node-exporter-datasets"} & set(default)
    raw = yaml.safe_load((ROOT / OVERLAY).read_text())["services"]
    assert raw["ingest"]["profiles"] == ["datasets"]
    assert raw["ingest-dispatch"]["profiles"] == ["datasets"]
    assert raw["node-exporter-datasets"]["profiles"] == ["datasets"]
    assert raw["operator"]["profiles"] == ["operator"]
    assert raw["operator"]["restart"] == "no"


def test_the_flag_stays_off_and_configuration_refuses_it(services: dict[str, Any]) -> None:
    env = services["api"]["environment"]
    assert env["DATASETS_API_ENABLED"] == "false"
    dataset = {
        "dataset_storage_backend": env["DATASET_STORAGE_BACKEND"],
        "dataset_s3_bucket": "nlw-staging-datasets-111122223333-us-east-1",
        "dataset_s3_region": env["DATASET_S3_REGION"],
        "dataset_s3_kms_key_arn": (
            "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"
        ),
        "dataset_s3_prefix": env["DATASET_S3_PREFIX"],
    }
    assert Settings(app_env="staging", **dataset).datasets_api_enabled is False
    with pytest.raises(ValidationError, match="DATASETS_API_ENABLED is not allowed"):
        Settings(app_env="staging", datasets_api_enabled=True, **dataset)


def test_each_container_mounts_only_its_own_credentials(services: dict[str, Any]) -> None:
    expected = {
        "api": [("/run/nlw/aws/api", "/run/nlw/aws", True)],
        "ingest": [("/run/nlw/aws/ingest", "/run/nlw/aws", True)],
        "operator": [("/run/nlw/aws/operator", "/run/nlw/aws", True)],
    }
    for name, service in services.items():
        assert _aws_mounts(service) == expected.get(name, []), name
        env = service.get("environment") or {}
        assert not {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} & set(env)
        if name in expected:
            assert env["AWS_SHARED_CREDENTIALS_FILE"] == "/run/nlw/aws/credentials"
            assert env["AWS_EC2_METADATA_DISABLED"] == "true"
        elif name not in ("backup", "restore"):
            assert not any(k.startswith("AWS_") for k in env), name


def test_runtimes_have_separate_users_keys_and_credentials(services: dict[str, Any]) -> None:
    users = {n: services[n]["user"] for n in ("api", "ingest", "ingest-dispatch", "operator")}
    assert users == {
        "api": "10001:10001", "ingest": "10002:10002",
        "ingest-dispatch": "10003:10003", "operator": "10004:10004",
    }  # fmt: skip
    for name, service in services.items():
        blob = json.dumps(service.get("volumes") or [])
        assert ("ingest.key" in blob) is (name == "ingest"), name
        env = service.get("environment") or {}
        assert ("DATABASE_MIGRATION_URL" in env) is (name in ("migrate", "operator")), name
    dispatch = services["ingest-dispatch"]
    assert set(dispatch["environment"]) == {"APP_ENV", "LOG_LEVEL", "DATABASE_URL", "REDIS_URL"}
    assert services["ingest"]["environment"]["APP_ENV"] == "staging"
    assert services["operator"]["environment"]["DATASET_DELETION_LOG"] == "s3"


@pytest.mark.parametrize("name", ["ingest", "ingest-dispatch", "operator"])
def test_dataset_runtimes_are_hardened_like_the_reviewed_api(
    services: dict[str, Any], name: str
) -> None:
    keys = ("read_only", "cap_drop", "security_opt", "mem_limit", "pids_limit", "cpus", "image")
    api, svc = services["api"], services[name]
    assert {k: svc.get(k) for k in keys} == {k: api.get(k) for k in keys}
    assert list(svc["networks"]) == ["internal"] and not svc.get("ports")


def test_the_dataset_exporter_reads_its_own_volume_only(services: dict[str, Any]) -> None:
    exp = services["node-exporter-datasets"]
    assert [(v["source"], v["target"], v.get("read_only")) for v in exp["volumes"]] == [
        ("datasets_textfile", "/textfile", True)
    ]
    op = [v["source"] for v in services["operator"]["volumes"]]
    assert "datasets_textfile" in op
    backup = [v["source"] for v in services["node-exporter"]["volumes"]]
    assert backup == ["backup_textfile"]


# --- Prometheus: the reviewed config plus exactly the dataset additions -----------


def test_the_dataset_prometheus_config_only_adds_the_dataset_alerts_and_targets(
    services: dict[str, Any],
) -> None:
    base = yaml.safe_load((ROOT / "docker/prometheus/prometheus.yml").read_text())
    ext = yaml.safe_load((ROOT / "docker/prometheus/prometheus.datasets.yml").read_text())
    assert ext["rule_files"] == [*base["rule_files"], "alerts/datasets.rules.yml"]
    added = ext["scrape_configs"][len(base["scrape_configs"]) :]
    assert ext["scrape_configs"][: len(base["scrape_configs"])] == base["scrape_configs"]
    assert [(j["job_name"], j["static_configs"][0]["targets"]) for j in added] == [
        ("nlw-ingest", ["ingest:9100"]),
        ("nlw-ingest-dispatch", ["ingest-dispatch:9100"]),
        ("nlw-datasets", ["node-exporter-datasets:9100"]),
    ]
    assert {k: v for k, v in ext.items() if k not in ("rule_files", "scrape_configs")} == {
        k: v for k, v in base.items() if k not in ("rule_files", "scrape_configs")
    }
    mounts = {v["target"]: v["source"] for v in services["prometheus"]["volumes"]}
    assert mounts["/etc/prometheus/prometheus.yml"].endswith("prometheus.datasets.yml")


# --- the credential refresher ------------------------------------------------------

SECRET = "SENTINEL-SECRET-VALUE"
TOKEN = "SENTINEL-SESSION-TOKEN"


def _fake(expiry: datetime, calls: list[tuple[list[str], dict[str, str]]]) -> Any:
    def run(argv: Any, env: dict[str, str]) -> str:
        calls.append((list(argv), env))
        return json.dumps(
            {
                "Credentials": {
                    "AccessKeyId": "ASIA" + "Q" * 16,
                    "SecretAccessKey": SECRET,
                    "SessionToken": TOKEN,
                    "Expiration": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            }
        )

    return run


def test_the_refresher_writes_a_file_the_application_accepts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AK" + "IA" + "Q" * 16)
    calls: list[tuple[list[str], dict[str, str]]] = []
    expiry = datetime.now(UTC).replace(microsecond=0) + timedelta(hours=1)
    code = refresher.refresh(
        "staging", "111122223333", tmp_path, ["api", "ingest"],
        run=_fake(expiry, calls), sleep=lambda s: None, chown=False,
    )  # fmt: skip
    assert code == 0
    for service in ("api", "ingest"):
        directory = tmp_path / service
        assert directory.stat().st_mode & 0o777 == 0o700
        path = directory / "credentials"
        assert path.stat().st_mode & 0o777 == 0o400
        creds = read_credentials_file(str(path))
        assert creds.secret_key == SECRET and creds.token == TOKEN and creds.expiry == expiry
        assert [p.name for p in directory.iterdir()] == ["credentials"]  # no temp file left
    argv = [c[0] for c in calls]
    assert [a[a.index("--role-arn") + 1] for a in argv] == [
        "arn:aws:iam::111122223333:role/nlw-staging-dataset-api",
        "arn:aws:iam::111122223333:role/nlw-staging-dataset-ingest",
    ]
    assert all(a[a.index("--duration-seconds") + 1] == "3600" for a in argv)
    assert [a[a.index("--role-session-name") + 1] for a in argv] == [
        "nlw-staging-api-refresher", "nlw-staging-ingest-refresher",
    ]  # fmt: skip
    assert all("AWS_ACCESS_KEY_ID" not in env for _, env in calls)
    out = capsys.readouterr().out
    assert SECRET not in out and TOKEN not in out and "ASIA" not in out
    assert out.count('"result": "ok"') == 2


def test_the_refresher_serves_only_the_api_and_ingest_roles() -> None:
    assert set(refresher.SERVICES) == {"api", "ingest"}
    for service in ("operator", "restore", "bootstrap"):
        with pytest.raises(refresher.RefreshError):
            refresher.role_arn("staging", "111122223333", service)
    for env, account in (("dev", "111122223333"), ("staging", "1234")):
        with pytest.raises(refresher.RefreshError):
            refresher.role_arn(env, account, "api")


def test_a_failing_or_short_lived_refresh_writes_nothing_and_fails(tmp_path: Path) -> None:
    pauses: list[float] = []
    soon = datetime.now(UTC) + timedelta(minutes=2)
    code = refresher.refresh(
        "staging", "111122223333", tmp_path, ["api"],
        run=_fake(soon, []), sleep=pauses.append, chown=False,
    )  # fmt: skip
    assert code == 1 and pauses == list(refresher.BACKOFF_S)
    assert not (tmp_path / "api" / "credentials").exists()

    def broken(argv: Any, env: dict[str, str]) -> str:
        raise refresher.RefreshError("assume-role failed (exit 255)")

    assert refresher.refresh(
        "staging", "111122223333", tmp_path, ["api"], run=broken, sleep=lambda s: None,
        chown=False,
    ) == 1  # fmt: skip


# --- systemd units and the settings template ---------------------------------------


def test_the_units_run_only_the_reviewed_commands() -> None:
    timer = (SYSTEMD / "nlw-aws-credentials.timer").read_text()
    assert "OnUnitActiveSec=15min" in timer
    svc = (SYSTEMD / "nlw-aws-credentials.service").read_text()
    assert "scripts/ops/nlw_aws_credential_refresh.py" in svc and "--service" not in svc
    assert "operator" not in svc.split("[Service]")[1].split("StandardOutput")[0]
    retention = (SYSTEMD / "nlw-dataset-retention.service").read_text()
    runs = [line for line in retention.splitlines() if "nlw.ops.datasets" in line]
    assert len(runs) == 2
    assert "retention-sweep" in runs[0] and "reconcile-receipts" in runs[1]
    assert retention.count("--profile operator") == 2 and retention.count("--no-deps") >= 2
    assert "OnCalendar=" in (SYSTEMD / "nlw-dataset-retention.timer").read_text()
    for unit in SYSTEMD.glob("nlw-*"):
        assert "DORMANT" in unit.read_text() or unit.name.startswith("nlw-backup"), unit


def test_the_settings_template_holds_placeholders_only() -> None:
    text = (ROOT / "deploy/staging/datasets.env.example").read_text()
    keys = {line.split("=", 1)[0] for line in text.splitlines() if "=" in line and line[0] != "#"}
    assert keys == _required(OVERLAY) - _required("docker-compose.prod.yml") - {
        "REDIS_URL", "NLW_IMAGE", "NLW_CTX_KEYS_DIR",
    }  # fmt: skip
    assert re.search(r"\b\d{12}\b", text) is None
    assert all("<" in line for line in text.splitlines() if "=" in line and line[0] != "#")
