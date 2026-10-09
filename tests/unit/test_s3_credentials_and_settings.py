"""Pinned short-lived credentials and S3 configuration refusals (ADR-033 D3/D5).
No network, no AWS."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from nlw.core.config import Settings
from nlw.storage import s3_credentials as creds

ACCOUNT = "111122223333"
OTHER_ACCOUNT = "444455556666"
KEY = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/11111111-2222-3333-4444-555555555555"
NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def _bucket(env: str, account: str = ACCOUNT) -> str:
    return f"nlw-{env}-datasets-{account}-us-east-1"


def _file(tmp_path: Path, *, mode: int = 0o400, expiry: datetime | None = None,
          token: bool = True, extra: str = "") -> str:  # fmt: skip
    path = tmp_path / "credentials"
    lines = [
        "[default]",
        "aws_access_key_id = ASIAEXAMPLEEXAMPLE",
        "aws_secret_access_key = s3cr3t",
    ]
    if token:
        lines.append("aws_session_token = t0ken")
    if expiry is not None:
        lines.append(f"x_nlw_expiration = {expiry.isoformat().replace('+00:00', 'Z')}")
    path.write_text("\n".join(lines) + "\n" + extra)
    os.chmod(path, mode)
    return str(path)


# --- the credential file -------------------------------------------------------------------


def test_a_private_temporary_credential_file_is_accepted(tmp_path: Path) -> None:
    c = creds.read_credentials_file(_file(tmp_path, expiry=NOW + timedelta(hours=1)), now=NOW)
    assert (c.access_key, c.token) == ("ASIAEXAMPLEEXAMPLE", "t0ken")
    assert c.expiry == NOW + timedelta(hours=1)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"mode": 0o440}, "private"),
        ({"mode": 0o404}, "private"),
        ({"token": False}, "temporary"),
        ({"expiry": None}, "temporary"),
        ({"expiry": NOW - timedelta(seconds=1)}, "expired"),
        ({"expiry": NOW + timedelta(seconds=creds.MIN_REMAINING_S - 1)}, "expired"),
    ],
)
def test_unsafe_static_or_expiring_credentials_are_refused(
    tmp_path: Path, kwargs: dict[str, Any], match: str
) -> None:
    kwargs.setdefault("expiry", NOW + timedelta(hours=1))
    with pytest.raises(creds.CredentialError, match=match) as exc:
        creds.read_credentials_file(_file(tmp_path, **kwargs), now=NOW)
    assert "s3cr3t" not in str(exc.value) and "t0ken" not in str(exc.value)


def test_a_missing_or_unreadable_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(creds.CredentialError, match="required"):
        creds.read_credentials_file(None)
    with pytest.raises(creds.CredentialError, match="missing"):
        creds.read_credentials_file(str(tmp_path / "absent"))
    with pytest.raises(creds.CredentialError, match="malformed"):
        creds.read_credentials_file(_file(tmp_path, extra="[default]\n"), now=NOW)


def test_static_keys_in_the_environment_are_refused() -> None:
    with pytest.raises(creds.CredentialError, match="static"):
        creds.refuse_static_environment({"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE"})
    with pytest.raises(creds.CredentialError, match="static"):
        creds.refuse_static_environment({"AWS_SECRET_ACCESS_KEY": "x"})
    creds.refuse_static_environment({"AWS_SHARED_CREDENTIALS_FILE": "/run/nlw/aws/api/c"})


def test_the_sdk_chain_is_pinned_to_the_file_and_never_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even with a profile, a config file and a container-credentials endpoint
    in the environment, the session yields ONLY the file's credentials."""
    path = _file(tmp_path, expiry=datetime.now(UTC) + timedelta(hours=1))
    other = tmp_path / "other"
    other.write_text("[default]\naws_access_key_id = OTHER\naws_secret_access_key = OTHER\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(other))
    monkeypatch.setenv("AWS_PROFILE", "default")
    monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.2/creds")
    session = creds._session(creds._refreshable(path), "us-east-1")
    got = session.get_credentials().get_frozen_credentials()
    assert (got.access_key, got.token) == ("ASIAEXAMPLEEXAMPLE", "t0ken")
    providers = session.get_component("credential_provider").providers
    assert [p.METHOD for p in providers] == ["nlw-credential-file"]  # no env/IMDS/container


# --- identity ------------------------------------------------------------------------------


class _Sts:
    def __init__(self, arn: str, account: str) -> None:
        self.ident = {"Arn": arn, "Account": account}

    def get_caller_identity(self) -> dict[str, str]:
        return self.ident


def _arn(role: str, account: str = ACCOUNT) -> str:
    return f"arn:aws:sts::{account}:assumed-role/{role}/nlw-session"


@pytest.mark.parametrize("service", ["api", "ingest", "operator"])
def test_the_expected_assumed_role_is_accepted(service: creds.Service) -> None:
    arn = creds.verify_identity(
        _Sts(_arn(f"nlw-staging-dataset-{service}"), ACCOUNT), _bucket("staging"), service
    )
    assert arn == f"arn:aws:iam::{ACCOUNT}:role/nlw-staging-dataset-{service}"


@pytest.mark.parametrize(
    ("arn", "account", "service"),
    [
        (_arn("nlw-staging-dataset-ingest"), ACCOUNT, "api"),  # another service's role
        (_arn("nlw-staging-dataset-bootstrap"), ACCOUNT, "api"),  # the instance role
        (_arn("nlw-production-dataset-api"), ACCOUNT, "api"),  # another environment
        (_arn("nlw-staging-dataset-api", OTHER_ACCOUNT), OTHER_ACCOUNT, "api"),  # other account
        (f"arn:aws:iam::{ACCOUNT}:user/someone", ACCOUNT, "api"),  # a long-lived user
        (f"arn:aws:sts::{ACCOUNT}:federated-user/x", ACCOUNT, "api"),
    ],
)
def test_any_other_identity_is_refused(arn: str, account: str, service: str) -> None:
    with pytest.raises(creds.CredentialError):
        creds.verify_identity(_Sts(arn, account), _bucket("staging"), service)  # type: ignore[arg-type]


def test_an_unverifiable_identity_is_refused() -> None:
    class Down:
        def get_caller_identity(self) -> dict[str, str]:
            raise ConnectionError("sts unreachable")

    with pytest.raises(creds.CredentialError, match="could not be verified"):
        creds.verify_identity(Down(), _bucket("staging"), "api")


# --- configuration -------------------------------------------------------------------------


def _s3(**kw: Any) -> Settings:
    env = kw.pop("app_env", "local")
    base: dict[str, Any] = {
        "app_env": env,
        "dataset_storage_backend": "s3",
        "dataset_s3_bucket": _bucket("local" if env in ("local", "dev") else env),
        "dataset_s3_region": "us-east-1",
        "dataset_s3_kms_key_arn": KEY,
    }
    if env in ("staging", "production"):
        base.update(nlw_llm_model="claude-x", nlw_llm_provider="anthropic")
    return Settings(**{**base, **kw})


def test_a_valid_configuration_is_accepted() -> None:
    assert _s3().dataset_s3_prefix == "versions"
    assert _s3(dataset_s3_bucket=_bucket("staging")).dataset_s3_bucket  # the D6 proof session


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"dataset_s3_bucket": "my-bucket"}, "DATASET_S3_BUCKET"),
        ({"dataset_s3_bucket": _bucket("production")}, "production dataset bucket"),
        ({"dataset_s3_region": "eu-west-1"}, "us-east-1"),
        ({"dataset_s3_kms_key_arn": f"arn:aws:kms:us-east-1:{ACCOUNT}:alias/nlw"}, "KMS"),
        ({"dataset_s3_kms_key_arn": KEY.replace(ACCOUNT, OTHER_ACCOUNT)}, "account"),
        ({"dataset_s3_kms_key_arn": KEY.replace("us-east-1", "us-west-2")}, "KMS"),
        ({"dataset_s3_prefix": "quarantine"}, "versions"),
        ({"dataset_s3_endpoint_url": "http://localhost:9000"}, "https"),
    ],
)
def test_misconfigured_s3_settings_are_refused(kw: dict[str, Any], match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        _s3(**kw)


@pytest.mark.parametrize("env", ["staging", "production"])
def test_deployed_environments_refuse_other_environments_and_dev_knobs(env: str) -> None:
    other = "production" if env == "staging" else "staging"
    with pytest.raises(ValidationError, match="belongs to"):
        _s3(app_env=env, dataset_s3_bucket=_bucket(other))
    with pytest.raises(ValidationError, match="belongs to"):
        _s3(app_env=env, dataset_s3_bucket=_bucket("local"))
    with pytest.raises(ValidationError, match="development only"):
        _s3(app_env=env, dataset_s3_endpoint_url="https://minio.example")
    with pytest.raises(ValidationError, match="development only"):
        _s3(app_env=env, dataset_s3_path_style=True)
    # Uploads stay refused in staging and production with S3 configured.
    with pytest.raises(ValidationError, match="DATASETS_API_ENABLED|datasets"):
        _s3(app_env=env, datasets_api_enabled=True)
    assert _s3(app_env=env).dataset_s3_bucket == _bucket(env)


def test_static_credentials_and_the_backup_bucket_are_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
    with pytest.raises(ValidationError, match="static"):
        _s3()
    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    for repo in (
        f"s3:https://s3.us-east-1.amazonaws.com/{_bucket('local')}/nlw",
        f"s3:s3.amazonaws.com/{_bucket('local')}",
    ):
        with pytest.raises(ValidationError, match="backup repository"):
            _s3(RESTIC_REPOSITORY=repo)


def test_no_application_service_receives_static_aws_keys() -> None:
    """ADR-033 D3: the API, ingest, dispatcher, worker, scheduler and web
    services never receive AWS access keys from Compose. (The backup service's
    Restic credentials are a separate, pre-existing O-4 concern.)"""
    import yaml

    root = Path(__file__).resolve().parents[2]
    app = {"api", "ingest", "ingest-dispatch", "worker", "scheduler", "web", "migrate"}
    for name in ("docker-compose.prod.yml", "docker-compose.staging.yml", "docker-compose.yml"):
        doc = yaml.safe_load((root / name).read_text()) or {}
        for svc, spec in (doc.get("services") or {}).items():
            if svc not in app:
                continue
            env = spec.get("environment") or {}
            names = set(env) if isinstance(env, dict) else {e.split("=", 1)[0] for e in env}
            assert not names & {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}, (name, svc)
