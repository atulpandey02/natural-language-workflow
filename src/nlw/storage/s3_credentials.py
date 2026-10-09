"""Pinned, short-lived AWS credentials for the S3 dataset store (ADR-033 D3).

Each process that touches S3 (the upload API, the ingest runtime, the operator
CLI) reads ONE credential file, named by ``AWS_SHARED_CREDENTIALS_FILE`` and
written by the host refresher (or, for the operator, from an MFA session):

    [default]
    aws_access_key_id = ...
    aws_secret_access_key = ...
    aws_session_token = ...
    x_nlw_expiration = 2026-10-09T15:00:00Z

Rules, all fail-closed:

- the SDK's credential chain is NOT used: the client receives credentials from
  this file only, so there is never a fallback to environment variables, a
  profile, a container provider or the EC2 instance role (IMDS);
- static credentials are refused: the environment must not hold
  ``AWS_ACCESS_KEY_ID``/``AWS_SECRET_ACCESS_KEY``, and the file must hold a
  session token and an expiry;
- the file must be private (no group/other access), present and readable;
- credentials that are expired or expire within ``MIN_REMAINING_S`` are
  refused at startup; while running they are re-read before expiry
  (rotation is the refresher's atomic rename);
- at startup ``sts:GetCallerIdentity`` must name the expected assumed role
  ``nlw-<env>-dataset-<service>`` in the account the bucket belongs to. Only the
  role ARN and account are logged, never a credential.
"""

from __future__ import annotations

import configparser
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import structlog

from nlw.core.config import Settings
from nlw.observability.metrics import set_dataset_s3_credential_expiry

log = structlog.get_logger(__name__)

Service = Literal["api", "ingest", "operator"]
MIN_REMAINING_S = 300
CREDENTIALS_ENV = "AWS_SHARED_CREDENTIALS_FILE"
STATIC_ENV = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
_BUCKET = re.compile(
    r"^nlw-(?P<env>local|dev|staging|production)-datasets-(?P<account>\d{12})-us-east-1"
    r"(?:-[a-z0-9]{1,16})?$"
)


class CredentialError(RuntimeError):
    """Credentials are missing, static, expired, exposed or of the wrong
    identity. Messages never contain a credential value or a path."""


@dataclass(frozen=True)
class BucketIdentity:
    env: str
    account: str


def bucket_identity(bucket: str) -> BucketIdentity:
    m = _BUCKET.match(bucket)
    if m is None:
        raise CredentialError("the dataset bucket name does not follow the ADR-033 pattern")
    return BucketIdentity(env=m.group("env"), account=m.group("account"))


def expected_role(bucket: str, service: Service) -> tuple[str, str]:
    """(role name, account) the process must be running as."""
    ident = bucket_identity(bucket)
    return f"nlw-{ident.env}-dataset-{service}", ident.account


def refuse_static_environment(environ: dict[str, str] | None = None) -> None:
    env = os.environ if environ is None else environ
    if any(env.get(name) for name in STATIC_ENV):
        raise CredentialError(
            "static AWS credentials in the environment are refused (ADR-033 D3/D5)"
        )


@dataclass(frozen=True)
class FileCredentials:
    access_key: str
    secret_key: str
    token: str
    expiry: datetime


def read_credentials_file(path: str | None, *, now: datetime | None = None) -> FileCredentials:
    """Parse and validate the credential file (never logs its contents)."""
    if not path:
        raise CredentialError(f"{CREDENTIALS_ENV} is required for the S3 dataset store")
    try:
        st = os.stat(path)
    except OSError:
        raise CredentialError("the AWS credential file is missing or unreadable") from None
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        raise CredentialError("the AWS credential file must be a private regular file")
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, encoding="utf-8") as fh:
            parser.read_file(fh)
        section = parser["default"]
        creds = (
            section["aws_access_key_id"].strip(),
            section["aws_secret_access_key"].strip(),
            section.get("aws_session_token", "").strip(),
        )
        raw_expiry = section.get("x_nlw_expiration", "").strip()
    except (OSError, KeyError, configparser.Error):
        raise CredentialError("the AWS credential file is malformed") from None
    if not all(creds[:2]):
        raise CredentialError("the AWS credential file is malformed")
    if not creds[2] or not raw_expiry:
        raise CredentialError(
            "only temporary credentials are accepted (session token and expiry required)"
        )
    try:
        expiry = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
    except ValueError:
        raise CredentialError("the AWS credential expiry is malformed") from None
    if expiry.tzinfo is None:
        raise CredentialError("the AWS credential expiry must carry a timezone")
    current = now or datetime.now(UTC)
    remaining = (expiry - current).total_seconds()
    set_dataset_s3_credential_expiry(remaining)
    if remaining < MIN_REMAINING_S:
        raise CredentialError("the AWS credentials are expired or about to expire")
    return FileCredentials(creds[0], creds[1], creds[2], expiry.astimezone(UTC))


def _refreshable(path: str) -> Any:
    """botocore credentials sourced ONLY from the file, re-read before expiry."""
    from botocore.credentials import RefreshableCredentials

    def load() -> dict[str, str]:
        c = read_credentials_file(path)
        return {
            "access_key": c.access_key,
            "secret_key": c.secret_key,
            "token": c.token,
            "expiry_time": c.expiry.isoformat(),
        }

    return RefreshableCredentials.create_from_metadata(
        metadata=load(), refresh_using=load, method="nlw-credential-file"
    )


def _session(credentials: Any, region: str) -> Any:
    """A botocore session whose credential chain is replaced by ``credentials``
    alone: no environment, profile, container or IMDS provider can be used."""
    import botocore.session
    from botocore.credentials import CredentialResolver

    class _Pinned:
        METHOD = "nlw-credential-file"
        CANONICAL_NAME = "nlw-credential-file"

        def load(self) -> Any:
            return credentials

    session = botocore.session.Session()
    session.register_component("credential_provider", CredentialResolver(providers=[_Pinned()]))
    session.set_config_variable("region", region)
    return session


def _client_config(settings: Settings) -> Any:
    from botocore.config import Config

    return Config(
        region_name=settings.dataset_s3_region,
        signature_version="s3v4",
        retries={"mode": "standard", "max_attempts": 3},
        connect_timeout=5,
        read_timeout=30,
        s3={"addressing_style": "path" if settings.dataset_s3_path_style else "virtual"},
    )


def verify_identity(sts: Any, bucket: str, service: Service) -> str:
    """``GetCallerIdentity`` must be the expected assumed role in the bucket's
    account. Returns the role ARN (safe to log)."""
    role, account = expected_role(bucket, service)
    try:
        ident = sts.get_caller_identity()
    except Exception as exc:
        raise CredentialError(
            f"the AWS identity could not be verified ({type(exc).__name__})"
        ) from None
    arn = str(ident.get("Arn") or "")
    m = re.match(r"^arn:aws:sts::(\d{12}):assumed-role/([A-Za-z0-9+=,.@_-]+)/[^/]+$", arn)
    if m is None or ident.get("Account") != account or m.group(1) != account:
        raise CredentialError("the AWS identity is not an assumed role in the bucket's account")
    if m.group(2) != role:
        raise CredentialError(f"the AWS identity is not the expected role {role}")
    return f"arn:aws:iam::{account}:role/{role}"


def build_clients(settings: Settings, service: Service) -> tuple[Any, str]:
    """(S3 client, verified role ARN) for ``service``. Raises ``CredentialError``."""
    refuse_static_environment()
    assert settings.dataset_s3_bucket and settings.dataset_s3_region  # Settings validated
    path = os.environ.get(CREDENTIALS_ENV)
    read_credentials_file(path)  # fail fast with a precise reason
    assert path is not None
    session = _session(_refreshable(path), settings.dataset_s3_region)
    config = _client_config(settings)
    s3 = session.create_client(
        "s3", config=config, endpoint_url=settings.dataset_s3_endpoint_url or None
    )
    sts = session.create_client(
        "sts", config=config, endpoint_url=f"https://sts.{settings.dataset_s3_region}.amazonaws.com"
    )
    role_arn = verify_identity(sts, settings.dataset_s3_bucket, service)
    log.info(
        "dataset.s3_identity",
        service=service,
        role_arn=role_arn,
        account=bucket_identity(settings.dataset_s3_bucket).account,
    )
    return s3, role_arn


def remaining_seconds(expiry: datetime, now: datetime | None = None) -> float:
    return (expiry - (now or datetime.now(UTC))).total_seconds()


__all__ = [
    "MIN_REMAINING_S",
    "BucketIdentity",
    "CredentialError",
    "FileCredentials",
    "Service",
    "bucket_identity",
    "build_clients",
    "expected_role",
    "read_credentials_file",
    "refuse_static_environment",
    "remaining_seconds",
    "verify_identity",
]
