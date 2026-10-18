#!/usr/bin/env python3
"""Per-container AWS credential refresher (O-6, ADR-038; dataset-s3-provisioning.md §5).

Run as root by ``nlw-aws-credentials.service`` (every 15 min). For each runtime
service (api, ingest, and the unattended retention identity) it assumes ONLY
``nlw-<env>-dataset-<service>`` (1 h, the fixed session name its trust policy
requires) with the host's own identity, and writes the temporary credential to

    <root>/<service>/credentials        directory 0700, file 0400, owned by the
                                         service's container uid

atomically (temp file in the same directory, fsync, rename, fsync of the
directory). The format is the one ``nlw.storage.s3_credentials`` accepts: a
``[default]`` profile with the three temporary-credential fields and
``x_nlw_expiration`` (ISO-8601 UTC). Logs are one JSON line per service with
the role ARN, the expiry and the result: never a credential value.

The operator and restore roles trust humans only (MFA); they are never
refreshed here.

After every run it writes ``<metrics-dir>/nlw_aws_credentials.prom`` (0644,
atomically; no credential, only times and results) for the dataset exporter:
``nlw_aws_credential_refresh_last_success_timestamp_seconds``,
``nlw_aws_credential_refresh_expiry_timestamp_seconds`` and
``nlw_aws_credential_refresh_last_run_ok`` per service. A failed service keeps
its previous success time, so ``NlwDatasetCredentialRefreshStale`` fires.

Standard library only: the host does not run the application. NOT RUN against
AWS.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SERVICES: dict[str, int] = {"api": 10001, "ingest": 10002, "retention": 10005}
DURATION_S = 3600
MIN_REMAINING = timedelta(minutes=5)
BACKOFF_S = (5, 20, 60)
_ENV = re.compile(r"staging|production")
_ACCOUNT = re.compile(r"\d{12}")
# Never handed to the AWS CLI: the host's own identity (instance profile) only.
_STRIPPED_ENV = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
)

Runner = Callable[[Sequence[str], dict[str, str]], str]


class RefreshError(RuntimeError):
    """The refresh failed; the message never carries a credential value."""


def role_arn(env: str, account: str, service: str) -> str:
    if not _ENV.fullmatch(env) or not _ACCOUNT.fullmatch(account) or service not in SERVICES:
        raise RefreshError("environment, account or service is not one this refresher serves")
    return f"arn:aws:iam::{account}:role/nlw-{env}-dataset-{service}"


def session_name(env: str, service: str) -> str:
    """The fixed name each role's trust policy requires (``trust-<service>``)."""
    return f"nlw-{env}-{service}"


def _aws_cli(argv: Sequence[str], env: dict[str, str]) -> str:
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        list(argv), env=env, capture_output=True, text=True, timeout=60, check=False
    )
    if done.returncode != 0:
        raise RefreshError(f"assume-role failed (exit {done.returncode})")
    return done.stdout


def assume(env: str, account: str, service: str, run: Runner = _aws_cli) -> dict[str, Any]:
    arn = role_arn(env, account, service)
    child_env = {k: v for k, v in os.environ.items() if k not in _STRIPPED_ENV}
    child_env["AWS_REGION"] = "us-east-1"
    out = run(
        [
            "aws", "sts", "assume-role", "--role-arn", arn,
            "--role-session-name", session_name(env, service),
            "--duration-seconds", str(DURATION_S), "--output", "json",
        ],
        child_env,
    )  # fmt: skip
    try:
        creds = json.loads(out)["Credentials"]
        record = {
            "access_key": str(creds["AccessKeyId"]),
            "secret_key": str(creds["SecretAccessKey"]),
            "token": str(creds["SessionToken"]),
            "expiry": datetime.fromisoformat(str(creds["Expiration"]).replace("Z", "+00:00")),
        }
    except (ValueError, KeyError, TypeError):
        raise RefreshError("assume-role returned an unexpected document") from None
    if not all(record[k] for k in ("access_key", "secret_key", "token")):
        raise RefreshError("assume-role returned an incomplete credential")
    expiry = record["expiry"]
    if expiry.tzinfo is None or expiry - datetime.now(UTC) < MIN_REMAINING:
        raise RefreshError("assume-role returned a credential that expires too soon")
    return record


def render(record: dict[str, Any]) -> str:
    expiry = record["expiry"].astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        "[default]\n"
        f"aws_access_key_id = {record['access_key']}\n"
        f"aws_secret_access_key = {record['secret_key']}\n"
        f"aws_session_token = {record['token']}\n"
        f"x_nlw_expiration = {expiry}\n"
    )


def write_atomically(directory: Path, body: str, uid: int, *, chown: bool = True) -> Path:
    """Write ``<directory>/credentials`` (0400, owned by ``uid``) atomically."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    if chown:
        os.chown(directory, uid, uid)
    target = directory / "credentials"
    fd, tmp = tempfile.mkstemp(prefix=".credentials-", dir=directory)
    try:
        os.fchmod(fd, 0o400)
        if chown:
            os.fchown(fd, uid, uid)
        os.write(fd, body.encode())
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(tmp)
        raise
    os.close(fd)
    os.replace(tmp, target)
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return target


METRICS_FILE = "nlw_aws_credentials.prom"
_SAMPLE = re.compile(r'^(nlw_aws_credential_refresh_[a-z_]+)\{service="([a-z]+)"\} (\S+)$')


def read_metrics(directory: Path) -> dict[tuple[str, str], float]:
    try:
        lines = (directory / METRICS_FILE).read_text().splitlines()
    except OSError:
        return {}
    out: dict[tuple[str, str], float] = {}
    for line in lines:
        m = _SAMPLE.match(line)
        if m and m.group(2) in SERVICES:
            try:
                out[(m.group(1), m.group(2))] = float(m.group(3))
            except ValueError:
                continue
    return out


def write_metrics(directory: Path, samples: dict[tuple[str, str], float]) -> None:
    """Prometheus textfile, written atomically (temp file, fsync, rename)."""
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    names = (
        ("nlw_aws_credential_refresh_last_success_timestamp_seconds",
         "Unix time of the last successful refresh"),
        ("nlw_aws_credential_refresh_expiry_timestamp_seconds",
         "Unix time the last written credential expires"),
        ("nlw_aws_credential_refresh_last_run_ok", "1 if the latest run refreshed it"),
    )  # fmt: skip
    lines: list[str] = []
    for name, help_text in names:
        lines += [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"]
        for service in sorted(SERVICES):
            if (name, service) in samples:
                lines.append(f'{name}{{service="{service}"}} {samples[(name, service)]:.0f}')
    fd, tmp = tempfile.mkstemp(prefix=".metrics-", dir=directory)
    try:
        os.fchmod(fd, 0o644)
        os.write(fd, ("\n".join(lines) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, directory / METRICS_FILE)


def _log(**fields: Any) -> None:
    print(json.dumps({"event": "nlw.aws_credential_refresh", **fields}, sort_keys=True))


def refresh(
    env: str,
    account: str,
    root: Path,
    services: Sequence[str],
    *,
    run: Runner = _aws_cli,
    sleep: Callable[[float], None] = time.sleep,
    chown: bool = True,
    metrics_dir: Path | None = None,
    now: Callable[[], float] = time.time,
) -> int:
    failed = 0
    samples = read_metrics(metrics_dir) if metrics_dir is not None else {}
    for service in services:
        arn = role_arn(env, account, service)
        for attempt, pause in enumerate((0, *BACKOFF_S)):
            if pause:
                sleep(pause)
            try:
                record = assume(env, account, service, run)
                write_atomically(root / service, render(record), SERVICES[service], chown=chown)
            except (RefreshError, OSError, subprocess.TimeoutExpired) as exc:
                reason = str(exc) if isinstance(exc, RefreshError) else type(exc).__name__
                _log(role_arn=arn, result="error", attempt=attempt + 1, reason=reason)
                continue
            _log(role_arn=arn, result="ok", expiry=record["expiry"].isoformat())
            samples[("nlw_aws_credential_refresh_last_success_timestamp_seconds", service)] = now()
            samples[("nlw_aws_credential_refresh_expiry_timestamp_seconds", service)] = record[
                "expiry"
            ].timestamp()
            samples[("nlw_aws_credential_refresh_last_run_ok", service)] = 1
            break
        else:
            failed += 1
            samples[("nlw_aws_credential_refresh_last_run_ok", service)] = 0
    if metrics_dir is not None:
        try:
            write_metrics(metrics_dir, samples)
        except OSError as exc:
            _log(result="metrics_error", reason=type(exc).__name__)
            failed += 1
    return 1 if failed else 0


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="nlw_aws_credential_refresh")
    p.add_argument("--env", required=True)
    p.add_argument("--account", required=True)
    p.add_argument("--root", default="/run/nlw/aws")
    p.add_argument("--metrics-dir", default="/run/nlw/aws-metrics")
    p.add_argument("--service", action="append", choices=sorted(SERVICES))
    args = p.parse_args(argv)
    try:
        return refresh(
            args.env, args.account, Path(args.root), args.service or sorted(SERVICES),
            metrics_dir=Path(args.metrics_dir),
        )  # fmt: skip
    except RefreshError as exc:
        _log(result="refused", reason=str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
