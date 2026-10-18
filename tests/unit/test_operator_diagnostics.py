"""Operator-safe diagnostics (O-3 review, ADR-034/ADR-035).

- Known operational failures keep their author-controlled reason; the raise
  sites of those exception types are pinned, so a new interpolation must be
  reviewed here first.
- A message that looks like it carries an identifier, a location, SQL or a
  secret is reduced to its class.
- Configuration errors name the setting, never the rejected value.
- The operator role must be at IAM path ``/`` before any purge.
"""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

import psycopg
import pytest
from pydantic import ValidationError

from nlw.backup.recovery_lock import RecoveryLocked, RecoveryStateUnknown
from nlw.core.config import Settings
from nlw.datasets.deletion_log import DeletionLogUnavailable
from nlw.ops import datasets as ops
from nlw.storage.blob import BlobUnavailable
from nlw.storage.s3_credentials import CredentialError, read_credentials_file, verify_role_path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "receipt_s3_fake", Path(__file__).with_name("receipt_s3_fake.py")
)
assert _spec is not None and _spec.loader is not None
fake = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("receipt_s3_fake", fake)
_spec.loader.exec_module(fake)

SAFE = {cls.__name__ for cls in ops.SAFE_MESSAGE_TYPES}

# Every value a safe exception's message may interpolate, by module. Anything
# else (a key, a bucket, a path, an exception's own text) fails this test.
PINNED_INTERPOLATIONS = {
    ("deletion_log_s3.py", "code or type(exc).__name__"),
    ("s3.py", "op"),  # a literal operation name, see test below
    ("s3.py", "reason"),  # a literal refusal reason, see test below
    ("s3.py", "type(exc).__name__"),
    ("s3_credentials.py", "CREDENTIALS_ENV"),
    ("s3_credentials.py", "code or type(exc).__name__"),
    ("s3_credentials.py", "role"),  # the expected role NAME (nlw-<env>-dataset-<service>)
    ("s3_credentials.py", "type(exc).__name__"),
}
# Non-literal messages: module constants, an enum value, or a re-raise of a
# pinned safe exception's own (already pinned) text.
PINNED_EXPRESSIONS = {
    ("deletion_log_s3.py", "status"),
    ("deletion_log_s3.py", "_NOT_ASKED"),
    ("deletion_log.py", "_UNCONFIGURED"),
    ("datasets.py", "str(exc)"),
}


def _safe_types(files: list[Path]) -> set[str]:
    names = set(SAFE) | {"ReceiptUnreadable"}
    grown = True
    while grown:
        grown = False
        for f in files:
            for node in ast.walk(ast.parse(f.read_text())):
                if (
                    isinstance(node, ast.ClassDef)
                    and node.name not in names
                    and any(isinstance(b, ast.Name) and b.id in names for b in node.bases)
                ):
                    names.add(node.name)
                    grown = True
    return names


def test_every_safe_message_is_author_controlled() -> None:
    files = sorted((ROOT / "src/nlw").rglob("*.py"))
    safe = _safe_types(files)
    interpolations, expressions = set(), set()
    for f in files:
        for node in ast.walk(ast.parse(f.read_text())):
            if not (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)):
                continue
            fn = node.exc.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if name not in safe or not node.exc.args:
                continue
            arg = node.exc.args[0]
            if isinstance(arg, ast.Constant):
                assert isinstance(arg.value, str)
            elif isinstance(arg, ast.JoinedStr):
                for part in arg.values:
                    if isinstance(part, ast.FormattedValue):
                        interpolations.add((f.name, ast.unparse(part.value)))
            else:
                expressions.add((f.name, ast.unparse(arg)))
    assert interpolations == PINNED_INTERPOLATIONS
    assert expressions == PINNED_EXPRESSIONS


def test_the_interpolated_s3_operation_and_reason_are_literals() -> None:
    tree = ast.parse((ROOT / "src/nlw/storage/s3.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) in (
            "_call",
            "_refuse_listing",
        ):
            assert isinstance(node.args[0], ast.Constant), ast.unparse(node)


# --- the guard ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        CredentialError("the AWS credentials are expired or about to expire"),
        CredentialError("the AWS identity is not the expected role nlw-staging-dataset-operator"),
        CredentialError("AWS_SHARED_CREDENTIALS_FILE is required for the S3 dataset store"),
        BlobUnavailable("list_object_versions failed"),
        DeletionLogUnavailable("the deletion log bucket has no Object Lock default retention"),
        RecoveryLocked("newest restore generation is validated but not operator-enabled"),
        RecoveryStateUnknown("cannot read authoritative recovery-lock state"),
    ],
)
def test_a_safe_message_keeps_its_reason(exc: BaseException) -> None:
    assert ops.safe_message(exc) == f"{type(exc).__name__}: {exc}"


@pytest.mark.parametrize(
    "text",
    [
        "denied for arn:aws:iam::111122223333:role/x",
        "account 111122223333 not allowed",
        "bucket nlw-staging-datasets-111122223333-us-east-1 missing",
        "bucket nlw-staging-deletion-receipts-x missing",
        "key versions/t/d/v/source.csv",
        "receipts/t/d/v/r.json not found",
        "endpoint https://s3.amazonaws.com unreachable",
        "credential " + "AK" + "IA" + "Q" * 16 + " refused",  # built: not a literal key
        "password authentication failed",
        "token=abc expired",
        "file /etc/nlw/aws/credentials unreadable",
        "SELECT name FROM datasets WHERE id = 1 failed",
        "user@example.test",
        "two\nlines",
        "x" * 201,
        "",
    ],
)
def test_a_message_that_looks_sensitive_is_withheld(text: str) -> None:
    for cls in (CredentialError, BlobUnavailable, DeletionLogUnavailable):
        out = ops.safe_message(cls(text))
        assert out == f"{cls.__name__} (details withheld)"
        if text:
            assert text not in out


def test_the_cli_prints_the_safe_reason_and_withholds_secrets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing(error: BaseException) -> Any:
        def run(args: Any, progress: dict[str, int]) -> int:
            progress["purged"] = 1
            raise error

        return run

    monkeypatch.setattr(ops, "_run", failing(CredentialError("the AWS credentials are expired")))
    assert ops.main(["verify-objects"]) == 3
    err = capsys.readouterr().err
    assert "stopped: CredentialError: the AWS credentials are expired. It is safe to re-run" in err
    assert "partial purged=1" in err

    secret = "nlw-production-datasets-999988887777-us-east-1 versions/a/b/c"
    monkeypatch.setattr(ops, "_run", failing(BlobUnavailable(secret)))
    assert ops.main(["verify-objects"]) == 3
    err = capsys.readouterr().err
    assert "BlobUnavailable (details withheld)" in err and "999988887777" not in err

    monkeypatch.setattr(ops, "_run", failing(OSError(f"connection to {secret} refused")))
    assert ops.main(["verify-objects"]) == 3
    err = capsys.readouterr().err
    assert "unexpected OSError; details are not printed" in err
    assert "999988887777" not in err and "versions/" not in err and "Traceback" not in err


# --- configuration errors name the setting, never the value ---------------------------

KEY = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"
S3 = {
    "dataset_storage_backend": "s3",
    "dataset_s3_bucket": "nlw-local-datasets-111122223333-us-east-1",
    "dataset_s3_region": "us-east-1",
    "dataset_s3_kms_key_arn": KEY,
}


@pytest.mark.parametrize(
    "kw, setting, value",
    [
        ({**S3, "dataset_s3_bucket": "my-secret-bucket-42"}, "DATASET_S3_BUCKET",
         "my-secret-bucket-42"),
        ({**S3, "dataset_deletion_log": "s3",
          "dataset_deletion_log_bucket": "nlw-local-deletion-receipts-999988887777-us-east-1"},
         "DATASET_DELETION_LOG_BUCKET", "999988887777"),
        ({"dataset_deletion_log": "bogus-value-9"}, "DATASET_DELETION_LOG", "bogus-value-9"),
        ({"dataset_dispatch_interval_s": 7}, "DATASET_DISPATCH_INTERVAL_S", "7"),
        ({"dataset_deletion_log": "local", "dataset_deletion_log_path": "relative/secret-path"},
         "DATASET_DELETION_LOG_PATH", "relative/secret-path"),
    ],
)  # fmt: skip
def test_configuration_errors_name_the_setting_never_the_value(
    kw: dict[str, Any], setting: str, value: str
) -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None, **kw)  # type: ignore[call-arg]
    reasons = ops.config_reasons(exc.value, Settings)
    assert setting in reasons, reasons
    assert value not in reasons, reasons


def test_a_credential_file_error_names_the_setting_not_the_path(tmp_path: Path) -> None:
    secret_path = tmp_path / "secret-credentials-file"
    with pytest.raises(CredentialError) as missing:
        read_credentials_file(None)
    assert "AWS_SHARED_CREDENTIALS_FILE" in str(missing.value)
    with pytest.raises(CredentialError) as unreadable:
        read_credentials_file(str(secret_path))
    assert str(secret_path) not in str(unreadable.value)
    assert ops.safe_message(unreadable.value).startswith("CredentialError: ")


def test_the_backup_cli_names_a_retention_setting_never_its_value(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from nlw.backup.__main__ import main as backup_main

    monkeypatch.setenv("NLW_BACKUP_RETENTION_MONTHLY", "77")
    assert backup_main(["backup"]) == 2
    err = capsys.readouterr().err
    assert "NLW_BACKUP_RETENTION_MONTHLY must be 12" in err and "77" not in err


# --- the operator role is at path / --------------------------------------------------


def test_a_role_at_path_root_is_confirmed() -> None:
    iam = fake.FakeIAM(env="staging", path="/")
    verify_role_path(iam, "nlw-staging-dataset-operator")
    assert iam.calls == ["get_role"]


@pytest.mark.parametrize("path", ["/ops/", "/nlw/staging/"])
def test_a_role_at_another_path_is_refused(path: str) -> None:
    iam = fake.FakeIAM(env="staging", path=path)
    with pytest.raises(CredentialError, match="must be at path /"):
        verify_role_path(iam, "nlw-staging-dataset-operator")


@pytest.mark.parametrize(
    "role",
    [
        {"RoleName": "nlw-staging-dataset-operator", "Path": "/ops/",
         "Arn": "arn:aws:iam::111122223333:role/ops/nlw-staging-dataset-operator"},
        {"RoleName": "other", "Path": "/", "Arn": "arn:aws:iam::111122223333:role/other"},
        {"RoleName": "nlw-staging-dataset-operator", "Path": "/",
         "Arn": "arn:aws:iam::111122223333:role/x/nlw-staging-dataset-operator-x"},
        # Only the Path says it is not at /: the Path itself is checked.
        {"RoleName": "nlw-staging-dataset-operator", "Path": "/ops/",
         "Arn": "arn:aws:iam::111122223333:role/nlw-staging-dataset-operator"},
    ],
)  # fmt: skip
def test_an_inconsistent_role_answer_is_refused(role: dict[str, str]) -> None:
    class Iam:
        def get_role(self, **kw: Any) -> dict[str, Any]:
            return {"Role": role}

    with pytest.raises(CredentialError, match="must be at IAM path /"):
        verify_role_path(Iam(), "nlw-staging-dataset-operator")


def test_the_receipt_log_checks_the_role_before_anything_else() -> None:
    from nlw.datasets.deletion_log_s3 import S3DeletionLog

    bucket = fake.ReceiptBucket()
    client = bucket.client("operator")
    iam = fake.FakeIAM(env="local", path="/ops/")

    def role_check() -> None:
        try:
            verify_role_path(iam, "nlw-local-dataset-operator")
        except CredentialError as exc:
            raise DeletionLogUnavailable(str(exc)) from None

    log = S3DeletionLog(client, fake.BUCKET, role_check=role_check)
    with pytest.raises(DeletionLogUnavailable, match="must be at path /"):
        log.preflight()
    assert client.calls == []  # not even the Object Lock check ran
    iam.path = "/"
    log.preflight()
    assert client.calls == ["get_object_lock_configuration"]


# --- verify-objects: noncurrent versions are reported, never a failure (ADR-036) -------


@pytest.mark.parametrize(
    "finding,code",
    [
        (None, 0),
        ("noncurrent_versions", 0),
        ("missing_objects", 1),
        ("digest_mismatches", 1),
        ("unaccounted_objects", 1),
    ],
)
def test_verify_objects_fails_on_everything_but_noncurrent_versions(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    finding: str | None,
    code: int,
) -> None:
    report: dict[str, list[str]] = {
        k: [] for k in ("missing_objects", "digest_mismatches", "unaccounted_objects")
    }
    report["noncurrent_versions"] = []
    if finding:
        report[finding] = ["v-1"]
    monkeypatch.setattr(ops, "_owner_url", lambda: "postgresql://unused")
    monkeypatch.setattr(psycopg, "connect", lambda *a, **k: contextlib.nullcontext(None))
    monkeypatch.setattr(ops, "dataset_store", lambda settings, service: object())
    monkeypatch.setattr(ops, "verify_objects", lambda conn, store: report)
    assert ops.main(["verify-objects"]) == code
    if finding:
        assert f"{finding}=1 v-1" in capsys.readouterr().out


# --- ADR-038: the unattended retention identity runs only its three commands --------

_DS = "11111111-2222-3333-4444-555555555555"
REFUSED_UNDER_RETENTION = [
    ["pending"], ["verify-objects"], ["dispatch-pending"], ["rejected-pending"],
    ["purge-rejected", "--operator", "t"], ["reapply-receipts"], ["restore-objects"],
    ["purge", "--dataset", _DS, "--operator", "t"], ["tombstone", "--dataset", _DS],
]  # fmt: skip


@pytest.mark.parametrize("argv", REFUSED_UNDER_RETENTION, ids=lambda a: a[0])
def test_the_retention_identity_is_refused_every_other_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    monkeypatch.setenv("DATASET_OPERATOR_IDENTITY", "retention")

    def no_db(*a: Any, **k: Any) -> Any:
        raise AssertionError("refused before any database connection")

    monkeypatch.setattr(psycopg, "connect", no_db)
    assert ops.main(argv) == 2
    err = capsys.readouterr().err
    assert "needs the operator identity" in err and argv[0] in err
    assert ops.RETENTION_COMMANDS == ("retention-sweep", "retention-status", "reconcile-receipts")


def test_offboarding_refuses_the_retention_identity(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from nlw.ops import offboarding

    monkeypatch.setenv("DATASET_OPERATOR_IDENTITY", "retention")
    monkeypatch.setenv("DATABASE_MIGRATION_URL", "postgresql://unused")
    monkeypatch.setattr(psycopg, "connect", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    assert offboarding.main(["request", "--workspace", _DS, "--operator", "t"]) == 2
    assert "offboarding needs the operator identity" in capsys.readouterr().err


def test_the_identity_setting_is_closed() -> None:
    assert Settings().dataset_operator_identity == "operator"
    with pytest.raises(ValidationError):
        Settings(dataset_operator_identity="restore")  # type: ignore[arg-type]
