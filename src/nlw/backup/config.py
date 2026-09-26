"""Fail-closed configuration for the encrypted backup / restore jobs (M11.5 P2).

This is DELIBERATELY separate from ``nlw.core.config.Settings``: the backup and
restore one-shot jobs need object-storage + repository-encryption + a privileged
DB connection that the API / worker / scheduler / web / migrate services must
NEVER inherit. Keeping these settings in their own model means importing the app
Settings can never pull backup credentials into a runtime service.

Secrets are ``SecretStr`` so they are masked in logs/reprs; nothing here is ever
printed. Required-in-production values fail CLOSED via an explicit validator.
"""

import contextlib
import os
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "dev", "staging", "production"]

# Backup-format version written into every manifest.
BACKUP_FORMAT_VERSION = "nlw-backup/1"

# Stable, sanitized recovery reason stamped on restored non-terminal work during
# post-restore quiescence (goes into the existing run/step ``error`` text columns).
DR_RESTORE_UNCERTAIN = "DR_RESTORE_UNCERTAIN"


class BackupSettings(BaseSettings):
    """Config for the backup job. Loaded from the environment only.

    ``restic`` reads its object-storage + repository-password secrets from the
    environment directly (``RESTIC_REPOSITORY``, ``RESTIC_PASSWORD``,
    ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``); we mirror them here ONLY to
    validate presence fail-closed and to pass a sanitized child environment. We
    never log or persist the values.
    """

    model_config = SettingsConfigDict(
        env_file=None,
        extra="ignore",
        populate_by_name=True,
        # A validation failure is printed to the journal by the CLI; never echo the
        # (possibly partial) credential values that were supplied.
        hide_input_in_errors=True,
    )

    app_env: Environment = Field(default="local")

    # Encrypted repository (restic). e.g. s3:https://s3.<region>.amazonaws.com/<bucket>/nlw
    restic_repository: str = Field(default="", alias="RESTIC_REPOSITORY")
    restic_password: SecretStr = Field(default=SecretStr(""), alias="RESTIC_PASSWORD")
    aws_access_key_id: SecretStr = Field(default=SecretStr(""), alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: SecretStr = Field(default=SecretStr(""), alias="AWS_SECRET_ACCESS_KEY")
    # Optional S3-compatible region (AWS S3); Backblaze B2 encodes it in the URL.
    aws_region: str = Field(default="", alias="AWS_DEFAULT_REGION")

    # Privileged DB connection used ONLY to dump (owner/superuser so the dump is
    # complete under FORCE RLS). libpq URL; the password is passed via PGPASSWORD
    # to the child, never on argv.
    backup_database_url: SecretStr = Field(default=SecretStr(""), alias="NLW_BACKUP_DATABASE_URL")

    # Retention (pilot defaults; documented, not silently assumed).
    retention_daily: int = Field(default=14, alias="NLW_BACKUP_RETENTION_DAILY")
    retention_weekly: int = Field(default=8, alias="NLW_BACKUP_RETENTION_WEEKLY")
    retention_monthly: int = Field(default=6, alias="NLW_BACKUP_RETENTION_MONTHLY")

    # Freshness: a successful backup older than this trips the dead-man alert. A
    # touch over 24h to tolerate the daily timer's randomized delay.
    max_age_hours: int = Field(default=26, alias="NLW_BACKUP_MAX_AGE_HOURS")

    # Host-readable node_exporter textfile the job atomically writes on completion.
    metrics_file: str = Field(
        default="/var/lib/node_exporter/textfile/nlw_backup.prom",
        alias="NLW_BACKUP_METRICS_FILE",
    )

    # Validated temp dir for the transient plaintext dump (restrictive perms, wiped).
    work_dir: str = Field(default="/tmp/nlw-backup", alias="NLW_BACKUP_WORK_DIR")

    # Host/process-level single-execution lock (flock). Lives on a shared, writable
    # runtime volume so two backup CONTAINERS (not just two threads) contend for it.
    lock_file: str = Field(default="/run/nlw/backup.lock", alias="NLW_BACKUP_LOCK_FILE")

    # Retention operating mode (see docs/ops/backup-providers.md, "retention modes"):
    #   simple    - the backup job runs `restic forget --prune` after a verified backup.
    #   immutable - the backup writer has NO delete rights; the job NEVER prunes;
    #               pruning is a separate, human-gated admin process off the VPS.
    retention_mode: Literal["simple", "immutable"] = Field(
        default="simple", alias="NLW_BACKUP_RETENTION_MODE"
    )
    # Escape hatch that, combined with immutable mode, is a CONTRADICTION we reject.
    force_local_prune: bool = Field(default=False, alias="NLW_BACKUP_FORCE_LOCAL_PRUNE")

    @model_validator(mode="after")
    def _fail_closed(self) -> "BackupSettings":
        if self.retention_daily < 1 or self.retention_weekly < 1 or self.retention_monthly < 1:
            raise ValueError("backup retention values must each be >= 1")
        if self.max_age_hours < 1:
            raise ValueError("NLW_BACKUP_MAX_AGE_HOURS must be >= 1")
        # Contradiction: immutable writer mode + a local automatic prune. A non-delete
        # writer cannot prune, and asking it to would either fail or require unsafe
        # delete-capable credentials on the VPS. Fail closed rather than guess.
        if self.retention_mode == "immutable" and self.force_local_prune:
            raise ValueError(
                "contradictory backup config: NLW_BACKUP_RETENTION_MODE=immutable with "
                "NLW_BACKUP_FORCE_LOCAL_PRUNE=true. Immutable mode never prunes from the "
                "VPS; run retention as a separate admin process (see backup-providers.md)."
            )
        if self.app_env in ("staging", "production"):
            missing = [
                name
                for name, present in (
                    ("RESTIC_REPOSITORY", bool(self.restic_repository)),
                    ("RESTIC_PASSWORD", bool(self.restic_password.get_secret_value())),
                    ("AWS_ACCESS_KEY_ID", bool(self.aws_access_key_id.get_secret_value())),
                    (
                        "AWS_SECRET_ACCESS_KEY",
                        bool(self.aws_secret_access_key.get_secret_value()),
                    ),
                    ("NLW_BACKUP_DATABASE_URL", bool(self.backup_database_url.get_secret_value())),
                )
                if not present
            ]
            if missing:
                raise ValueError(
                    f"backup misconfigured (fail-closed in {self.app_env}): missing "
                    + ", ".join(missing)
                )
        return self

    def restic_env(self) -> dict[str, str]:
        """A minimal child environment carrying ONLY restic's secrets — never the
        parent process environment, so nothing else leaks into the subprocess."""
        env = {
            "RESTIC_REPOSITORY": self.restic_repository,
            "RESTIC_PASSWORD": self.restic_password.get_secret_value(),
            "AWS_ACCESS_KEY_ID": self.aws_access_key_id.get_secret_value(),
            "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key.get_secret_value(),
            # restic needs PATH to find itself / tools.
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
        }
        if self.aws_region:
            env["AWS_DEFAULT_REGION"] = self.aws_region
        return env


class RestoreSettings(BaseSettings):
    """Config for the restore job. Restore MUST refuse an arbitrary active
    production DB by default: it requires an explicit destructive confirmation
    that matches the exact target identity."""

    model_config = SettingsConfigDict(
        env_file=None,
        extra="ignore",
        populate_by_name=True,
        # A validation failure is printed to the journal by the CLI; never echo the
        # (possibly partial) credential values that were supplied.
        hide_input_in_errors=True,
    )

    app_env: Environment = Field(default="local")
    restic_repository: str = Field(default="", alias="RESTIC_REPOSITORY")
    restic_password: SecretStr = Field(default=SecretStr(""), alias="RESTIC_PASSWORD")
    aws_access_key_id: SecretStr = Field(default=SecretStr(""), alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: SecretStr = Field(default=SecretStr(""), alias="AWS_SECRET_ACCESS_KEY")
    aws_region: str = Field(default="", alias="AWS_DEFAULT_REGION")

    # Owner/superuser connection to the FRESH target DB (creates objects/grants).
    restore_database_url: SecretStr = Field(default=SecretStr(""), alias="NLW_RESTORE_DATABASE_URL")
    # The exact snapshot to restore ("latest" or a restic snapshot id).
    snapshot: str = Field(default="latest", alias="NLW_RESTORE_SNAPSHOT")
    # The exact expected target identity the operator must confirm to authorize a
    # destructive restore (e.g. the fresh Compose project or DB name). Fail-closed.
    target_id: str = Field(default="", alias="NLW_RESTORE_TARGET_ID")
    confirm: str = Field(default="", alias="NLW_RESTORE_CONFIRM")
    work_dir: str = Field(default="/tmp/nlw-restore", alias="NLW_RESTORE_WORK_DIR")

    # The exact Compose project the restore runs inside; the runtime-state guard is
    # scoped to THIS project (never a global container scan). Its running services
    # are inspected and api/worker/scheduler/web must be down.
    compose_project: str = Field(default="", alias="NLW_RESTORE_COMPOSE_PROJECT")
    # "compose" = probe Compose runtime state (fail closed if undeterminable);
    # "off" = rely on structural isolation + the DB-session guard only (local drills
    # where the probe runs on the host instead). Production requires "compose".
    runtime_guard: Literal["compose", "off"] = Field(
        default="compose", alias="NLW_RESTORE_RUNTIME_GUARD"
    )
    # Restore-ready gate artifact written atomically ONLY after quiescence+validation.
    gate_file: str = Field(default="/var/lib/nlw/restore-ready.json", alias="NLW_RESTORE_GATE_FILE")

    @model_validator(mode="after")
    def _fail_closed(self) -> "RestoreSettings":
        # In staging/production the runtime-state guard must be enforceable: a scoped
        # Compose project is required so the check cannot silently no-op.
        if self.app_env in ("staging", "production"):
            if self.runtime_guard != "compose":
                raise ValueError(
                    "restore misconfigured: NLW_RESTORE_RUNTIME_GUARD must be 'compose' "
                    f"in {self.app_env} (refusing to disable the runtime-state guard)"
                )
            if not self.compose_project:
                raise ValueError(
                    "restore misconfigured: NLW_RESTORE_COMPOSE_PROJECT is required in "
                    f"{self.app_env} to scope the runtime-state guard"
                )
        return self

    def restic_env(self) -> dict[str, str]:
        env = {
            "RESTIC_REPOSITORY": self.restic_repository,
            "RESTIC_PASSWORD": self.restic_password.get_secret_value(),
            "AWS_ACCESS_KEY_ID": self.aws_access_key_id.get_secret_value(),
            "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key.get_secret_value(),
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
        }
        if self.aws_region:
            env["AWS_DEFAULT_REGION"] = self.aws_region
        return env

    def require_confirmation(self) -> None:
        """Fail CLOSED unless the operator supplied the destructive confirmation
        matching the exact expected target identity."""
        if not self.target_id:
            raise ValueError("NLW_RESTORE_TARGET_ID is required (the exact restore target)")
        if self.confirm != self.target_id:
            raise ValueError(
                "restore refused: NLW_RESTORE_CONFIRM must exactly equal "
                "NLW_RESTORE_TARGET_ID to authorize a destructive restore"
            )


def sa_engine_url(libpq_or_sa_url: str) -> str:
    """Normalize a DB URL to the psycopg-v3 SQLAlchemy dialect.

    The backup/restore jobs accept a plain libpq URL (``postgresql://…``) because
    that is what ``pg_dump``/``pg_restore`` consume directly. SQLAlchemy, however,
    defaults a bare ``postgresql://`` to the psycopg2 driver, which we do NOT ship
    (we ship psycopg v3). Force the ``postgresql+psycopg`` dialect for the engine
    paths (quiesce/validate) while leaving an already-qualified URL untouched.
    """
    if libpq_or_sa_url.startswith("postgresql+"):
        return libpq_or_sa_url
    if libpq_or_sa_url.startswith("postgresql://"):
        return "postgresql+psycopg://" + libpq_or_sa_url[len("postgresql://") :]
    if libpq_or_sa_url.startswith("postgres://"):
        return "postgresql+psycopg://" + libpq_or_sa_url[len("postgres://") :]
    return libpq_or_sa_url


def validated_work_dir(path: str) -> Path:
    """Resolve + create the transient work dir with restrictive (0700) perms.

    Refuses obviously dangerous targets (root, home, the repo). Never a broad
    deletion target — callers clean specific files they create, not this tree
    wholesale unless it is under a system temp root.
    """
    p = Path(path).resolve()
    forbidden = {Path("/"), Path.home().resolve(), Path.cwd().resolve()}
    if p in forbidden or str(p) in ("", "/"):
        raise ValueError(f"unsafe work dir: {p}")
    p.mkdir(parents=True, exist_ok=True)
    p.chmod(0o700)
    return p


def validated_runtime_file(path: str, *, what: str) -> Path:
    """Resolve a lock/gate file path and ensure its parent dir exists (0700).

    Refuses a path that IS a forbidden directory (root/home/cwd) or resolves to an
    empty/`/` string, so the lock/gate location can never be chosen through an
    unsafe unresolved variable. Returns the resolved file path (not created here —
    the flock opener / atomic writer create it).
    """
    if not path or path in ("", "/"):
        raise ValueError(f"unsafe {what} path: {path!r}")
    p = Path(path).resolve()
    forbidden = {Path("/"), Path.home().resolve(), Path.cwd().resolve()}
    if p in forbidden:
        raise ValueError(f"unsafe {what} path: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        p.parent.chmod(0o700)  # a shared/mounted runtime dir may not be chmod-able
    return p
