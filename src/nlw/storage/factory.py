"""Build the configured dataset object store (ADR-030, ADR-033).

- ``disabled``: no store (no upload route is mounted; the ingest runtime
  refuses to boot).
- ``local``: a filesystem store scoped per environment under
  ``{DATASET_STORAGE_ROOT}/{APP_ENV}`` (``Settings`` refuses it in staging and
  production, and refuses a root that shares the backup repository).
- ``s3``: AWS S3 (ADR-033) with credentials pinned to this service's file and
  its identity verified at startup (``nlw.storage.s3_credentials``). The
  caller names the service (``api``, ``ingest``, ``operator`` or ``restore``)
  so the expected assumed role can be checked.

``restore_source_store`` (O-4, ADR-036) reads the restore bucket AWS Backup
restored a point in time into, as the restore role; it is only ever read.
"""

from __future__ import annotations

import os
from pathlib import Path

from nlw.core.config import Settings
from nlw.storage.blob import BlobStore, LocalBlobStore
from nlw.storage.s3_credentials import Service


def dataset_store(settings: Settings, *, service: Service = "api") -> BlobStore | None:
    if settings.dataset_storage_backend == "disabled":
        return None
    if settings.dataset_storage_backend == "s3":
        from nlw.storage.s3 import S3BlobStore
        from nlw.storage.s3_credentials import build_clients

        assert settings.dataset_s3_bucket and settings.dataset_s3_kms_key_arn  # validated
        client, _ = build_clients(settings, service)
        return S3BlobStore(
            client,
            bucket=settings.dataset_s3_bucket,
            kms_key_arn=settings.dataset_s3_kms_key_arn,
            prefix=settings.dataset_s3_prefix,
            read_limit=settings.dataset_max_upload_bytes,
        )
    assert settings.dataset_storage_root  # Settings validated it
    root = Path(settings.dataset_storage_root) / settings.app_env
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    return LocalBlobStore(root)


def restore_source_store(settings: Settings) -> BlobStore | None:
    """The restore bucket (read-only use), or ``None`` if none is configured."""
    if settings.dataset_storage_backend != "s3" or not settings.dataset_restore_bucket:
        return None
    from nlw.storage.s3 import S3BlobStore
    from nlw.storage.s3_credentials import build_clients

    assert settings.dataset_s3_kms_key_arn  # validated
    client, _ = build_clients(settings, "restore")
    return S3BlobStore(
        client,
        bucket=settings.dataset_restore_bucket,
        kms_key_arn=settings.dataset_s3_kms_key_arn,  # never used: this store is only read
        prefix=settings.dataset_s3_prefix,
        read_limit=settings.dataset_max_upload_bytes,
    )
