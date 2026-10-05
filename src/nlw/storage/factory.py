"""Build the configured dataset object store (ADR-030).

Only ``local`` exists: a filesystem store scoped per environment under
``{DATASET_STORAGE_ROOT}/{APP_ENV}`` (``Settings`` refuses it in staging and
production, and refuses a root that shares the backup repository). No S3 client
is a dependency yet (owner decision O-2), so deployed environments have no
dataset store and the upload routes are not mounted.
"""

from __future__ import annotations

import os
from pathlib import Path

from nlw.core.config import Settings
from nlw.storage.blob import LocalBlobStore


def dataset_store(settings: Settings) -> LocalBlobStore | None:
    if settings.dataset_storage_backend == "disabled":
        return None
    assert settings.dataset_storage_root  # Settings validated it
    root = Path(settings.dataset_storage_root) / settings.app_env
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    return LocalBlobStore(root)
