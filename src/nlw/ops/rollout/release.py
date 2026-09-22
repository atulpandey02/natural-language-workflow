"""Release identity for a rollout = the external CI-generated manifest
(``nlw.ops.release_manifest``). This module only re-exports the loader under the
rollout's names so the phases/gates keep a single ``ReleaseSpec`` type.
"""

from __future__ import annotations

from pathlib import Path

from nlw.ops.release_manifest import (
    KEY_CLASSES,
    ReleaseManifest,
    ReleaseManifestError,
    load_manifest,
    parse_manifest,
)

ReleaseSpec = ReleaseManifest
ReleaseSpecError = ReleaseManifestError
parse_release = parse_manifest


def load_release(path: Path, *, local: bool = False) -> ReleaseSpec:
    return load_manifest(path, local=local)


__all__ = ["KEY_CLASSES", "ReleaseSpec", "ReleaseSpecError", "load_release", "parse_release"]
