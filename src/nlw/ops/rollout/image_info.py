"""``python -m nlw.ops.rollout.image_info`` — runs INSIDE a release image and
prints what the rollout's capability preflight needs to compare against the
release manifest (M12A-Prep §B): the git SHA baked into the artifact, the
Alembic head the image carries, the migration files it ships, and the
rollout/ops commands it can execute. Nothing here reads a database, a key file
or any secret; the output is plain JSON on stdout.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

REQUIRED_MODULES = (
    "nlw.ops.rollout",
    "nlw.ops.roles",
    "nlw.ctxkeys",
    "nlw.backup.__main__",
    "nlw.ops.rollout.smoke",
)


def collect() -> dict[str, object]:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    migrations_dir = Path("migrations/versions")
    files = sorted(p.name for p in migrations_dir.glob("[0-9][0-9][0-9][0-9]_*.py"))
    head = ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()
    return {
        "git_sha": os.environ.get("NLW_GIT_SHA", ""),
        "alembic_head": head or "",
        "migrations": files,
        "modules": {m: importlib.util.find_spec(m) is not None for m in REQUIRED_MODULES},
        "python": sys.version.split()[0],
    }


def main() -> int:
    print(json.dumps(collect(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
