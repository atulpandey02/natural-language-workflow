"""Regression: dump/restore MUST preserve object ownership (P2, ADR-022).

``pg_dump``/``pg_restore --no-owner`` would flatten every object onto the
restoring superuser, silently turning the NOSUPERUSER-owned SECURITY DEFINER
functions (nlw_rls_bypass / nlw_workspace_bootstrap) into a privilege-escalation
vector. These tests capture the actual argv and fail closed if ``--no-owner``
ever comes back. (The DR drill caught this end-to-end; this locks it at unit
level.)
"""

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from nlw.backup import backup as backup_mod
from nlw.backup import restore as restore_mod


def _fake_run(captured: list[list[str]]):  # type: ignore[no-untyped-def]
    def run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
        captured.append(cmd)
        # pg_dump writes to the --file target; create it so the caller's chmod works.
        if "--file" in cmd:
            Path(cmd[cmd.index("--file") + 1]).write_bytes(b"dump")
        # pg_dumpall writes to stdout; everything else just needs rc 0.
        return SimpleNamespace(returncode=0, stdout="-- roles\n", stderr="")

    return run


def test_pg_dump_preserves_ownership(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", _fake_run(captured))
    backup_mod._default_dump(tmp_path, "postgresql://nlw:pw@db/nlw")
    dump_cmd = next(c for c in captured if c and c[0] == "pg_dump")
    assert "--no-owner" not in dump_cmd  # ownership MUST be preserved
    assert "--format=custom" in dump_cmd


def test_pg_restore_preserves_ownership(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", _fake_run(captured))
    restore_mod._default_pg_restore(Path("/tmp/db.dump"), "postgresql://nlw:pw@db/nlw")
    restore_cmd = captured[0]
    assert restore_cmd[0] == "pg_restore"
    assert "--no-owner" not in restore_cmd  # ownership MUST be preserved
    assert "--exit-on-error" in restore_cmd  # fail closed on an unresolvable owner
