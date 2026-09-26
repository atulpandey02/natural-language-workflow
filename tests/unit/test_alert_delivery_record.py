"""The human delivery record (scripts/ops/record-alert-delivery.sh) is written
without touching the rollout directory's ownership/mode (nlwops:nlwops 0700 on
the host) and never for the null receiver."""

from __future__ import annotations

import grp
import json
import os
import pwd
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ops/record-alert-delivery.sh"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    me = pwd.getpwuid(os.getuid()).pw_name
    mygrp = grp.getgrgid(os.getgid()).gr_name
    return subprocess.run(
        ["bash", str(SCRIPT), "--owner", me, "--group", mygrp, *args],
        capture_output=True, text=True, check=False,
    )  # fmt: skip


def test_record_is_0640_and_the_rollout_directory_is_untouched(tmp_path: Path) -> None:
    rollout = tmp_path / "rollout"
    rollout.mkdir(mode=0o700)
    os.chmod(rollout, 0o700)
    before = rollout.stat()
    p = _run("--dir", str(rollout), "--receiver", "ops-slack", "--confirmed-by", "ops-lead")
    assert p.returncode == 0, p.stderr
    rec = rollout / "alert-delivery.json"
    assert stat.S_IMODE(rec.stat().st_mode) == 0o640
    doc = json.loads(rec.read_text())
    assert doc["receiver"] == "ops-slack" and doc["confirmed_by"] == "ops-lead"
    assert doc["delivered_at"].endswith("+00:00")
    after = rollout.stat()
    assert stat.S_IMODE(after.st_mode) == 0o700
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert sorted(x.name for x in rollout.iterdir()) == ["alert-delivery.json"]  # no temp leftovers
    # Re-recording replaces atomically and still leaves the directory alone.
    p2 = _run(
        "--dir",
        str(rollout),
        "--receiver",
        "ops-slack",
        "--confirmed-by",
        "ops-2",
        "--delivered-at",
        "2026-09-26T10:00:00+00:00",
    )
    assert p2.returncode == 0 and json.loads(rec.read_text())["confirmed_by"] == "ops-2"
    assert stat.S_IMODE(rollout.stat().st_mode) == 0o700


def test_record_script_refuses_null_receiver_naive_time_and_missing_dir(tmp_path: Path) -> None:
    rollout = tmp_path / "rollout"
    rollout.mkdir(mode=0o700)
    assert _run("--dir", str(rollout), "--receiver", "null", "--confirmed-by", "x").returncode == 2
    assert (
        _run(
            "--dir",
            str(rollout),
            "--receiver",
            "ops",
            "--confirmed-by",
            "x",
            "--delivered-at",
            "2026-09-26T10:00:00",
        ).returncode
        == 2
    )
    assert (
        _run(
            "--dir", str(tmp_path / "missing"), "--receiver", "ops", "--confirmed-by", "x"
        ).returncode
        == 2
    )
    assert (
        _run("--dir", str(rollout), "--receiver", "ops;rm", "--confirmed-by", "x").returncode == 2
    )
    assert not (rollout / "alert-delivery.json").exists()
