"""Production key preparation is file-only and fail closed (M12A-Prep §E, O.13).

Runs against a real temporary filesystem as the current user (so ownership
checks use our own uid; the container uid 10001 is exercised by the rehearsal).
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from nlw import ctxkeys

UID = os.getuid()


def test_prepare_creates_0700_dir_and_0400_file_without_printing_material(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = tmp_path / "ctx-keys"
    fp = ctxkeys.prepare_key_file(d, "api", owner=(UID, os.getgid()))
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    f = d / "api.key"
    assert stat.S_IMODE(f.stat().st_mode) == 0o400
    material = f.read_text().strip()
    assert len(material) == 64 and fp == ctxkeys.file_fingerprint(f)
    assert fp != material  # a fingerprint is never the material
    # CLI path prints class + fingerprint only.
    rc = ctxkeys.main(
        ["prepare", "--dir", str(d), "--class", "worker", "--owner", f"{UID}:{os.getgid()}"]
    )
    out = capsys.readouterr()
    assert rc == 0 and out.out.startswith("prepared worker ") and material not in out.out + out.err
    assert (d / "worker.key").read_text().strip() not in out.out + out.err


def test_prepare_refuses_overwrite_symlink_and_bad_dir(tmp_path: Path) -> None:
    d = tmp_path / "ctx-keys"
    ctxkeys.prepare_key_file(d, "api", owner=(UID, os.getgid()))
    with pytest.raises(ctxkeys.KeyFileError, match="overwrite"):
        ctxkeys.prepare_key_file(d, "api", owner=(UID, os.getgid()))
    (d / "worker.key").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(ctxkeys.KeyFileError, match="overwrite"):
        ctxkeys.prepare_key_file(d, "worker", owner=(UID, os.getgid()))
    os.chmod(d, 0o755)
    with pytest.raises(ctxkeys.KeyFileError, match="0700"):
        ctxkeys.prepare_key_file(d, "scheduler", owner=(UID, os.getgid()))
    os.chmod(d, 0o700)
    link = tmp_path / "linkdir"
    link.symlink_to(d)
    with pytest.raises(ctxkeys.KeyFileError, match="symlink"):
        ctxkeys.prepare_key_file(link, "scheduler", owner=(UID, os.getgid()))
    with pytest.raises(ctxkeys.KeyFileError, match="invalid key class"):
        ctxkeys.prepare_key_file(d, "backup", owner=(UID, os.getgid()))


def _good_dir(tmp_path: Path) -> Path:
    d = tmp_path / "ctx-keys"
    for c in ("api", "worker", "scheduler"):
        ctxkeys.prepare_key_file(d, c, owner=(UID, os.getgid()))
    return d


def test_placement_rejects_wrong_mode_symlink_dir_empty_and_malformed(tmp_path: Path) -> None:
    d = _good_dir(tmp_path)
    f = d / "api.key"
    ctxkeys.check_key_file_placement(f, owner_uid=UID)
    with pytest.raises(ctxkeys.KeyFileError, match="owner uid"):
        ctxkeys.check_key_file_placement(f, owner_uid=UID + 1)
    os.chmod(f, 0o440)
    with pytest.raises(ctxkeys.KeyFileError, match="mode"):
        ctxkeys.check_key_file_placement(f, owner_uid=UID)
    os.chmod(f, 0o400)
    link = d / "link.key"
    link.symlink_to(f)
    with pytest.raises(ctxkeys.KeyFileError, match="symlink"):
        ctxkeys.check_key_file_placement(link, owner_uid=UID)
    sub = d / "dir.key"
    sub.mkdir()
    with pytest.raises(ctxkeys.KeyFileError, match="regular"):
        ctxkeys.check_key_file_placement(sub, owner_uid=UID)
    empty = d / "empty.key"
    empty.touch(mode=0o400)
    with pytest.raises(ctxkeys.KeyFileError, match="empty"):
        ctxkeys.check_key_file_placement(empty, owner_uid=UID)
    bad = d / "bad.key"
    bad.write_text("not-hex-material\n")
    os.chmod(bad, 0o400)
    with pytest.raises(ctxkeys.KeyFileError, match="hex"):
        ctxkeys.check_key_file_placement(bad, owner_uid=UID)
    short = d / "short.key"
    short.write_text("ab" * 16 + "\n")  # 16 bytes < 32
    os.chmod(short, 0o400)
    with pytest.raises(ctxkeys.KeyFileError, match="hex"):
        ctxkeys.check_key_file_placement(short, owner_uid=UID)
    with pytest.raises(ctxkeys.KeyFileError, match="missing"):
        ctxkeys.check_key_file_placement(d / "nope.key", owner_uid=UID)


def test_fingerprint_command_outputs_class_id_hash_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = _good_dir(tmp_path)
    rc = ctxkeys.main(
        ["fingerprint", "--dir", str(d), "--key-id-api", "stg-api-1",
         "--key-id-worker", "stg-worker-1", "--key-id-scheduler", "stg-sched-1",
         "--owner", str(UID)]
    )  # fmt: skip
    out = capsys.readouterr().out
    assert rc == 0
    lines = [ln.split() for ln in out.strip().splitlines()]
    assert [ln[0] for ln in lines] == ["api", "worker", "scheduler"]
    assert [ln[1] for ln in lines] == ["stg-api-1", "stg-worker-1", "stg-sched-1"]
    for c, _kid, fp in lines:
        assert fp == ctxkeys.file_fingerprint(d / f"{c}.key")
        assert (d / f"{c}.key").read_text().strip() not in out
    assert len({ln[2] for ln in lines}) == 3  # independent keys


def test_fingerprint_rejects_invalid_key_id_and_bad_owner(tmp_path: Path) -> None:
    d = _good_dir(tmp_path)
    assert (
        ctxkeys.main(
            [
                "fingerprint",
                "--dir",
                str(d),
                "--key-id-api",
                "BAD ID",
                "--key-id-worker",
                "w-1",
                "--key-id-scheduler",
                "s-1",
                "--owner",
                str(UID),
            ]
        )
        == 1
    )
    assert (
        ctxkeys.main(
            [
                "fingerprint",
                "--dir",
                str(d),
                "--key-id-api",
                "a-1",
                "--key-id-worker",
                "w-1",
                "--key-id-scheduler",
                "s-1",
                "--owner",
                str(UID + 1),
            ]
        )
        == 1
    )
    assert ctxkeys.main(["verify-files", "--dir", str(d), "--owner", str(UID)]) == 0
    assert ctxkeys.main(["verify-files", "--dir", str(d), "--owner", str(UID + 1)]) == 1


def test_file_commands_need_no_database(tmp_path: Path) -> None:
    """prepare/fingerprint/verify-files must run without DATABASE_MIGRATION_URL."""
    d = tmp_path / "ctx-keys"
    env = {k: v for k, v in os.environ.items() if k != "DATABASE_MIGRATION_URL"}
    p = subprocess.run(
        [sys.executable, "-m", "nlw.ctxkeys", "prepare", "--dir", str(d),
         "--class", "api", "--owner", f"{UID}:{os.getgid()}"],
        env=env, capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert p.returncode == 0, p.stderr
    assert p.stdout.startswith("prepared api ")
    assert (d / "api.key").read_text().strip() not in p.stdout + p.stderr


def test_dev_helper_is_not_a_production_path() -> None:
    """The 0644 dev helper must say so and must never be referenced by the
    production/staging deployment tooling."""
    root = Path(__file__).resolve().parents[2]
    helper = (root / "scripts" / "ops" / "ctx-keys-dev.sh").read_text()
    assert "NEVER use this for production" in helper and "0644" in helper
    for f in (
        "scripts/ops/deploy-staging.sh",
        "src/nlw/ops/rollout/phases.py",
        "scripts/ops/rehearse-0010-to-0016.sh",
    ):
        assert "ctx-keys-dev" not in (root / f).read_text(), f
