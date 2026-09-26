"""``restic snapshots --latest 1`` answers PER host+paths group — one entry per
one-shot backup container hostname — in repository order. The evidence command
takes ``[0]`` as the newest snapshot, so the list must be newest-first
(reproduced in the N -> N+1 rehearsal: the manifest of an OLDER snapshot was
compared against the new source revision)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from nlw.backup.restic import Restic


def _restic_with(snapshots: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch) -> Restic:
    r = Restic({"RESTIC_REPOSITORY": "s3:https://example.invalid/r", "RESTIC_PASSWORD": "x"})

    def fake(*args: str, what: str) -> Any:
        assert args[:2] == ("snapshots", "--tag") and "--latest" in args
        return SimpleNamespace(stdout=json.dumps(snapshots), returncode=0)

    monkeypatch.setattr(r, "_restic_checked", fake)
    return r


def test_latest_snapshots_are_newest_first_across_host_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    older = {
        "id": "a" * 64,
        "short_id": "aaaa",
        "time": "2026-09-26T10:00:00.123456789Z",
        "hostname": "c1",
        "tags": ["nlw-db", "rev-0010_x"],
    }
    newer = {
        "id": "b" * 64,
        "short_id": "bbbb",
        "time": "2026-09-26T12:00:00.5Z",
        "hostname": "c2",
        "tags": ["nlw-db", "rev-0020_y"],
    }
    r = _restic_with([older, newer], monkeypatch)
    assert [s["id"] for s in r.latest_snapshots()] == [newer["id"], older["id"]]
    r2 = _restic_with([newer, older], monkeypatch)
    assert [s["id"] for s in r2.latest_snapshots()] == [newer["id"], older["id"]]
    # A malformed time never becomes "the newest".
    bad = dict(older, id="c" * 64, time="not-a-time")
    r3 = _restic_with([bad, newer], monkeypatch)
    assert r3.latest_snapshots()[0]["id"] == newer["id"]
    assert _restic_with([], monkeypatch).latest_snapshots() == []
