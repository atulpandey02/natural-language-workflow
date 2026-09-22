"""Key-file placement checks from ``stat`` output (M12A-Prep §E/§K).

The rollout never reads key material. It asks the host for ``stat`` lines and
for fingerprints computed in-place by ``python -m nlw.ctxkeys fingerprint``
(which itself enforces the same rules before hashing).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from nlw.ops.rollout.gates import GateError
from nlw.ops.rollout.release import KEY_CLASSES

CONTAINER_UID = 10001
KEY_DIR_MODE = "700"
KEY_FILE_MODE = "400"
# `stat -c '%n|%F|%a|%u|%g|%s'`
_STAT_RE = re.compile(
    r"^(?P<name>[^|]+)\|(?P<type>[^|]+)\|(?P<mode>[0-7]{3,4})\|(?P<uid>\d+)\|(?P<gid>\d+)\|(?P<size>\d+)$"
)
STAT_FORMAT = "%n|%F|%a|%u|%g|%s"


@dataclass(frozen=True)
class StatLine:
    name: str
    kind: str
    mode: str
    uid: int
    gid: int
    size: int


def parse_stat_line(line: str) -> StatLine:
    m = _STAT_RE.match(line.strip())
    if not m:
        raise GateError(f"unparseable stat line {line.strip()!r}")
    return StatLine(
        name=m.group("name"),
        kind=m.group("type"),
        mode=m.group("mode")[-3:],
        uid=int(m.group("uid")),
        gid=int(m.group("gid")),
        size=int(m.group("size")),
    )


def check_key_dir(st: StatLine) -> None:
    if st.kind != "directory":
        raise GateError(f"key directory {st.name} is not a directory ({st.kind})")
    if st.mode != KEY_DIR_MODE:
        raise GateError(f"key directory {st.name} has mode {st.mode}, want {KEY_DIR_MODE}")
    if st.uid != 0:
        raise GateError(f"key directory {st.name} must be owned by root (uid 0), got uid {st.uid}")


def check_key_file(st: StatLine, *, uid: int = CONTAINER_UID) -> None:
    if st.kind != "regular file":
        raise GateError(
            f"key file {st.name} is not a regular file ({st.kind}); symlinks/dirs rejected"
        )
    if st.mode != KEY_FILE_MODE:
        raise GateError(f"key file {st.name} has mode {st.mode}, want {KEY_FILE_MODE}")
    if st.uid != uid:
        raise GateError(f"key file {st.name} is owned by uid {st.uid}, want container uid {uid}")
    if st.size < 64:
        raise GateError(f"key file {st.name} is too small ({st.size} bytes) to hold a 32-byte key")


def parse_fingerprint_lines(text: str) -> dict[str, tuple[str, str]]:
    """``<class> <key_id> <sha256>`` lines from ``nlw.ctxkeys fingerprint``."""
    out: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        cls, kid, fp = parts
        if cls in KEY_CLASSES and re.match(r"^[0-9a-f]{64}$", fp):
            out[cls] = (kid, fp)
    if set(out) != set(KEY_CLASSES):
        raise GateError(f"fingerprints missing for: {sorted(set(KEY_CLASSES) - set(out))}")
    return out
