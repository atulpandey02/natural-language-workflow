"""The real-container scheduler shutdown drill's PASS/FAIL rule, tested without
Docker. A nonzero, missing or malformed Redis queue length must FAIL a round
(the drill previously printed it without judging it), and the exit-code and
elapsed-time checks still apply."""

import shutil
import subprocess
from pathlib import Path

import pytest

DRILL = Path(__file__).resolve().parents[2] / "tests" / "drills" / "scheduler_shutdown_drill.sh"


def _verdict(elapsed_ms: str, code: str, allowed: str, qlen: str, max_s: str = "8") -> str:
    out = subprocess.run(
        ["bash", str(DRILL), "--verdict", elapsed_ms, code, allowed, qlen, max_s],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return out.stdout.strip()


pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")


@pytest.mark.parametrize(
    ("elapsed_ms", "code", "allowed", "qlen", "expected"),
    [
        ("350", "0", "0", "0", "PASS"),
        ("150", "143", "0 143", "0", "PASS"),  # startup round may exit 143
        # queue length is judged: nonzero, missing or malformed all FAIL
        ("350", "0", "0", "1", "FAIL"),
        ("350", "0", "0", "17", "FAIL"),
        ("350", "0", "0", "", "FAIL"),
        ("350", "0", "0", "abc", "FAIL"),
        ("350", "0", "0", "-1", "FAIL"),
        ("350", "0", "0", "0 1", "FAIL"),
        ("350", "0", "0", "(error) ERR", "FAIL"),
        ("350", "0", "0", "0\n", "FAIL"),
        # existing checks preserved
        ("350", "137", "0", "0", "FAIL"),
        ("150", "137", "0 143", "0", "FAIL"),
        ("150", "143", "0", "0", "FAIL"),
        ("8000", "0", "0", "0", "FAIL"),
        ("7999", "0", "0", "0", "PASS"),
        ("", "0", "0", "0", "FAIL"),
    ],
)
def test_drill_verdict(elapsed_ms: str, code: str, allowed: str, qlen: str, expected: str) -> None:
    assert _verdict(elapsed_ms, code, allowed, qlen) == expected


def test_each_round_captures_queue_length_once_and_judges_it() -> None:
    text = DRILL.read_text()
    record = text[text.index("record() {") : text.index("\n}\n", text.index("record() {"))]
    assert record.count("$(queue_len") == 1  # one observation per round
    assert '"$qlen"' in record and "verdict " in record  # that observation is judged
