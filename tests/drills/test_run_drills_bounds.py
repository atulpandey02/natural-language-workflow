"""The drill readiness helper is bounded (M11, regression F).

``ready_code`` in ``run_drills.sh`` must never block indefinitely, even when the
API endpoint is a black hole (open/unroutable socket that never answers). We
point it at a TEST-NET address (RFC 5737, guaranteed unroutable) and assert it
returns the 000 sentinel well within its ``--max-time`` bound.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

DRILL = Path(__file__).with_name("run_drills.sh")
BLACKHOLE = "http://192.0.2.1:8000"  # RFC 5737 TEST-NET-1: no route, never answers


def test_f_ready_code_is_bounded() -> None:
    # Source the script (guarded main() does NOT run on source) and call the
    # bounded helper against the black hole.
    script = f'set -euo pipefail; API="{BLACKHOLE}"; source "{DRILL}"; ready_code'
    start = time.monotonic()
    proc = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=20,  # test-level guard; the helper itself must finish far sooner
    )
    elapsed = time.monotonic() - start
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "000"
    # --connect-timeout 2 / --max-time 5: comfortably under 10s.
    assert elapsed < 10.0, f"ready_code took {elapsed:.1f}s (should be bounded)"


def test_f_degraded_is_true_on_blackhole() -> None:
    script = f'set -euo pipefail; API="{BLACKHOLE}"; source "{DRILL}"; degraded && echo DEGRADED'
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "DEGRADED"
