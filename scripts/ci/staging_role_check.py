"""Staging-validation: prove the worker executes a run (CI only, stdlib only).

Replaces a step that triggered ``/workflows/{id}/runs`` with ``|| true``, slept
a fixed five seconds and then hoped to catch the worker's transient connection
in ``pg_stat_activity``. The workflow id came from ``/workflows`` list order,
which puts the seeded approval workflow (no current version) first, so the
trigger returned 409 and the failure was swallowed.

Now:
- the workflow id is the exact runnable one exported by ``web/e2e/seed.mjs``;
- any non-201 trigger fails the step, reporting only the status and the
  sanitized error code from the API's ``{"error": {"code", ...}}`` body;
- the run is polled until a terminal status that only the worker can set
  (``COMPLETED``/``FAILED``), with a deadline, so a run that no worker picks
  up fails deterministically instead of passing by luck.

    python3 scripts/ci/staging_role_check.py --api URL --workflow ID
    (token and workspace from K6_ADMIN_TOKEN / K6_WORKSPACE; never printed)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

TERMINAL = {"COMPLETED", "FAILED"}
# Only these run statuses are ever printed; anything else is reported as
# "unrecognised" so no server-supplied text reaches the CI log.
KNOWN_STATUSES = {"PENDING", "RUNNING", "WAITING_APPROVAL", *TERMINAL}
_CODE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class CheckFailed(RuntimeError):
    """A safe, printable failure (never contains tokens or response bodies)."""


Http = Callable[[str, str, dict[str, str]], tuple[int, bytes]]


def _http(method: str, url: str, headers: dict[str, str]) -> tuple[int, bytes]:
    req = urllib.request.Request(
        url, method=method, headers=headers, data=b"" if method == "POST" else None
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - CI loopback URL
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def sanitized_code(body: bytes) -> str:
    """Only the machine error code, and only if it has a safe shape."""
    try:
        code = json.loads(body)["error"]["code"]
    except (ValueError, KeyError, TypeError):
        return "unparseable"
    return code if isinstance(code, str) and _CODE.match(code) else "unsafe"


def trigger_run(http: Http, api: str, headers: dict[str, str], workflow_id: str) -> str:
    status, body = http("POST", f"{api}/workflows/{workflow_id}/runs", headers)
    if status != 201:
        raise CheckFailed(f"run trigger returned HTTP {status} ({sanitized_code(body)})")
    try:
        run_id = json.loads(body)["run_id"]  # RunCreateOut (api/schemas.py)
    except (ValueError, KeyError, TypeError) as exc:
        raise CheckFailed("run trigger response has no run id") from exc
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", run_id):
        raise CheckFailed("run trigger response has an invalid run id")
    return run_id


def wait_for_worker(
    http: Http,
    api: str,
    headers: dict[str, str],
    run_id: str,
    *,
    deadline_s: float,
    interval_s: float = 1.0,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    end = clock() + deadline_s
    last = "unknown"
    while True:
        status, body = http("GET", f"{api}/runs/{run_id}", headers)
        if status != 200:
            raise CheckFailed(f"run read returned HTTP {status} ({sanitized_code(body)})")
        try:
            reported = json.loads(body).get("status")
        except (ValueError, AttributeError) as exc:
            raise CheckFailed("run read returned an unparseable body") from exc
        last = reported if reported in KNOWN_STATUSES else "unrecognised"
        if last in TERMINAL:
            return last
        if clock() >= end:
            raise CheckFailed(
                f"no worker finished the run within {deadline_s:.0f}s (status {last})"
            )
        sleep(interval_s)


def main(argv: list[str] | None = None, http: Http = _http) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--api", required=True)
    p.add_argument("--workflow", required=True)
    p.add_argument("--deadline", type=float, default=90.0)
    p.add_argument("--idempotency-key", default="role-check-1")
    args = p.parse_args(argv)
    token, workspace = os.environ.get("K6_ADMIN_TOKEN", ""), os.environ.get("K6_WORKSPACE", "")
    if not token or not workspace or not args.workflow:
        print("FAIL: token, workspace and runnable workflow id are required", file=sys.stderr)
        return 2
    headers: dict[str, Any] = {
        "Authorization": f"Bearer {token}",
        "X-Workspace-Id": workspace,
        "Idempotency-Key": args.idempotency_key,
        "Content-Type": "application/json",
    }
    try:
        run_id = trigger_run(http, args.api, headers, args.workflow)
        final = wait_for_worker(http, args.api, headers, run_id, deadline_s=args.deadline)
    except CheckFailed as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if final != "COMPLETED":
        print(f"FAIL: seeded run ended {final}", file=sys.stderr)
        return 1
    print(f"worker executed run {run_id}: {final}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
