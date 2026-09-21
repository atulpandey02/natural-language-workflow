"""P1C action-lifecycle smoke driver (host side).

Runs against the docker-compose stack stood up by ``smoke-p1c-action-lifecycle.sh``.
It proves, end-to-end through the REAL worker + Redis broker + containerized
Postgres, that an ambiguous/expired-final external action resolves to a TERMINAL
UNKNOWN and is NEVER resent — without any network delivery.

The happy path (WAITING_APPROVAL -> approve -> SUCCESS -> COMPLETED) is validated
in the integration suite (tests/integration/test_action_execution.py), where a
MockTransport injects the destination. It cannot be exercised against an internal
compose sink because the SSRF guard (ADR-014) correctly refuses to deliver to a
private IP — a property this smoke also relies on.

Env:
  OWNER_LIBPQ   libpq URL for the owner role (default localhost:5433 / nlw)
  REDIS_URL     broker URL the host uses to enqueue (default localhost:6379)
"""

import json
import os
import sys
import time
import uuid

import psycopg

OWNER_LIBPQ = os.environ.get("OWNER_LIBPQ", "postgresql://nlw:nlw@localhost:5433/nlw")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

_PLAN = {
    "steps": [
        {
            "id": "notify",
            "tool": "webhook.send",
            "args": {"payload": {"hello": "world"}},
            "connector": "hook",
        }
    ]
}


def _fail(msg: str) -> None:
    print(f"SMOKE FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def _assert_live_unknown_constraint() -> None:
    with psycopg.connect(OWNER_LIBPQ) as c:
        row = c.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname='ck_external_action_status'"
        ).fetchone()
    if row is None or "unknown" not in str(row[0]):
        _fail(f"migration 0012 not live; constraint = {row}")
    print(f"  [ok] live CHECK allows 'unknown': {row[0]}")


def _seed_expired_final_action() -> uuid.UUID:
    """Seed an approved run whose in-flight action is at the attempt cap with an
    expired lease: a resume must resolve it to terminal UNKNOWN with no send."""
    tid = uuid.uuid4()
    uid = uuid.uuid4()
    wf, ver, run, cid = (uuid.uuid4() for _ in range(4))
    with psycopg.connect(OWNER_LIBPQ, autocommit=True) as c:
        c.execute("SET session_replication_role = replica")  # bypass FK ordering noise
        c.execute("INSERT INTO workspaces (id, name, slug) VALUES (%s,'ws',%s)", (tid, f"ws-{tid}"))
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (uid, str(uid), f"{uid}@example.com"),
        )
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, status) "
            "VALUES (%s,%s,'webhook','hook',%s::jsonb,'active')",
            (cid, tid, json.dumps({"url": "https://sink.example/hook"})),
        )
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tid, wf, json.dumps(_PLAN)),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) "
            "VALUES (%s,%s,%s,%s,'RUNNING')",
            (run, tid, wf, ver),
        )
        c.execute(
            "INSERT INTO step_runs (id, tenant_id, run_id, step_id, tool, status, attempt) "
            "VALUES (%s,%s,%s,'notify','webhook.send','RUNNING',5)",
            (uuid.uuid4(), tid, run),
        )
        # In-flight action at the cap with an expired lease -> expired final attempt.
        c.execute(
            "INSERT INTO external_actions (id, tenant_id, run_id, step_id, connector_id, tool, "
            "external_action_key, destination_summary, status, attempts, lease_token, lease_owner, "
            "lease_expires_at, last_attempt_at) "
            "VALUES (%s,%s,%s,'notify',%s,'webhook.send',%s,'sink.example','pending',5,%s,'dead', "
            "now() - interval '1 minute', now() - interval '1 minute')",
            (uuid.uuid4(), tid, run, cid, uuid.uuid4(), uuid.uuid4()),
        )
    return run


def _enqueue(run_id: uuid.UUID) -> None:
    os.environ["REDIS_URL"] = REDIS_URL
    os.environ.setdefault("NLW_REDIS_URL", REDIS_URL)
    from nlw.worker.actors import advance_run

    advance_run.send(str(run_id))


def _poll_terminal(run_id: uuid.UUID, timeout_s: float = 30.0) -> dict[str, object]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with psycopg.connect(OWNER_LIBPQ) as c:
            c.row_factory = psycopg.rows.dict_row  # type: ignore[assignment]
            ea = c.execute(
                "SELECT status, error_class, attempts FROM external_actions WHERE run_id=%s",
                (run_id,),
            ).fetchone()
            run = c.execute("SELECT status FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
        if ea and ea["status"] != "pending":
            return {"ea": dict(ea), "run": dict(run) if run else {}}
        time.sleep(1.0)
    _fail("timed out waiting for the worker to finalize the action")
    raise AssertionError  # unreachable


def main() -> None:
    print("P1C action-lifecycle smoke (containerized worker + broker + Postgres)")
    print("- verifying migration 0012 is live...")
    _assert_live_unknown_constraint()

    print("- seeding an expired-final in-flight action and enqueuing a resume...")
    run_id = _seed_expired_final_action()
    _enqueue(run_id)

    print("- waiting for the real worker to finalize it...")
    result = _poll_terminal(run_id)
    ea = result["ea"]
    run = result["run"]
    print(f"  worker result: external_action={ea}  run={run}")

    if ea["status"] != "unknown":  # type: ignore[index]
        _fail(f"expected external_action status 'unknown', got {ea['status']!r}")  # type: ignore[index]
    if ea["error_class"] != "ACTION_OUTCOME_UNKNOWN":  # type: ignore[index]
        _fail(f"expected ACTION_OUTCOME_UNKNOWN, got {ea['error_class']!r}")  # type: ignore[index]
    if ea["attempts"] != 5:  # type: ignore[index]
        _fail(f"attempts must NOT increment past the cap on an expired final attempt: {ea}")
    if run.get("status") != "FAILED":  # type: ignore[union-attr]
        _fail(f"expected run FAILED, got {run}")

    print("SMOKE PASS: expired-final action resolved to terminal UNKNOWN, never resent.")


if __name__ == "__main__":
    main()
