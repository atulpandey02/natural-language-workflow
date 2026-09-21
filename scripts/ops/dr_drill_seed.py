"""DR drill: seed representative two-tenant data, and (post-restore) assert the
recovery invariants. Runs as the owner (bypasses FORCE RLS). No secrets printed.

    python -m scripts.ops.dr_drill_seed seed    --url <owner-url>
    python -m scripts.ops.dr_drill_seed verify   --url <owner-url>   # post-restore
    python -m scripts.ops.dr_drill_seed newrun   --url <owner-url>   # execute a NEW run
"""

import sys
import uuid
from datetime import UTC, datetime, timedelta

import psycopg

_PLAN = '{"steps":[{"id":"a","tool":"fake.echo","args":{}}]}'
# A connector-less inline tool (no outbound side effect) so the post-restore
# execution proof needs no network and no SSRF-policy relaxation.
_NEWRUN_PLAN = '{"steps":[{"id":"a","tool":"fake.echo","args":{"hello":"dr"}}]}'


def _tenant(c: psycopg.Connection, label: str) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    tid, uid, wf, ver = (uuid.uuid4() for _ in range(4))
    c.execute(
        "INSERT INTO workspaces (id, name, slug) VALUES (%s,%s,%s)", (tid, label, f"{label}-{tid}")
    )
    c.execute(
        "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
        (uid, str(uid), f"{uid}@e.com"),
    )
    c.execute(
        "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,'owner')",
        (uuid.uuid4(), uid, tid),
    )
    # A connector: config is non-secret; secret_ref is a pointer, never a value.
    c.execute(
        "INSERT INTO connectors (id, tenant_id, type, name, config, secret_ref, status) "
        "VALUES (%s,%s,'webhook','hook','{\"url\":\"https://sink.example/h\"}'::jsonb,'WEBHOOK_AUTH','active')",
        (uuid.uuid4(), tid),
    )
    c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tid))
    c.execute(
        "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) VALUES (%s,%s,%s,1,%s::jsonb)",
        (ver, tid, wf, _PLAN),
    )
    return tid, uid, wf, ver


def _run(c: psycopg.Connection, tid: uuid.UUID, ver: uuid.UUID, status: str) -> uuid.UUID:
    rid, wf = uuid.uuid4(), uuid.uuid4()
    c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, tid))
    c.execute(
        "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) VALUES (%s,%s,%s,%s,%s)",
        (rid, tid, wf, ver, status),
    )
    return rid


def _action(c: psycopg.Connection, tid: uuid.UUID, run_id: uuid.UUID, status: str) -> None:
    c.execute(
        "INSERT INTO external_actions (id, tenant_id, run_id, step_id, connector_id, tool, "
        "external_action_key, status, attempts) VALUES (%s,%s,%s,'a',%s,'webhook.send',%s,%s,1)",
        (uuid.uuid4(), tid, run_id, uuid.uuid4(), uuid.uuid4(), status),
    )


def seed(url: str) -> None:
    with psycopg.connect(url, autocommit=True) as c:
        for label in ("acme", "globex"):
            tid, uid, wf, ver = _tenant(c, label)
            # Terminal + non-terminal runs.
            done = _run(c, tid, ver, "COMPLETED")
            pending = _run(c, tid, ver, "PENDING")
            running = _run(c, tid, ver, "RUNNING")
            _run(c, tid, ver, "WAITING_APPROVAL")
            c.execute(
                "INSERT INTO step_runs (id, tenant_id, run_id, step_id, tool, status, attempt) VALUES (%s,%s,%s,'a','webhook.send','RUNNING',0)",
                (uuid.uuid4(), tid, running),
            )
            # Terminal actions + a deliberately non-terminal (pending) one.
            _action(c, tid, done, "success")
            _action(c, tid, running, "pending")  # ambiguous once restored -> UNKNOWN
            # A stale schedule (would replay a pre-cutoff occurrence) + its occurrence row.
            sid = uuid.uuid4()
            c.execute(
                "INSERT INTO schedules (id, tenant_id, workflow_id, workflow_version_id, timezone, "
                "frequency, minute, hour, enabled, next_run_at, created_by) "
                "VALUES (%s,%s,%s,%s,'UTC','daily',0,9,true,%s,%s)",
                (sid, tid, wf, ver, datetime.now(UTC) - timedelta(hours=2), uid),
            )
            occ = _run(c, tid, ver, "COMPLETED")
            c.execute(
                "UPDATE workflow_runs SET schedule_id=%s, scheduled_for=%s, trigger='schedule' WHERE id=%s",
                (sid, datetime.now(UTC) - timedelta(hours=2), occ),
            )
            # An approval bound to the WAITING_APPROVAL run's step.
            c.execute(
                "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, tool, status) VALUES (%s,%s,%s,'a',%s,'hook','webhook.send','pending')",
                (uuid.uuid4(), tid, pending, uuid.uuid4()),
            )
    print(
        "seed: 2 tenants with terminal + non-terminal runs/actions/schedules/approvals (no secrets printed)"
    )


def verify(url: str) -> None:
    with psycopg.connect(url) as c:
        non_terminal = c.execute(
            "SELECT count(*) FROM workflow_runs WHERE status IN ('PENDING','RUNNING','WAITING_APPROVAL')"
        ).fetchone()[0]
        assert non_terminal == 0, f"restored non-terminal runs NOT quiesced: {non_terminal}"
        dr_reason = c.execute(
            "SELECT count(*) FROM workflow_runs WHERE error='DR_RESTORE_UNCERTAIN'"
        ).fetchone()[0]
        assert dr_reason > 0, "expected DR_RESTORE_UNCERTAIN runs after quiescence"
        pending_actions = c.execute(
            "SELECT count(*) FROM external_actions WHERE status='pending'"
        ).fetchone()[0]
        assert pending_actions == 0, f"pending external actions not made unknown: {pending_actions}"
        unknown = c.execute(
            "SELECT count(*) FROM external_actions WHERE status='unknown'"
        ).fetchone()[0]
        assert unknown > 0, "expected the ambiguous action to become UNKNOWN"
        success_still = c.execute(
            "SELECT count(*) FROM external_actions WHERE status='success'"
        ).fetchone()[0]
        assert success_still > 0, "SUCCESS actions must be preserved"
        # No-replay: nothing is left in a retryable state that a started worker would
        # re-drive (no pending status, no armed next_attempt_at on a non-final action).
        retryable = c.execute(
            "SELECT count(*) FROM external_actions "
            "WHERE status NOT IN ('success','failed','unknown') OR next_attempt_at IS NOT NULL"
        ).fetchone()[0]
        assert retryable == 0, f"retryable external actions remain (would resend): {retryable}"
        cutoff = c.execute(
            "SELECT cutoff_at FROM dr_restore_events ORDER BY restored_at DESC LIMIT 1"
        ).fetchone()[0]
        stale = c.execute(
            "SELECT count(*) FROM schedules WHERE next_run_at <= %s", (cutoff,)
        ).fetchone()[0]
        assert stale == 0, f"schedules replay the gap: {stale} at/before cutoff"
        events = c.execute("SELECT count(*) FROM dr_restore_events").fetchone()[0]
        assert events >= 1, "no dr_restore_event recorded"
        # A NEWLY created post-restore run is PENDING (executable once services start),
        # while restored runs stay terminal (not auto-replayed).
        with psycopg.connect(url, autocommit=True) as w:
            tid = w.execute("SELECT tenant_id FROM workflows LIMIT 1").fetchone()[0]
            wf = w.execute(
                "SELECT id FROM workflows WHERE tenant_id=%s LIMIT 1", (tid,)
            ).fetchone()[0]
            ver = w.execute(
                "SELECT id FROM workflow_versions WHERE workflow_id=%s LIMIT 1", (wf,)
            ).fetchone()[0]
            new_run = uuid.uuid4()
            w.execute(
                "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) VALUES (%s,%s,%s,%s,'PENDING')",
                (new_run, tid, wf, ver),
            )
            st = w.execute("SELECT status FROM workflow_runs WHERE id=%s", (new_run,)).fetchone()[0]
            assert st == "PENDING", "a new post-restore run must be executable"
    print(
        "verify: OK — restored non-terminal work quiesced, ambiguous->UNKNOWN, SUCCESS preserved, "
        "schedules recomputed after cutoff, DR event recorded, new run insertable"
    )


def newrun(url: str) -> None:
    """Create a BRAND-NEW post-restore workflow + run and EXECUTE it to COMPLETED
    through the real engine (in-process, no queue), proving the recovered database
    accepts and processes new work. Uses the connector-less fake.echo tool.

    Also proves restored work is NOT replayed: no restored run advances here (they
    are all terminal after quiescence), and only the brand-new run runs."""
    import uuid as _uuid

    from sqlalchemy import create_engine as _create_engine
    from sqlalchemy.orm import sessionmaker

    from nlw.backup.config import sa_engine_url
    from nlw.engine.execution import process_advance

    engine = _create_engine(sa_engine_url(url))
    session_factory = sessionmaker(engine)

    with psycopg.connect(url, autocommit=True) as c:
        tid = c.execute("SELECT tenant_id FROM workflows LIMIT 1").fetchone()[0]
        # Snapshot terminal runs BEFORE, to prove none of them get re-executed.
        before_terminal = c.execute(
            "SELECT count(*) FROM workflow_runs WHERE status IN ('COMPLETED','FAILED')"
        ).fetchone()[0]
        wf, ver, run = (_uuid.uuid4() for _ in range(3))
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'dr-new')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tid, wf, _NEWRUN_PLAN),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) "
            "VALUES (%s,%s,%s,%s,'PENDING')",
            (run, tid, wf, ver),
        )

    pending: list[uuid.UUID] = [run]
    for _ in range(20):  # bounded; a single inline step completes in a couple passes
        if not pending:
            break
        rid = pending.pop(0)
        process_advance(session_factory, rid, enqueue=lambda r, d: pending.append(r))

    with psycopg.connect(url) as c:
        status = c.execute("SELECT status FROM workflow_runs WHERE id=%s", (run,)).fetchone()[0]
        after_terminal = c.execute(
            "SELECT count(*) FROM workflow_runs WHERE status IN ('COMPLETED','FAILED')"
        ).fetchone()[0]
    assert status == "COMPLETED", f"new post-restore run did not complete: status={status}"
    # Exactly ONE new terminal run (the new one); no restored run was replayed.
    assert after_terminal == before_terminal + 1, (
        f"unexpected terminal-run delta: before={before_terminal} after={after_terminal} "
        "(restored work may have been replayed)"
    )
    print(f"newrun: OK — a brand-new post-restore run executed to COMPLETED (run={run})")


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[2] != "--url":
        print("usage: dr_drill_seed.py {seed|verify|newrun} --url <owner-url>", file=sys.stderr)
        return 2
    cmd, url = sys.argv[1], sys.argv[3]
    {"seed": seed, "verify": verify, "newrun": newrun}[cmd](url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
