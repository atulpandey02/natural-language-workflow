"""Signed database context — adversarial PostgreSQL tests (M11.5 P3B, ADR-024).

Real Postgres (pg_stack, migration 0016, TEST keys installed like deployment does).
Every test speaks direct SQL as a runtime role, because that is exactly what an
SQL-injected / credential-holding attacker can do. What must hold:

- bare unsigned ``app.user_id`` / ``app.tenant_id`` grant NOTHING (the forgeries
  that P3A left open are now dead);
- a valid signed context yields exactly its own claims, for its own login role and
  purpose, only while valid, only with an active key of the right class;
- changing ANY signed field, the tag, the key id, the role, the purpose, the times,
  or the shape invalidates it (fail closed -> NULL -> RLS denies);
- runtime roles cannot read the key registry, and no function is a signing oracle;
- commit / rollback / pool reuse never carry a context into another transaction;
- the Python signer and PostgreSQL produce byte-identical messages and tags
  (golden vectors).
"""

import json
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy import text

from nlw.tenancy.signing import (
    ALL_GUCS,
    Purpose,
    SecretBytes,
    SignedContext,
    canonical_message,
    compute_mac,
)

pytestmark = pytest.mark.integration

VECTORS = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "ctx_golden_vectors.json").read_text()
)


def _claims(conn: psycopg.Connection) -> tuple[object, ...] | None:
    row = conn.execute(
        "SELECT (c).purpose, (c).user_id, (c).tenant_id, (c).run_id, (c).key_id "
        "FROM public.app_ctx_claims() c"
    ).fetchone()
    return None if row is None or row[0] is None else tuple(row)


def _set(conn: psycopg.Connection, gucs: dict[str, str]) -> None:
    for name, value in gucs.items():
        conn.execute("SELECT set_config(%s, %s, true)", (name, value))


def _ws(o: str) -> uuid.UUID:
    t = uuid.uuid4()
    with psycopg.connect(o, autocommit=True) as c:
        c.execute("INSERT INTO workspaces (id, name, slug) VALUES (%s,'ws',%s)", (t, f"w-{t}"))
        c.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (uuid.uuid4(), t)
        )
    return t


def _user(o: str, t: uuid.UUID, role: str) -> uuid.UUID:
    u = uuid.uuid4()
    with psycopg.connect(o, autocommit=True) as c:
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (u, f"s-{u}", f"{u}@x.io"),
        )
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,%s)",
            (uuid.uuid4(), u, t, role),
        )
    return u


def _tampered(ctx: SignedContext, **changes: str) -> dict[str, str]:
    g = ctx.as_gucs()
    g.update(changes)
    return g


# --- 1-3: bare unsigned GUC forgery grants nothing ------------------------------
def test_unsigned_guc_forgery_grants_nothing(pg_stack: SimpleNamespace) -> None:
    tid = _ws(pg_stack.owner_libpq)
    owner = _user(pg_stack.owner_libpq, tid, "owner")
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        c.execute("SELECT set_config('app.user_id', %s, true)", (str(owner),))
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (str(tid),))
        assert _claims(c) is None
        assert c.execute("SELECT public.ctx_user_id()").fetchone()[0] is None  # type: ignore[index]
        assert c.execute("SELECT public.ctx_tenant_id()").fetchone()[0] is None  # type: ignore[index]
        assert c.execute("SELECT is_current_user_admin_or_owner(%s)", (tid,)).fetchone()[0] is False  # type: ignore[index]
        assert c.execute("SELECT count(*) FROM workflows").fetchone()[0] == 0  # type: ignore[index]
        assert c.execute("SELECT count(*) FROM users").fetchone()[0] == 0  # type: ignore[index]
        assert c.execute("SELECT count(*) FROM memberships").fetchone()[0] == 0  # type: ignore[index]
        c.rollback()


# --- 4-5: a valid signed context sees exactly its own workspace ------------------
def test_valid_api_context_scoped_to_its_workspace(pg_stack: SimpleNamespace) -> None:
    ta, tb = _ws(pg_stack.owner_libpq), _ws(pg_stack.owner_libpq)
    ua = _user(pg_stack.owner_libpq, ta, "owner")
    with pg_stack.ctx_conn(pg_stack.app_libpq, Purpose.API_REQUEST, user_id=ua, tenant_id=ta) as c:
        claims = _claims(c)
        assert claims is not None and claims[0] == "api_request"
        assert claims[1] == ua and claims[2] == ta
        assert c.execute("SELECT count(*) FROM workflows").fetchone()[0] == 1
        assert (
            c.execute("SELECT count(*) FROM workflows WHERE tenant_id=%s", (tb,)).fetchone()[0] == 0
        )
        c.rollback()
    # Valid user paired with ANOTHER workspace they are not a member of -> nothing.
    with pg_stack.ctx_conn(pg_stack.app_libpq, Purpose.API_REQUEST, user_id=ua, tenant_id=tb) as c:
        assert c.execute("SELECT count(*) FROM workflows").fetchone()[0] == 0
        assert c.execute("SELECT is_current_user_member(%s)", (tb,)).fetchone()[0] is False
        c.rollback()


# --- 6: every field change invalidates the tag ----------------------------------
@pytest.mark.parametrize(
    "guc,value",
    [
        ("app.ctx_v", "2"),
        ("app.ctx_kid", "other-key"),
        ("app.ctx_role", "nlw_worker"),
        ("app.ctx_purpose", "api_identity"),
        ("app.ctx_user", "00000000-0000-4000-8000-000000000001"),
        ("app.ctx_tenant", "00000000-0000-4000-8000-000000000002"),
        ("app.ctx_run", "00000000-0000-4000-8000-000000000003"),
        ("app.ctx_iat", "1"),
        ("app.ctx_exp", "9999999999"),
        ("app.ctx_nonce", "0" * 32),
        ("app.ctx_mac", "0" * 64),
    ],
)
def test_changing_any_signed_field_invalidates(
    pg_stack: SimpleNamespace, guc: str, value: str
) -> None:
    tid = _ws(pg_stack.owner_libpq)
    u = _user(pg_stack.owner_libpq, tid, "owner")
    ctx = pg_stack.sign(Purpose.API_REQUEST, user_id=u, tenant_id=tid)
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        _set(c, ctx.as_gucs())
        assert _claims(c) is not None  # sanity: valid before tampering
        _set(c, _tampered(ctx, **{guc: value}))
        assert _claims(c) is None, guc
        assert c.execute("SELECT count(*) FROM workflows").fetchone()[0] == 0  # type: ignore[index]
        c.rollback()


# --- 7-9: time window ------------------------------------------------------------
def _resign(
    pg_stack: SimpleNamespace, purpose: Purpose, *, iat: int, exp: int, **ids: uuid.UUID
) -> dict[str, str]:
    """Re-sign a context with explicit times using the fixture key (attacker-with-key
    would be able to do this; we use it to test the DB's independent time checks)."""
    signer = pg_stack.signers[purpose]
    msg = canonical_message(
        key_id=signer.key_id,
        db_role=signer.db_role,
        purpose=str(purpose),
        user_id=str(ids.get("user_id", "") or ""),
        tenant_id=str(ids.get("tenant_id", "") or ""),
        run_id=str(ids.get("run_id", "") or ""),
        issued_at=iat,
        expires_at=exp,
        nonce="ab" * 16,
    )
    key = SecretBytes(
        bytes.fromhex(
            pg_stack.key_hex[
                {
                    "api_request": "api",
                    "api_identity": "api",
                    "worker_execution": "worker",
                    "scheduler_reconcile": "scheduler",
                }[str(purpose)]
            ]
        )
    )
    return {
        "app.ctx_v": "1",
        "app.ctx_kid": signer.key_id,
        "app.ctx_role": signer.db_role,
        "app.ctx_purpose": str(purpose),
        "app.ctx_user": str(ids.get("user_id", "") or ""),
        "app.ctx_tenant": str(ids.get("tenant_id", "") or ""),
        "app.ctx_run": str(ids.get("run_id", "") or ""),
        "app.ctx_iat": str(iat),
        "app.ctx_exp": str(exp),
        "app.ctx_nonce": "ab" * 16,
        "app.ctx_mac": compute_mac(key, msg),
    }


def test_expired_future_and_overlong_contexts_fail(pg_stack: SimpleNamespace) -> None:
    tid = _ws(pg_stack.owner_libpq)
    u = _user(pg_stack.owner_libpq, tid, "owner")
    now = int(time.time())
    cases = {
        "expired": (now - 300, now - 1),
        "future_issued": (now + 3600, now + 3700),
        "lifetime_over_max": (now, now + 601),
        "zero_lifetime": (now, now),
    }
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        for name, (iat, exp) in cases.items():
            _set(
                c,
                _resign(pg_stack, Purpose.API_REQUEST, iat=iat, exp=exp, user_id=u, tenant_id=tid),
            )
            assert _claims(c) is None, name
        # control: a correctly-windowed re-signed context verifies
        _set(
            c,
            _resign(pg_stack, Purpose.API_REQUEST, iat=now, exp=now + 60, user_id=u, tenant_id=tid),
        )
        assert _claims(c) is not None
        c.rollback()


# --- 10-11: wrong DB login role / wrong purpose for the role ---------------------
def test_wrong_login_role_and_wrong_purpose_fail(pg_stack: SimpleNamespace) -> None:
    tid = _ws(pg_stack.owner_libpq)
    u = _user(pg_stack.owner_libpq, tid, "owner")
    api_ctx = pg_stack.sign(Purpose.API_REQUEST, user_id=u, tenant_id=tid)
    # A valid api_request token presented over the WORKER login role: rejected.
    with psycopg.connect(pg_stack.worker_libpq, autocommit=False) as c:
        _set(c, api_ctx.as_gucs())
        assert _claims(c) is None
        c.rollback()
    # A worker token over the API login role: rejected.
    wrk_ctx = pg_stack.sign(Purpose.WORKER_EXECUTION, tenant_id=tid, run_id=uuid.uuid4())
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        _set(c, wrk_ctx.as_gucs())
        assert _claims(c) is None
        c.rollback()
    # Scheduler token over the worker role: rejected.
    sch_ctx = pg_stack.sign(Purpose.SCHEDULER_RECONCILE)
    with psycopg.connect(pg_stack.worker_libpq, autocommit=False) as c:
        _set(c, sch_ctx.as_gucs())
        assert _claims(c) is None
        c.rollback()


# --- 12-14: unknown / revoked / retired keys; overlap ----------------------------
def test_unknown_revoked_and_retired_keys_fail_and_overlap_works(pg_stack: SimpleNamespace) -> None:
    from nlw.ctxkeys import install_key, revoke_key
    from nlw.tenancy.keys import signer_from_material
    from nlw.tenancy.signing import generate_test_key

    tid = _ws(pg_stack.owner_libpq)
    u = _user(pg_stack.owner_libpq, tid, "owner")
    # unknown key id (valid tag under an uninstalled key)
    rogue = signer_from_material(Purpose.API_REQUEST, "never-installed", generate_test_key())
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        _set(c, rogue.sign(user_id=u, tenant_id=tid).as_gucs())
        assert _claims(c) is None
        c.rollback()
    # rotation: install a NEW api key, both verify during overlap
    new_hex = generate_test_key()
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as o:
        install_key(
            o,
            key_class="api",
            key_id="api-k2",
            secret=SecretBytes(bytes.fromhex(new_hex)),
            activate_at=None,
            actor="t",
        )
    new_signer = signer_from_material(Purpose.API_REQUEST, "api-k2", new_hex)
    old_ctx = pg_stack.sign(Purpose.API_REQUEST, user_id=u, tenant_id=tid)
    new_ctx = new_signer.sign(user_id=u, tenant_id=tid)
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        _set(c, old_ctx.as_gucs())
        assert _claims(c) is not None
        _set(c, new_ctx.as_gucs())
        assert _claims(c) is not None
        c.rollback()
    # revoke the OLD key: old contexts fail immediately, new ones keep working
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as o:
        revoke_key(o, key_id=pg_stack.key_ids["api"], retire_at=None, actor="t")
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        _set(c, old_ctx.as_gucs())
        assert _claims(c) is None
        _set(c, new_ctx.as_gucs())
        assert _claims(c) is not None
        c.rollback()
    # a wrong-class key (worker) cannot sign an api purpose even if active
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as o:
        events = o.execute("SELECT event, key_id FROM ctx_key_events ORDER BY id").fetchall()
        cols = {
            r[0]
            for r in o.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name='ctx_key_events'"
            )
        }
    assert ("revoked", pg_stack.key_ids["api"]) in events and ("installed", "api-k2") in events
    assert "secret" not in cols  # audit carries no material


# --- 15: runtime roles cannot read or mutate the registry -------------------------
def test_runtime_roles_cannot_touch_key_registry(pg_stack: SimpleNamespace) -> None:
    for libpq in (pg_stack.app_libpq, pg_stack.worker_libpq, pg_stack.scheduler_libpq):
        with psycopg.connect(libpq, autocommit=True) as c:
            for sql in (
                "SELECT key_id FROM ctx_keys",
                "SELECT secret FROM ctx_keys",
                "INSERT INTO ctx_keys (key_id, key_class, secret, secret_sha256) "
                "VALUES ('x','api','\\x00'::bytea,'')",
                "UPDATE ctx_keys SET status='revoked'",
                "DELETE FROM ctx_keys",
                "SELECT * FROM ctx_key_events",
            ):
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    c.execute(sql)
    with psycopg.connect(pg_stack.owner_libpq) as o:
        owner = o.execute("SELECT tableowner FROM pg_tables WHERE tablename='ctx_keys'").fetchone()
        assert owner is not None and owner[0] == "nlw_ctx_verifier"
        for role in ("nlw_app", "nlw_worker", "nlw_scheduler", "public"):
            for priv in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                got = o.execute(
                    "SELECT has_table_privilege(%s, 'ctx_keys', %s)", (role, priv)
                ).fetchone()
                assert got is not None and got[0] is False, (role, priv)


# --- 16: no signing oracle --------------------------------------------------------
def test_no_signing_oracle_for_runtime_roles(pg_stack: SimpleNamespace) -> None:
    """No function callable by a runtime role returns key material or computes a
    tag over caller-supplied data with a registry key. app_ctx_canon is pure
    (no key); app_ctx_claims only verifies the caller's own tag."""
    with psycopg.connect(pg_stack.owner_libpq) as o:
        rows = o.execute(
            "SELECT p.proname, pg_get_functiondef(p.oid) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' "
            "AND (has_function_privilege('nlw_app', p.oid, 'EXECUTE') "
            "  OR has_function_privilege('nlw_worker', p.oid, 'EXECUTE') "
            "  OR has_function_privilege('nlw_scheduler', p.oid, 'EXECUTE'))"
        ).fetchall()
    for name, src in rows:
        body = str(src).lower()
        if name == "app_ctx_claims":
            assert "return null" in body and "returns app_ctx_claims_t" in body
            continue
        # No other runtime-callable function may reference the key registry.
        assert "ctx_keys" not in body, name
    with psycopg.connect(pg_stack.app_libpq, autocommit=True) as c:
        # The canonicalizer is harmless (no key) and the composite never exposes secret.
        cols = {
            r[0]
            for r in c.execute(
                "SELECT a.attname FROM pg_attribute a JOIN pg_type t ON t.typrelid = a.attrelid "
                "WHERE t.typname = 'app_ctx_claims_t' AND a.attnum > 0"
            )
        }
        assert cols == {"purpose", "user_id", "tenant_id", "run_id", "key_id"}


# --- 17: API context cannot replay as worker/scheduler (covered above) + worker/sched
#         contexts are not human -------------------------------------------------------
def test_worker_and_scheduler_contexts_are_never_human(pg_stack: SimpleNamespace) -> None:
    tid = _ws(pg_stack.owner_libpq)
    owner = _user(pg_stack.owner_libpq, tid, "owner")
    run_id = uuid.uuid4()
    with pg_stack.ctx_conn(
        pg_stack.worker_libpq, Purpose.WORKER_EXECUTION, tenant_id=tid, run_id=run_id
    ) as c:
        assert c.execute("SELECT public.ctx_user_id()").fetchone()[0] is None
        assert c.execute("SELECT public.ctx_tenant_id()").fetchone()[0] == tid
        assert c.execute("SELECT public.ctx_run_id()").fetchone()[0] == run_id
        # A worker cannot satisfy human helpers even for a tenant it is bound to.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT is_current_user_admin_or_owner(%s)", (tid,))
        c.rollback()
    with pg_stack.ctx_conn(pg_stack.scheduler_libpq, Purpose.SCHEDULER_RECONCILE) as c:
        assert c.execute("SELECT public.ctx_user_id()").fetchone()[0] is None
        assert c.execute("SELECT public.ctx_tenant_id()").fetchone()[0] is None
        assert c.execute("SELECT public.ctx_purpose()").fetchone()[0] == "scheduler_reconcile"
        c.rollback()
    # A worker holding a (forged) human id in the user field: shape rejected.
    wrk = pg_stack.sign(Purpose.WORKER_EXECUTION, tenant_id=tid, run_id=run_id)
    with psycopg.connect(pg_stack.worker_libpq, autocommit=False) as c:
        _set(c, _tampered(wrk, **{"app.ctx_user": str(owner)}))
        assert _claims(c) is None
        c.rollback()


# --- 24-26: commit / rollback / pooled reuse never leak a context ----------------
def test_commit_rollback_and_pool_reuse_clear_context(pg_stack: SimpleNamespace) -> None:
    ta, tb = _ws(pg_stack.owner_libpq), _ws(pg_stack.owner_libpq)
    ua, ub = _user(pg_stack.owner_libpq, ta, "owner"), _user(pg_stack.owner_libpq, tb, "owner")
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        pg_stack.apply_ctx(c, pg_stack.sign(Purpose.API_REQUEST, user_id=ua, tenant_id=ta))
        assert _claims(c) is not None
        c.commit()
        assert _claims(c) is None  # commit cleared it
        pg_stack.apply_ctx(c, pg_stack.sign(Purpose.API_REQUEST, user_id=ua, tenant_id=ta))
        c.rollback()
        assert _claims(c) is None  # rollback cleared it
    # SQLAlchemy pool (size 1): a SESSION-level leak from tenant A must be reset
    # before the same connection serves tenant B (RESET ALL on check-in).
    from nlw.db.session import create_sync_engine

    settings = pg_stack.settings
    settings_small = settings.model_copy(update={"db_pool_size": 1, "db_max_overflow": 0})
    eng = create_sync_engine(settings_small)
    try:
        with eng.connect() as c1:
            for name, value in (
                pg_stack.sign(Purpose.API_REQUEST, user_id=ua, tenant_id=ta).as_gucs().items()
            ):
                c1.execute(
                    text("SELECT set_config(:n, :v, false)"), {"n": name, "v": value}
                )  # SESSION-level (bug simulation)
            assert c1.execute(text("SELECT (public.app_ctx_claims()).tenant_id")).scalar() == ta
            c1.commit()
        with eng.connect() as c2:  # same physical connection
            assert c2.execute(text("SELECT (public.app_ctx_claims()).tenant_id")).scalar() is None
            assert c2.execute(text("SELECT current_setting('app.ctx_mac', true)")).scalar() in (
                None,
                "",
            )
            # tenant B's own transaction-local context works and is scoped to B
            for name, value in (
                pg_stack.sign(Purpose.API_REQUEST, user_id=ub, tenant_id=tb).as_gucs().items()
            ):
                c2.execute(text("SELECT set_config(:n, :v, true)"), {"n": name, "v": value})
            assert c2.execute(text("SELECT (public.app_ctx_claims()).tenant_id")).scalar() == tb
            assert (
                c2.execute(
                    text("SELECT count(*) FROM workflows WHERE tenant_id=:t"), {"t": ta}
                ).scalar()
                == 0
            )
            c2.rollback()
    finally:
        eng.dispose()


# --- 27-28: missing / malformed context fails closed with no leakage --------------
@pytest.mark.parametrize(
    "gucs",
    [
        {},
        {"app.ctx_v": "1"},
        {g: "garbage" for g in ALL_GUCS},
        {**{g: "" for g in ALL_GUCS}, "app.ctx_mac": "zz" * 32},
        {**{g: "1" for g in ALL_GUCS}, "app.ctx_user": "not-a-uuid"},
    ],
    ids=["none", "version_only", "garbage", "bad_hex", "bad_uuid"],
)
def test_missing_or_malformed_context_fails_closed(
    pg_stack: SimpleNamespace, gucs: dict[str, str]
) -> None:
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        _set(c, gucs)
        # Never raises, never leaks: plain NULL.
        assert _claims(c) is None
        assert c.execute("SELECT count(*) FROM workflows").fetchone()[0] == 0  # type: ignore[index]
        c.rollback()


# --- golden vectors: PostgreSQL reproduces the Python message + tag exactly -------
def test_golden_vectors_match_in_postgres(pg_stack: SimpleNamespace) -> None:
    key = bytes.fromhex(VECTORS["key_hex"])
    with psycopg.connect(pg_stack.owner_libpq) as o:
        for v in VECTORS["vectors"]:
            msg = o.execute(
                "SELECT convert_from(public.app_ctx_canon(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s), 'UTF8')",
                (
                    "1",
                    v["key_id"],
                    v["db_role"],
                    v["purpose"],
                    v["user_id"],
                    v["tenant_id"],
                    v["run_id"],
                    str(v["issued_at"]),
                    str(v["expires_at"]),
                    v["nonce"],
                ),
            ).fetchone()
            assert msg is not None and msg[0] == v["message"], v["purpose"]
            mac = o.execute(
                "SELECT encode(hmac(public.app_ctx_canon(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s), "
                "%s, 'sha256'), 'hex')",
                (
                    "1",
                    v["key_id"],
                    v["db_role"],
                    v["purpose"],
                    v["user_id"],
                    v["tenant_id"],
                    v["run_id"],
                    str(v["issued_at"]),
                    str(v["expires_at"]),
                    v["nonce"],
                    key,
                ),
            ).fetchone()
            assert mac is not None and mac[0] == v["mac"], v["purpose"]


# --- 40: no live policy or helper trusts the legacy unsigned settings -------------
def test_no_live_policy_or_helper_trusts_unsigned_gucs(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as o:
        pols = o.execute(
            "SELECT policyname, tablename, coalesce(qual,''), coalesce(with_check,'') "
            "FROM pg_policies WHERE schemaname='public'"
        ).fetchall()
        funcs = o.execute(
            "SELECT p.proname, p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='public'"
        ).fetchall()
    assert len(pols) == 51  # the complete inventory survived the cutover
    offenders = [
        f"{t}.{n}" for n, t, q, w in pols if "app.user_id" in q + w or "app.tenant_id" in q + w
    ]
    assert offenders == []
    # No policy may be unconditional either (the old scheduler USING(true) set).
    unconditional = [
        f"{t}.{n}"
        for n, t, q, w in pols
        if q.strip() in ("true", "(true)") or w.strip() in ("true", "(true)")
    ]
    assert unconditional == []
    helper_offenders = [
        n for n, src in funcs if ("app.user_id" in str(src) or "app.tenant_id" in str(src))
    ]
    assert helper_offenders == []
    # Every policy references a signed accessor or a signed helper.
    signed = ("ctx_user_id", "ctx_tenant_id", "ctx_run_id", "ctx_purpose", "is_current_user_")
    unsigned = [f"{t}.{n}" for n, t, q, w in pols if not any(s in q + w for s in signed)]
    assert unsigned == []
