"""Shared integration fixtures.

``pg_stack`` starts a throwaway Postgres, bootstraps the runtime roles
(nlw_app, nlw_worker, and the non-login nlw_rls_bypass) exactly as the docker
init script / CI do, applies the real Alembic migrations as the owner, and hands
back settings for both the API role (nlw_app) and the worker role (nlw_worker).
"""

import shutil
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from testcontainers.community.postgres import PostgresContainer

from nlw.core.config import Settings
from nlw.ctxkeys import install_key
from nlw.tenancy.keys import clear_process_signers, set_process_signer, signer_from_material
from nlw.tenancy.signing import Purpose, SecretBytes, SignedContext, generate_test_key

_SUPABASE_URL = "https://proj.supabase.co"
_SECRET = "dev-secret-for-tests-32bytes-min-length"


def _libpq(user: str, password: str, host: str, port: str | int, db: str) -> str:
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


def _sqlalchemy(user: str, password: str, host: str, port: str | int, db: str) -> str:
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{db}"


def _bootstrap_roles(owner_libpq: str, db: str) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as conn:
        conn.execute(
            "DO $$ BEGIN "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_app') THEN "
            "CREATE ROLE nlw_app LOGIN PASSWORD 'nlw_app' "
            "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT; END IF; "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_worker') THEN "
            "CREATE ROLE nlw_worker LOGIN PASSWORD 'nlw_worker' "
            "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT; END IF; "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_scheduler') THEN "
            "CREATE ROLE nlw_scheduler LOGIN PASSWORD 'nlw_scheduler' "
            "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT; END IF; "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_ingest') THEN "
            "CREATE ROLE nlw_ingest LOGIN PASSWORD 'nlw_ingest' "
            "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT; END IF; "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_rls_bypass') THEN "
            "CREATE ROLE nlw_rls_bypass NOLOGIN NOSUPERUSER BYPASSRLS "
            "NOCREATEDB NOCREATEROLE; END IF; "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_workspace_bootstrap') THEN "
            "CREATE ROLE nlw_workspace_bootstrap NOLOGIN NOSUPERUSER BYPASSRLS "
            "NOCREATEDB NOCREATEROLE; END IF; "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_membership_admin') THEN "
            "CREATE ROLE nlw_membership_admin NOLOGIN NOSUPERUSER BYPASSRLS "
            "NOCREATEDB NOCREATEROLE; END IF; "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_ctx_verifier') THEN "
            "CREATE ROLE nlw_ctx_verifier NOLOGIN NOSUPERUSER NOBYPASSRLS "
            "NOCREATEDB NOCREATEROLE; END IF; END $$;"
        )
        for role in ("nlw_app", "nlw_worker", "nlw_scheduler"):
            conn.execute(f"GRANT CONNECT ON DATABASE {db} TO {role}")
            conn.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
        conn.execute("GRANT nlw_rls_bypass TO CURRENT_USER")
        conn.execute("GRANT nlw_workspace_bootstrap TO CURRENT_USER")
        conn.execute("GRANT nlw_membership_admin TO CURRENT_USER")
        conn.execute("GRANT nlw_ctx_verifier TO CURRENT_USER")


# TEST HARNESS ONLY (never a migration). Founding a workspace requires an
# operator grant since migration 0022, enforced inside the SECURITY DEFINER
# bootstrap. Most integration tests exercise other features and simply need a
# workspace, so by default the harness plays the operator: every new identity
# receives one open grant, and consuming a harness grant issues the next one.
# The real function still checks, locks and consumes a real grant each time.
# Tests of the gate itself opt out with ``@pytest.mark.workspace_grants_enforced``.
_TEST_AUTO_GRANTS = """
CREATE FUNCTION nlw_test_auto_grant(p_email text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
    BEGIN
        INSERT INTO public.workspace_creation_grants
            (id, email_normalized, granted_by, expires_at)
        VALUES (gen_random_uuid(), lower(btrim(p_email)), 'test-harness',
                now() + interval '1 day')
        ON CONFLICT DO NOTHING;
    EXCEPTION
        WHEN check_violation THEN
            NULL;  -- an email the grant table cannot hold simply gets no grant
        WHEN undefined_table THEN
            NULL;  -- a reversibility test downgraded below 0022
    END $$;
CREATE FUNCTION nlw_test_auto_grant_user() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
    BEGIN PERFORM public.nlw_test_auto_grant(NEW.email); RETURN NEW; END $$;
CREATE FUNCTION nlw_test_auto_regrant() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
    BEGIN
        IF NEW.granted_by = 'test-harness' AND OLD.consumed_at IS NULL
           AND NEW.consumed_at IS NOT NULL THEN
            PERFORM public.nlw_test_auto_grant(NEW.email_normalized);
        END IF;
        RETURN NEW;
    END $$;
CREATE TRIGGER nlw_test_auto_grant_user AFTER INSERT OR UPDATE OF email ON users
    FOR EACH ROW EXECUTE FUNCTION nlw_test_auto_grant_user();
CREATE TRIGGER nlw_test_auto_regrant AFTER UPDATE ON workspace_creation_grants
    FOR EACH ROW EXECUTE FUNCTION nlw_test_auto_regrant();
REVOKE ALL ON FUNCTION nlw_test_auto_grant(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION nlw_test_auto_grant_user() FROM PUBLIC;
REVOKE ALL ON FUNCTION nlw_test_auto_regrant() FROM PUBLIC;
"""


@pytest.fixture
def pg_stack(request: pytest.FixtureRequest) -> Iterator[SimpleNamespace]:
    with PostgresContainer("postgres:16") as pg:
        host, port = pg.get_container_host_ip(), pg.get_exposed_port(5432)
        owner_user, owner_password, db = pg.username, pg.password, pg.dbname
        owner_libpq = _libpq(owner_user, owner_password, host, port, db)
        owner_sa = _sqlalchemy(owner_user, owner_password, host, port, db)
        app_sa = _sqlalchemy("nlw_app", "nlw_app", host, port, db)
        worker_sa = _sqlalchemy("nlw_worker", "nlw_worker", host, port, db)
        scheduler_sa = _sqlalchemy("nlw_scheduler", "nlw_scheduler", host, port, db)
        ingest_sa = _sqlalchemy("nlw_ingest", "nlw_ingest", host, port, db)

        _bootstrap_roles(owner_libpq, db)

        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", owner_sa)
        command.upgrade(cfg, "head")
        if request.node.get_closest_marker("workspace_grants_enforced") is None:
            with psycopg.connect(owner_libpq, autocommit=True) as conn:
                conn.execute(_TEST_AUTO_GRANTS)

        # --- TEST-ONLY signed-context keys (M11.5 P3B) ---------------------
        # One fresh random key per runtime class, installed into ctx_keys as the
        # owner (exactly what `python -m nlw.ctxkeys install` does in deployment)
        # and written to 0600 files so each role's Settings points at ITS key file.
        # These keys exist only for this container's lifetime; nothing is committed.
        keys_dir = Path(tempfile.mkdtemp(prefix="nlw-ctx-keys-"))
        key_hex = {c: generate_test_key() for c in ("api", "worker", "scheduler", "ingest")}
        key_ids = {c: f"test-{c}-{uuid.uuid4().hex[:8]}" for c in key_hex}
        key_files: dict[str, Path] = {}
        with psycopg.connect(owner_libpq, autocommit=True) as conn:
            for cls, hx in key_hex.items():
                path = keys_dir / f"{cls}.key"
                path.write_text(hx)
                path.chmod(0o600)
                key_files[cls] = path
                if cls == "ingest":
                    continue  # registered on demand: enable_ingest() (below)
                install_key(
                    conn,
                    key_class=cls,
                    key_id=key_ids[cls],
                    secret=SecretBytes(bytes.fromhex(hx)),
                    activate_at=None,
                    actor="pg_stack",
                )
        signers = {
            Purpose.API_IDENTITY: signer_from_material(
                Purpose.API_IDENTITY, key_ids["api"], key_hex["api"]
            ),
            Purpose.API_REQUEST: signer_from_material(
                Purpose.API_REQUEST, key_ids["api"], key_hex["api"]
            ),
            Purpose.WORKER_EXECUTION: signer_from_material(
                Purpose.WORKER_EXECUTION, key_ids["worker"], key_hex["worker"]
            ),
            Purpose.SCHEDULER_RECONCILE: signer_from_material(
                Purpose.SCHEDULER_RECONCILE, key_ids["scheduler"], key_hex["scheduler"]
            ),
            Purpose.DATASET_INGEST: signer_from_material(
                Purpose.DATASET_INGEST, key_ids["ingest"], key_hex["ingest"]
            ),
        }
        # Engine/scheduler code paths look up the process-wide signer (as the real
        # worker/scheduler entrypoints register theirs at boot).
        clear_process_signers()
        for s in signers.values():  # api signers too: test seed helpers without pg_stack
            set_process_signer(s)

        def _settings(url: str, key_class: str = "api") -> Settings:
            return Settings(  # type: ignore[call-arg]
                _env_file=None,
                database_url=url,
                database_migration_url=owner_sa,
                supabase_url=_SUPABASE_URL,
                supabase_jwt_secret=_SECRET,
                # Rate limiting needs Redis; the general API fixtures don't run one.
                # Dedicated M9 tests build settings with it enabled + a real Redis.
                rate_limit_enabled=False,
                ctx_key_id=key_ids[key_class],
                ctx_key_file=str(key_files[key_class]),
                # Tests are a development environment: demo tools (fake.*, static.*)
                # are enabled EXPLICITLY (unset = hidden from planning, fail closed).
                demo_tools_enabled=True,
            )

        def enable_ingest() -> None:
            """Register the ingest key (ADR-031), as the operator would when the
            ingest runtime is enabled. Until then every dataset_ingest context
            fails closed — which is also what lets the downgrade tests run
            (migration 0026 refuses to downgrade with an ingest key registered)."""
            with psycopg.connect(owner_libpq, autocommit=True) as conn:
                install_key(
                    conn,
                    key_class="ingest",
                    key_id=key_ids["ingest"],
                    secret=SecretBytes(bytes.fromhex(key_hex["ingest"])),
                    activate_at=None,
                    actor="pg_stack",
                )

        def sign(purpose: Purpose, **ids: uuid.UUID | None) -> SignedContext:
            """Mint a valid signed context for ``purpose`` (test helper)."""
            return signers[purpose].sign(**ids)

        def apply_ctx(conn: psycopg.Connection, ctx: SignedContext) -> None:
            """Apply a signed context TRANSACTION-locally on a raw psycopg connection.
            With autocommit=True each statement is its own transaction, so callers
            must use autocommit=False (or a `with conn.transaction()` block)."""
            for name, value in ctx.as_gucs().items():
                conn.execute("SELECT set_config(%s, %s, true)", (name, value))

        def run_as(
            libpq: str,
            purpose: Purpose,
            sql: str,
            params: tuple[object, ...] = (),
            **ids: uuid.UUID | None,
        ) -> list[tuple[object, ...]]:
            """Execute ONE statement under a fresh signed context in its own
            transaction (commit on success; rollback on error, which propagates).
            The signed equivalent of the old autocommit+GUC single-statement shape
            used by the direct-SQL tests."""
            with psycopg.connect(libpq, autocommit=False) as conn:
                apply_ctx(conn, sign(purpose, **ids))
                try:
                    cur = conn.execute(sql, params)
                    rows = cur.fetchall() if cur.description else []
                    conn.commit()
                    return rows
                except Exception:
                    conn.rollback()
                    raise

        def ctx_conn(libpq: str, purpose: Purpose, **ids: uuid.UUID | None) -> psycopg.Connection:
            """Open a NON-autocommit connection with a signed context already applied
            in an open transaction (the common shape for direct-SQL tests). The
            caller commits/rolls back and closes."""
            conn = psycopg.connect(libpq, autocommit=False)
            apply_ctx(conn, sign(purpose, **ids))
            return conn

        def seed_user() -> uuid.UUID:
            """Insert a users row (as owner, bypassing RLS). Returns the user id."""
            uid = uuid.uuid4()
            with psycopg.connect(owner_libpq, autocommit=True) as conn:
                conn.execute(
                    "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
                    (uid, f"sub-{uid}", f"{uid}@example.com"),
                )
            return uid

        def grant_workspace_creation(email: str, *, expires: str = "1 day") -> uuid.UUID:
            """Issue one open workspace-creation grant (as the operator would)."""
            gid = uuid.uuid4()
            with psycopg.connect(owner_libpq, autocommit=True) as conn:
                conn.execute(
                    "INSERT INTO workspace_creation_grants "
                    "(id, email_normalized, granted_by, created_at, expires_at) "
                    "VALUES (%s, lower(btrim(%s)), 'test-operator', "
                    "now() - interval '1 day', now() + %s::interval)",
                    (gid, email, expires),
                )
            return gid

        def seed_member(role: str = "owner") -> SimpleNamespace:
            """Create a user + workspace + one membership with ``role`` (as owner)."""
            uid, tid = seed_user(), uuid.uuid4()
            with psycopg.connect(owner_libpq, autocommit=True) as conn:
                conn.execute(
                    "INSERT INTO workspaces (id, name, slug) VALUES (%s,%s,%s)",
                    (tid, "ws", f"ws-{tid}"),
                )
                conn.execute(
                    "INSERT INTO memberships (id, user_id, workspace_id, role) "
                    "VALUES (%s,%s,%s,%s)",
                    (uuid.uuid4(), uid, tid, role),
                )
            return SimpleNamespace(user_id=uid, tenant_id=tid)

        def add_membership(tenant_id: uuid.UUID, role: str) -> uuid.UUID:
            """Add a fresh user to an existing workspace with ``role`` (as owner).

            Returns the new user id. Lets a test have distinct member/admin/owner
            principals in the same tenant.
            """
            uid = seed_user()
            with psycopg.connect(owner_libpq, autocommit=True) as conn:
                conn.execute(
                    "INSERT INTO memberships (id, user_id, workspace_id, role) "
                    "VALUES (%s,%s,%s,%s)",
                    (uuid.uuid4(), uid, tenant_id, role),
                )
            return uid

        try:
            yield SimpleNamespace(
                settings=_settings(app_sa, "api"),
                worker_settings=_settings(worker_sa, "worker"),
                scheduler_settings=_settings(scheduler_sa, "scheduler"),
                ingest_settings=_settings(ingest_sa, "ingest"),
                ingest_sa=ingest_sa,
                owner_libpq=owner_libpq,
                owner_sa=owner_sa,
                app_libpq=_libpq("nlw_app", "nlw_app", host, port, db),
                worker_libpq=_libpq("nlw_worker", "nlw_worker", host, port, db),
                scheduler_libpq=_libpq("nlw_scheduler", "nlw_scheduler", host, port, db),
                ingest_libpq=_libpq("nlw_ingest", "nlw_ingest", host, port, db),
                seed_user=seed_user,
                seed_member=seed_member,
                grant_workspace_creation=grant_workspace_creation,
                add_membership=add_membership,
                enable_ingest=enable_ingest,
                # Signed-context test helpers (P3B)
                signers=signers,
                key_ids=key_ids,
                key_hex=key_hex,
                key_files=key_files,
                sign=sign,
                apply_ctx=apply_ctx,
                ctx_conn=ctx_conn,
                run_as=run_as,
            )
        finally:
            clear_process_signers()
            shutil.rmtree(keys_dir, ignore_errors=True)
