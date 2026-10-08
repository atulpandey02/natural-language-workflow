"""Dataset ingest runtime boundary: nlw_ingest grants, dataset_ingest purpose (ADR-031).

Owner decision O-1. Background CSV processing moves from the API role to a
dedicated, least-privilege runtime:

- ``dataset_ingest`` signed purpose, bound to ``nlw_ingest`` and to key class
  ``ingest``; claim shape tenant + run (the run slot carries the VERSION id), no
  user. ``app_ctx_claims()`` is replaced IN PLACE (same owner, same SECURITY
  DEFINER, same checks plus the new purpose); no new SECURITY DEFINER function.
  The existing accessors are untouched; ``ctx_ingest_tenant_id()`` and
  ``ctx_ingest_version_id()`` (SECURITY INVOKER) expose the new claims.
- ``dataset_processing_requests``: immutable, admin-created records that anchor
  the queue's work envelope (trigger-computed ``envelope_sha256``).
- ``nlw_ingest``: SELECT/UPDATE on exactly the processing columns of ONE version
  (its signed context), SELECT on that version's dataset, request, profile and
  events, INSERT of its profile and processing events. No DELETE anywhere.
- The API role loses the processing path: no profile INSERT, no entering
  PROFILING/PROFILED, no lease, no rejection of a version being processed
  (policy + guard). Review rejection from QUARANTINED and deletion stay.
- ``dataset_event_required()`` covers ``nlw_ingest``;
  ``dataset_consistency_check()`` runs the one invariant the ingest role can
  affect (its dataset is ACTIVE) instead of sibling counts it cannot see.

The role itself is provisioned outside Alembic (initdb / ``nlw.ops.roles
ensure``), like every runtime role; in staging/production it stays NOLOGIN
(dormant) until owner decision O-6. Additive: no existing row is rewritten.

DOWNGRADE: disposable databases only. It refuses while an ``ingest`` key is
registered. Never downgrade a live environment; fix forward.

Revision ID: 0026_dataset_ingest_role
Revises: 0025_dataset_ingestion
Create Date: 2026-10-07
"""

import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

from alembic import op

revision: str = "0026_dataset_ingest_role"
down_revision: str | Sequence[str] | None = "0025_dataset_ingestion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _load(filename: str) -> ModuleType:
    name = f"_nlw_migration_{filename.removesuffix('.py')}"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _m0024() -> ModuleType:
    return _load("0024_dataset_lifecycle.py")


def _m0025() -> ModuleType:
    return _load("0025_dataset_ingestion.py")


_T = "public.ctx_tenant_id()"
_ADMIN = f"(tenant_id = {_T} AND public.is_current_user_admin_or_owner(tenant_id))"
_IT = "public.ctx_ingest_tenant_id()"
_IV = "public.ctx_ingest_version_id()"
_INGEST_VERSION = f"(tenant_id = {_IT} AND version_id = {_IV})"
INGEST_EVENT_TYPES = ("VERSION_PROFILING_STARTED", "VERSION_PROFILED", "VERSION_REJECTED")
INGEST_VERSION_COLUMNS = (
    "status",
    "processing_lease_token",
    "processing_lease_expires_at",
    "storage_object_key",
    "rejection_code",
)

# --- the verifier, verbatim from 0016 (downgrade target) -------------------------
# A unit test proves this text appears byte-for-byte in migration 0016.
CLAIMS_0016 = """
        CREATE FUNCTION app_ctx_claims() RETURNS app_ctx_claims_t
            LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog
            AS $$
            DECLARE
                v       text := current_setting('app.ctx_v', true);
                kid     text := current_setting('app.ctx_kid', true);
                role    text := current_setting('app.ctx_role', true);
                purpose text := current_setting('app.ctx_purpose', true);
                usr     text := coalesce(current_setting('app.ctx_user', true), '');
                ten     text := coalesce(current_setting('app.ctx_tenant', true), '');
                run     text := coalesce(current_setting('app.ctx_run', true), '');
                iat     text := current_setting('app.ctx_iat', true);
                exp     text := current_setting('app.ctx_exp', true);
                nonce   text := current_setting('app.ctx_nonce', true);
                mac     text := current_setting('app.ctx_mac', true);
                k_secret bytea;
                k_class  text;
                k_expected text;
                want    bytea;
                got     bytea;
                acc     int := 0;
                i       int;
                now_e   bigint := floor(extract(epoch FROM clock_timestamp()))::bigint;
                iat_i   bigint;
                exp_i   bigint;
                uuid_re constant text :=
                    '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
            BEGIN
                -- 1) presence + version + formats (every check fails CLOSED -> NULL)
                IF v IS DISTINCT FROM '1' THEN RETURN NULL; END IF;
                IF kid IS NULL OR kid !~ '^[A-Za-z0-9._-]{1,64}$' THEN RETURN NULL; END IF;
                IF role IS NULL OR role !~ '^[a-z_][a-z0-9_]{0,62}$' THEN RETURN NULL; END IF;
                IF purpose IS NULL OR purpose NOT IN
                   ('api_identity', 'api_request', 'worker_execution', 'scheduler_reconcile')
                THEN RETURN NULL; END IF;
                IF usr <> '' AND usr !~ uuid_re THEN RETURN NULL; END IF;
                IF ten <> '' AND ten !~ uuid_re THEN RETURN NULL; END IF;
                IF run <> '' AND run !~ uuid_re THEN RETURN NULL; END IF;
                IF iat IS NULL OR iat !~ '^[0-9]{1,12}$' THEN RETURN NULL; END IF;
                IF exp IS NULL OR exp !~ '^[0-9]{1,12}$' THEN RETURN NULL; END IF;
                IF nonce IS NULL OR nonce !~ '^[0-9a-f]{32}$' THEN RETURN NULL; END IF;
                IF mac IS NULL OR mac !~ '^[0-9a-f]{64}$' THEN RETURN NULL; END IF;
                -- 2) the signed expected role must be THIS login role, and the
                --    purpose must be one that role may present
                IF role <> session_user::text THEN RETURN NULL; END IF;
                IF (purpose IN ('api_identity', 'api_request') AND role <> 'nlw_app')
                   OR (purpose = 'worker_execution' AND role <> 'nlw_worker')
                   OR (purpose = 'scheduler_reconcile' AND role <> 'nlw_scheduler')
                THEN RETURN NULL; END IF;
                -- 3) claim shape per purpose
                IF purpose = 'api_identity' AND (usr = '' OR ten <> '' OR run <> '')
                THEN RETURN NULL; END IF;
                IF purpose = 'api_request' AND (usr = '' OR ten = '' OR run <> '')
                THEN RETURN NULL; END IF;
                IF purpose = 'worker_execution' AND (usr <> '' OR ten = '')
                THEN RETURN NULL; END IF;
                IF purpose = 'scheduler_reconcile' AND (usr <> '' OR ten <> '' OR run <> '')
                THEN RETURN NULL; END IF;
                -- 4) time window: not from the future (60s skew), not expired,
                --    lifetime bounded (independent of the application's cap)
                iat_i := iat::bigint; exp_i := exp::bigint;
                IF iat_i > now_e + 60 THEN RETURN NULL; END IF;
                IF exp_i <= now_e THEN RETURN NULL; END IF;
                IF exp_i - iat_i < 1 OR exp_i - iat_i > 600 THEN RETURN NULL; END IF;
                -- 5) active key of the right class (unknown/revoked/retired -> NULL)
                SELECT k.secret, k.key_class INTO k_secret, k_class FROM public.ctx_keys k
                    WHERE k.key_id = kid AND k.status = 'active'
                      AND k.activated_at <= now()
                      AND (k.retired_at IS NULL OR k.retired_at > now());
                IF NOT FOUND THEN RETURN NULL; END IF;
                -- (assigned first: a CASE inside an IF condition would be cut at
                -- its inner THEN by the PL/pgSQL parser)
                k_expected := CASE purpose
                                WHEN 'worker_execution' THEN 'worker'
                                WHEN 'scheduler_reconcile' THEN 'scheduler'
                                ELSE 'api' END;
                IF k_class <> k_expected THEN RETURN NULL; END IF;
                -- 6) recompute the tag and compare in constant time
                want := public.hmac(
                    public.app_ctx_canon(v, kid, role, purpose, usr, ten, run, iat, exp, nonce),
                    k_secret, 'sha256');
                got := decode(mac, 'hex');
                IF octet_length(want) <> 32 OR octet_length(got) <> 32 THEN RETURN NULL; END IF;
                FOR i IN 0..31 LOOP
                    acc := acc | (get_byte(want, i) # get_byte(got, i));
                END LOOP;
                IF acc <> 0 THEN RETURN NULL; END IF;
                RETURN ROW(purpose, NULLIF(usr, '')::uuid, NULLIF(ten, '')::uuid,
                           NULLIF(run, '')::uuid, kid)::public.app_ctx_claims_t;
            END;
            $$
        """

# The four additions, each an exact replacement (asserted): the purpose, its
# role binding, its claim shape (tenant + run, no user) and its key class.
_CLAIMS_EDITS = (
    (
        "('api_identity', 'api_request', 'worker_execution', 'scheduler_reconcile')",
        "('api_identity', 'api_request', 'worker_execution', 'scheduler_reconcile',\n"
        "                    'dataset_ingest')",
    ),
    (
        "                   OR (purpose = 'scheduler_reconcile' AND role <> 'nlw_scheduler')\n",
        "                   OR (purpose = 'scheduler_reconcile' AND role <> 'nlw_scheduler')\n"
        "                   OR (purpose = 'dataset_ingest' AND role <> 'nlw_ingest')\n",
    ),
    (
        "                -- 4) time window",
        "                IF purpose = 'dataset_ingest' AND (usr <> '' OR ten = '' OR run = '')\n"
        "                THEN RETURN NULL; END IF;\n"
        "                -- 4) time window",
    ),
    (
        "                                WHEN 'scheduler_reconcile' THEN 'scheduler'\n",
        "                                WHEN 'scheduler_reconcile' THEN 'scheduler'\n"
        "                                WHEN 'dataset_ingest' THEN 'ingest'\n",
    ),
)


def claims_0026() -> str:
    text = CLAIMS_0016.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
    for old, new in _CLAIMS_EDITS:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    return text


def _claims_restore_0016() -> str:
    return CLAIMS_0016.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)


_ACCESSORS = (
    (
        "ctx_ingest_tenant_id()",
        "CREATE FUNCTION ctx_ingest_tenant_id() RETURNS uuid LANGUAGE sql STABLE "
        "SET search_path = pg_catalog AS $$ "
        "SELECT c.tenant_id FROM public.app_ctx_claims() c WHERE c.purpose = 'dataset_ingest' $$",
    ),
    (
        "ctx_ingest_version_id()",
        "CREATE FUNCTION ctx_ingest_version_id() RETURNS uuid LANGUAGE sql STABLE "
        "SET search_path = pg_catalog AS $$ "
        "SELECT c.run_id FROM public.app_ctx_claims() c WHERE c.purpose = 'dataset_ingest' $$",
    ),
)

# --- processing requests ---------------------------------------------------------
# Canonical envelope message v1 (byte-identical in nlw.datasets.envelope):
#   "nlwingest1" || for each field: <octet_length> ":" <value>
# fields: version, request_id, tenant_id, dataset_id, version_id, content_sha256,
#         requested_at in integer microseconds since the epoch.
REQUESTED_AT_US = "(extract(epoch FROM {col}) * 1000000)::bigint"
_ENVELOPE_DIGEST = (
    "encode(sha256(convert_to('nlwingest1' || "
    + " || ".join(
        f"octet_length({f}) || ':' || {f}"
        for f in (
            "'1'",
            "NEW.id::text",
            "NEW.tenant_id::text",
            "NEW.dataset_id::text",
            "NEW.version_id::text",
            "NEW.content_sha256",
            REQUESTED_AT_US.format(col="NEW.requested_at") + "::text",
        )
    )
    + ", 'UTF8')), 'hex')"
)

_REQUESTS_TABLE = """
CREATE TABLE dataset_processing_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    dataset_id uuid NOT NULL,
    version_id uuid NOT NULL,
    content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    requested_by uuid NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    envelope_sha256 text NOT NULL CHECK (envelope_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT fk_dataset_processing_requests_version
        FOREIGN KEY (version_id, dataset_id, tenant_id)
        REFERENCES dataset_versions (id, dataset_id, tenant_id)
)
"""

_FN_REQUEST_GUARD = f"""
CREATE FUNCTION dataset_processing_request_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    DECLARE
        v record;
    BEGIN
        IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'a processing request is immutable' USING ERRCODE = '23514';
        END IF;
        NEW.requested_at := now();
        SELECT vv.status, vv.content_sha256, vv.storage_object_key INTO v
            FROM public.dataset_versions vv
            WHERE vv.id = NEW.version_id AND vv.dataset_id = NEW.dataset_id
              AND vv.tenant_id = NEW.tenant_id;
        IF NOT FOUND OR v.status NOT IN ('QUARANTINED', 'PROFILING')
           OR v.content_sha256 IS NULL OR v.storage_object_key IS NULL
           OR v.content_sha256 <> NEW.content_sha256 THEN
            RAISE EXCEPTION 'a processing request needs a stored, unprocessed version and digest'
                USING ERRCODE = '23514';
        END IF;
        NEW.envelope_sha256 := {_ENVELOPE_DIGEST};
        RETURN NEW;
    END $$
"""

# --- version guard: processing belongs to the ingest runtime -----------------------
_PROCESSING_RULE = """        -- ADR-031: processing belongs to the ingest runtime. The API role may
        -- not take, renew or settle a lease, enter PROFILING/PROFILED, or reject
        -- a version that is being processed; the ingest role may only move a
        -- version along the processing path.
        IF session_user::text = 'nlw_app' AND (
            (NEW.status IN ('PROFILING', 'PROFILED') AND NEW.status <> OLD.status)
            OR (OLD.status = 'PROFILING' AND NEW.status = 'REJECTED')
            OR NEW.processing_lease_token IS DISTINCT FROM OLD.processing_lease_token
            OR NEW.processing_lease_expires_at IS DISTINCT FROM OLD.processing_lease_expires_at)
        THEN
            RAISE EXCEPTION 'processing transitions are reserved for the ingest service'
                USING ERRCODE = '42501';
        END IF;
        IF session_user::text = 'nlw_ingest' AND NEW.status <> OLD.status AND NOT (
            (OLD.status = 'QUARANTINED' AND NEW.status = 'PROFILING')
            OR (OLD.status = 'PROFILING' AND NEW.status IN ('PROFILED', 'REJECTED'))) THEN
            RAISE EXCEPTION 'the ingest service only moves a version along the processing path'
                USING ERRCODE = '42501';
        END IF;
"""
_TRANSITION_MARKER = "        IF NEW.status <> OLD.status AND NOT ("


def versions_guard_0026() -> str:
    original = _m0025()._fn_versions_guard()
    assert original.count(_TRANSITION_MARKER) == 1
    return original.replace(_TRANSITION_MARKER, _PROCESSING_RULE + _TRANSITION_MARKER)


# --- deferred checks ---------------------------------------------------------------
_RUNTIME_LIST_0025 = "('nlw_app', 'nlw_worker', 'nlw_scheduler')"
_RUNTIME_LIST_0026 = "('nlw_app', 'nlw_worker', 'nlw_scheduler', 'nlw_ingest')"


def event_required(runtime_list: str) -> str:
    original = _m0025()._FN_EVENT_REQUIRED
    assert original.count(_RUNTIME_LIST_0025) == 1
    text = original.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
    return text.replace(_RUNTIME_LIST_0025, runtime_list)


# The ingest role sees ONE version (RLS), so the cross-version counts below
# would be partial for it. Its transitions never involve ACTIVE, DELETING or
# DELETED (policy WITH CHECK + version guard), so those invariants cannot
# change; it is held to the one it can affect: its dataset must be ACTIVE.
_INGEST_CONSISTENCY = """
        IF session_user::text = 'nlw_ingest' THEN
            IF TG_TABLE_NAME <> 'dataset_versions'
               OR NEW.status NOT IN ('PROFILING', 'PROFILED', 'REJECTED') THEN
                RAISE EXCEPTION 'the ingest service changes only processing versions'
                    USING ERRCODE = '42501';
            END IF;
            SELECT d.status INTO ds_status FROM public.datasets d
                WHERE d.id = NEW.dataset_id AND d.tenant_id = NEW.tenant_id;
            IF ds_status IS DISTINCT FROM 'ACTIVE' THEN
                RAISE EXCEPTION 'a version is processed only in an ACTIVE dataset'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NULL;
        END IF;"""
_CONSISTENCY_MARKER = (
    "    BEGIN\n        -- Separate branches: NEW has no dataset_id column on the datasets table."
)


def consistency_0026() -> str:
    original = _m0024()._FN_CONSISTENCY
    assert original.count(_CONSISTENCY_MARKER) == 1
    text = original.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
    return text.replace(
        _CONSISTENCY_MARKER,
        "    BEGIN" + _INGEST_CONSISTENCY + _CONSISTENCY_MARKER.removeprefix("    BEGIN"),
    )


def _consistency_restore() -> str:
    return _m0024()._FN_CONSISTENCY.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)


# --- policies ----------------------------------------------------------------------
_VERSIONS_APP_UPDATE_0024 = (
    f"({_ADMIN} AND status <> 'DELETED')",
    f"({_ADMIN} AND status <> 'DELETED')",
)
_VERSIONS_APP_UPDATE = (
    f"({_ADMIN} AND status <> 'DELETED')",
    f"({_ADMIN} AND status NOT IN ('DELETED', 'PROFILING', 'PROFILED'))",
)
_ING_EVENTS = ", ".join(f"'{e}'" for e in INGEST_EVENT_TYPES)

# (name, table, command, role, using, with_check)
POLICIES: tuple[tuple[str, str, str, str, str | None, str | None], ...] = (
    (
        "dataset_processing_requests_app_select",
        "dataset_processing_requests",
        "SELECT",
        "nlw_app",
        _ADMIN,
        None,
    ),
    (
        "dataset_processing_requests_app_insert",
        "dataset_processing_requests",
        "INSERT",
        "nlw_app",
        None,
        f"({_ADMIN} AND requested_by = public.ctx_user_id())",
    ),
    (
        "dataset_processing_requests_ingest_select",
        "dataset_processing_requests",
        "SELECT",
        "nlw_ingest",
        _INGEST_VERSION,
        None,
    ),
    (
        "datasets_ingest_select",
        "datasets",
        "SELECT",
        "nlw_ingest",
        f"(tenant_id = {_IT} AND id = (SELECT v.dataset_id FROM public.dataset_versions v "
        f"WHERE v.id = {_IV} AND v.tenant_id = {_IT}))",
        None,
    ),
    (
        "dataset_versions_ingest_select",
        "dataset_versions",
        "SELECT",
        "nlw_ingest",
        f"(tenant_id = {_IT} AND id = {_IV})",
        None,
    ),
    (
        "dataset_versions_ingest_update",
        "dataset_versions",
        "UPDATE",
        "nlw_ingest",
        f"(tenant_id = {_IT} AND id = {_IV} AND status IN ('QUARANTINED', 'PROFILING'))",
        f"(tenant_id = {_IT} AND id = {_IV} AND status IN ('PROFILING', 'PROFILED', 'REJECTED'))",
    ),
    (
        "dataset_profiles_ingest_select",
        "dataset_profiles",
        "SELECT",
        "nlw_ingest",
        _INGEST_VERSION,
        None,
    ),
    (
        "dataset_profiles_ingest_insert",
        "dataset_profiles",
        "INSERT",
        "nlw_ingest",
        None,
        _INGEST_VERSION,
    ),
    (
        "dataset_events_ingest_select",
        "dataset_events",
        "SELECT",
        "nlw_ingest",
        _INGEST_VERSION,
        None,
    ),
    (
        "dataset_events_ingest_insert",
        "dataset_events",
        "INSERT",
        "nlw_ingest",
        None,
        f"({_INGEST_VERSION[1:-1]} AND actor_kind = 'service' AND actor_user_id IS NULL "
        f"AND event_type IN ({_ING_EVENTS}))",
    ),
)


def _create_policy(
    name: str, table: str, cmd: str, role: str, using: str | None, check: str | None
) -> None:
    sql = f"CREATE POLICY {name} ON {table} FOR {cmd} TO {role}"
    if using is not None:
        sql += f" USING {using}"
    if check is not None:
        sql += f" WITH CHECK {check}"
    op.execute(sql)


def _versions_app_update(using: str, check: str) -> None:
    op.execute("DROP POLICY dataset_versions_app_update ON dataset_versions")
    _create_policy(
        "dataset_versions_app_update", "dataset_versions", "UPDATE", "nlw_app", using, check
    )


def _profiles_app_insert() -> tuple[str, str, str, str | None, str | None]:
    for name, table, cmd, using, check in _m0025()._POLICIES:
        if name == "dataset_profiles_app_insert":
            return name, table, cmd, using, check
    raise AssertionError("0025 has no dataset_profiles_app_insert")


def upgrade() -> None:
    # --- connection-level access for the (separately provisioned) role ---------
    op.execute(
        "DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO nlw_ingest', "
        "current_database()); END $$"
    )
    op.execute("GRANT USAGE ON SCHEMA public TO nlw_ingest")

    # --- signed context: key class, verifier, accessors -------------------------
    op.execute("ALTER TABLE ctx_keys DROP CONSTRAINT ctx_keys_key_class_check")
    op.execute(
        "ALTER TABLE ctx_keys ADD CONSTRAINT ctx_keys_key_class_check "
        "CHECK (key_class IN ('api', 'worker', 'scheduler', 'ingest'))"
    )
    op.execute(claims_0026())
    op.execute("GRANT EXECUTE ON FUNCTION app_ctx_claims() TO nlw_ingest")
    for sig, ddl in _ACCESSORS:
        op.execute(ddl)
        op.execute(f"ALTER FUNCTION {sig} OWNER TO nlw_ctx_verifier")
        op.execute(f"REVOKE ALL ON FUNCTION {sig} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {sig} TO nlw_ingest")

    # --- processing requests -------------------------------------------------------
    op.execute(_REQUESTS_TABLE)
    op.execute(
        "CREATE INDEX ix_dataset_processing_requests_version "
        "ON dataset_processing_requests (version_id)"
    )
    op.execute(_FN_REQUEST_GUARD)
    op.execute("REVOKE ALL ON FUNCTION dataset_processing_request_guard() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER dataset_processing_requests_guard BEFORE INSERT OR UPDATE OR DELETE "
        "ON dataset_processing_requests FOR EACH ROW "
        "EXECUTE FUNCTION dataset_processing_request_guard()"
    )
    op.execute("REVOKE ALL ON dataset_processing_requests FROM PUBLIC")
    op.execute("ALTER TABLE dataset_processing_requests ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE dataset_processing_requests FORCE ROW LEVEL SECURITY")
    op.execute("GRANT SELECT, INSERT ON dataset_processing_requests TO nlw_app")

    # --- the API role leaves the processing path ----------------------------------
    op.execute("DROP POLICY dataset_profiles_app_insert ON dataset_profiles")
    op.execute("REVOKE INSERT ON dataset_profiles FROM nlw_app")
    _versions_app_update(*_VERSIONS_APP_UPDATE)
    op.execute(versions_guard_0026())

    # --- nlw_ingest: exactly the processing path -----------------------------------
    op.execute("GRANT SELECT ON datasets TO nlw_ingest")
    op.execute(
        f"GRANT SELECT, UPDATE ({', '.join(INGEST_VERSION_COLUMNS)}) "
        "ON dataset_versions TO nlw_ingest"
    )
    op.execute("GRANT SELECT, INSERT ON dataset_profiles TO nlw_ingest")
    op.execute("GRANT SELECT, INSERT ON dataset_events TO nlw_ingest")
    op.execute("GRANT SELECT ON dataset_processing_requests TO nlw_ingest")
    # The DR recovery lock, like every runtime (lock columns only; no tenant data).
    op.execute(
        "GRANT SELECT (id, restored_at, validation_completed_at, runtime_enabled_at) "
        "ON dr_restore_events TO nlw_ingest"
    )
    for policy in POLICIES:
        _create_policy(*policy)

    # --- deferred checks ---------------------------------------------------------
    op.execute(event_required(_RUNTIME_LIST_0026))
    op.execute(consistency_0026())


def downgrade() -> None:
    # Disposable databases only (see the module docstring).
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM ctx_keys WHERE key_class = 'ingest') THEN "
        "RAISE EXCEPTION 'ingest keys are registered: revoke and remove them before a "
        "downgrade (disposable databases only)'; END IF; END $$"
    )
    op.execute(_consistency_restore())
    op.execute(event_required(_RUNTIME_LIST_0025))
    for name, table, *_ in reversed(POLICIES):
        op.execute(f"DROP POLICY IF EXISTS {name} ON {table}")
    op.execute(
        "REVOKE SELECT (id, restored_at, validation_completed_at, runtime_enabled_at) "
        "ON dr_restore_events FROM nlw_ingest"
    )
    op.execute(
        "REVOKE ALL ON datasets, dataset_versions, dataset_profiles, dataset_events FROM nlw_ingest"
    )

    op.execute(
        _m0025()._fn_versions_guard().replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
    )
    _versions_app_update(*_VERSIONS_APP_UPDATE_0024)
    op.execute("GRANT INSERT ON dataset_profiles TO nlw_app")
    name, table, cmd, using, check = _profiles_app_insert()
    _create_policy(name, table, cmd, "nlw_app", using, check)

    op.execute("DROP TABLE dataset_processing_requests")
    op.execute("DROP FUNCTION dataset_processing_request_guard()")

    for sig, _ in reversed(_ACCESSORS):
        op.execute(f"DROP FUNCTION {sig}")
    op.execute("REVOKE EXECUTE ON FUNCTION app_ctx_claims() FROM nlw_ingest")
    op.execute(_claims_restore_0016())
    op.execute("ALTER TABLE ctx_keys DROP CONSTRAINT ctx_keys_key_class_check")
    op.execute(
        "ALTER TABLE ctx_keys ADD CONSTRAINT ctx_keys_key_class_check "
        "CHECK (key_class IN ('api', 'worker', 'scheduler'))"
    )
    op.execute("REVOKE USAGE ON SCHEMA public FROM nlw_ingest")
    op.execute(
        "DO $$ BEGIN EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM nlw_ingest', "
        "current_database()); END $$"
    )
