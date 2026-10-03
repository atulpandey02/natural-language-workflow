"""Dataset lifecycle foundation: metadata only (Phase 2A, ADR-029).

Adds three tenant-scoped tables and NO customer data:

- ``datasets``: a stable logical container per workspace. States
  ``ACTIVE -> DELETING -> DELETED``. The name is unique per workspace
  (case-insensitive) among non-tombstoned rows; a ``DELETED`` row is a scrubbed
  tombstone (no name or description).
- ``dataset_versions``: one immutable record per future ingested object, numbered
  per dataset from an atomic counter (never reused). States ``QUARANTINED ->
  PROFILING -> PROFILED -> ACTIVE -> SUPERSEDED`` with ``REJECTED`` and
  ``DELETING -> DELETED`` (the full table is in ADR-029). File metadata is bounded
  and sanitized; a digest and a storage-object key placeholder are set once, later,
  by ingestion. No bytes, rows, URLs or credentials are stored.
- ``dataset_events``: append-only lifecycle evidence with closed vocabularies.

Every invariant is enforced in the database for every role (triggers), not only
by the service: valid transitions, immutable columns, set-once fields, scrubbing
only on the tombstone, insert only into an ACTIVE dataset with the allocated
version number, nothing ever leaves DELETED, at most one ACTIVE version, and (a
deferred constraint trigger checked at commit) ``active_version_id`` set exactly
when the dataset has an ACTIVE version, a DELETING dataset with no live version,
and a DELETED dataset with only DELETED versions.

Tenancy: RLS on the signed context (migration 0016 predicates). ``nlw_app`` reads
as a member, inserts and updates as an admin/owner, can never write or touch a
DELETED row, and cannot delete. Lifecycle events are admin-readable and
append-only for runtime roles. ``nlw_worker``, ``nlw_scheduler`` and PUBLIC have
no privileges. No SECURITY DEFINER function is added; trigger functions run as
the invoker with a fixed search_path. The tombstone (-> DELETED) is an operator
action with the owner credential (``python -m nlw.ops.datasets``).

The signed-policy inventory grows from 53 to 61 (8 policies below).

Downgrade drops the three tables and their functions. It exists for disposable
environments and tests only: never downgrade a live environment that holds
dataset metadata (the evidence trail would be destroyed); fix forward.

Revision ID: 0024_dataset_lifecycle
Revises: 0023_plan_outcome_events
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0024_dataset_lifecycle"
down_revision: str | Sequence[str] | None = "0023_plan_outcome_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_T = "public.ctx_tenant_id()"
_MEMBER = f"(tenant_id = {_T} AND public.is_current_user_member(tenant_id))"
_ADMIN = f"(tenant_id = {_T} AND public.is_current_user_admin_or_owner(tenant_id))"

DATASET_STATES = ("ACTIVE", "DELETING", "DELETED")
VERSION_STATES = (
    "QUARANTINED",
    "PROFILING",
    "PROFILED",
    "ACTIVE",
    "SUPERSEDED",
    "REJECTED",
    "DELETING",
    "DELETED",
)
# The nlw.ingest reject codes plus a human review rejection.
REJECTION_CODES = (
    "FILE_TYPE",
    "FILE_TOO_LARGE",
    "FILE_EMPTY",
    "CONTENT_BINARY",
    "ENCODING_UNSUPPORTED",
    "TOO_MANY_ROWS",
    "TOO_MANY_COLUMNS",
    "FIELD_TOO_LARGE",
    "PARSE_TIMEOUT",
    "PARSE_ERROR",
    "REVIEW_REJECTED",
)
EVENT_TYPES = (
    "DATASET_CREATED",
    "DATASET_DELETION_REQUESTED",
    "DATASET_TOMBSTONED",
    "VERSION_CREATED",
    "VERSION_PROFILING_STARTED",
    "VERSION_PROFILED",
    "VERSION_ACTIVATED",
    "VERSION_SUPERSEDED",
    "VERSION_REJECTED",
    "VERSION_DELETION_REQUESTED",
    "VERSION_TOMBSTONED",
)
REASON_CODES = ("USER_REQUEST", "DATASET_DELETION", "OPERATOR_TOMBSTONE", *REJECTION_CODES)
MAX_DECLARED_SIZE_BYTES = 25_000_000  # the nlw.ingest profiler's byte cap


def _in(values: Sequence[str]) -> str:
    return ", ".join(f"'{v}'" for v in values)


_DATASETS = f"""
CREATE TABLE datasets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES workspaces (id),
    name text CHECK (name IS NULL OR (
        char_length(name) BETWEEN 1 AND 100 AND name = btrim(name)
        AND name !~ '[[:cntrl:]]')),
    normalized_name text CHECK (normalized_name IS NULL OR
        char_length(normalized_name) BETWEEN 1 AND 400),
    description text CHECK (description IS NULL OR (
        char_length(description) <= 500
        AND regexp_replace(description, '[\t\n\r]', '', 'g') !~ '[[:cntrl:]]')),
    status text NOT NULL CHECK (status IN ({_in(DATASET_STATES)})),
    active_version_id uuid,
    last_version_number integer NOT NULL DEFAULT 0 CHECK (last_version_number >= 0),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deletion_requested_at timestamptz,
    deleted_at timestamptz,
    CONSTRAINT uq_datasets_id_tenant UNIQUE (id, tenant_id),
    CONSTRAINT ck_datasets_name_iff_live CHECK ((name IS NULL) = (status = 'DELETED')),
    CONSTRAINT ck_datasets_normalized_iff_live
        CHECK ((normalized_name IS NULL) = (status = 'DELETED')),
    CONSTRAINT ck_datasets_description_scrubbed
        CHECK (status <> 'DELETED' OR description IS NULL),
    CONSTRAINT ck_datasets_pointer_only_active
        CHECK (status = 'ACTIVE' OR active_version_id IS NULL),
    CONSTRAINT ck_datasets_deletion_requested
        CHECK ((deletion_requested_at IS NULL) = (status = 'ACTIVE')),
    CONSTRAINT ck_datasets_deleted_at CHECK ((deleted_at IS NULL) = (status <> 'DELETED'))
)
"""

_VERSIONS = f"""
CREATE TABLE dataset_versions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    dataset_id uuid NOT NULL,
    version_number integer NOT NULL CHECK (version_number >= 1),
    status text NOT NULL CHECK (status IN ({_in(VERSION_STATES)})),
    original_filename text CHECK (original_filename IS NULL OR (
        char_length(original_filename) BETWEEN 1 AND 255
        AND original_filename = btrim(original_filename)
        AND original_filename !~ E'[/\\\\\\\\]'
        AND original_filename !~ '[[:cntrl:]]'
        AND original_filename NOT IN ('.', '..'))),
    media_type text NOT NULL CHECK (media_type IN ('text/csv')),
    declared_size_bytes bigint NOT NULL
        CHECK (declared_size_bytes BETWEEN 1 AND {MAX_DECLARED_SIZE_BYTES}),
    content_sha256 text CHECK (content_sha256 IS NULL OR content_sha256 ~ '^[0-9a-f]{{64}}$'),
    storage_object_key text CHECK (storage_object_key IS NULL OR (
        char_length(storage_object_key) <= 300
        AND storage_object_key ~
            '^(quarantine|datasets)/[0-9a-f-]{{36}}/[0-9a-f-]{{36}}/[a-z0-9][a-z0-9._-]{{0,127}}$'
        AND split_part(storage_object_key, '/', 2) = tenant_id::text
        AND split_part(storage_object_key, '/', 3) = dataset_id::text)),
    rejection_code text
        CHECK (rejection_code IS NULL OR rejection_code IN ({_in(REJECTION_CODES)})),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    profiling_started_at timestamptz,
    profiled_at timestamptz,
    activated_at timestamptz,
    superseded_at timestamptz,
    rejected_at timestamptz,
    deletion_requested_at timestamptz,
    deleted_at timestamptz,
    CONSTRAINT fk_dataset_versions_dataset FOREIGN KEY (dataset_id, tenant_id)
        REFERENCES datasets (id, tenant_id),
    CONSTRAINT uq_dataset_versions_number UNIQUE (dataset_id, version_number),
    CONSTRAINT uq_dataset_versions_id_dataset_tenant UNIQUE (id, dataset_id, tenant_id),
    CONSTRAINT ck_dataset_versions_filename_iff_live
        CHECK ((original_filename IS NULL) = (status = 'DELETED')),
    CONSTRAINT ck_dataset_versions_key_scrubbed
        CHECK (status <> 'DELETED' OR storage_object_key IS NULL),
    CONSTRAINT ck_dataset_versions_rejected_has_code
        CHECK (status <> 'REJECTED' OR rejection_code IS NOT NULL),
    CONSTRAINT ck_dataset_versions_code_only_when_rejected
        CHECK (rejection_code IS NULL OR status IN ('REJECTED', 'DELETING', 'DELETED')),
    CONSTRAINT ck_dataset_versions_deletion_requested
        CHECK ((deletion_requested_at IS NOT NULL) = (status IN ('DELETING', 'DELETED'))),
    CONSTRAINT ck_dataset_versions_deleted_at
        CHECK ((deleted_at IS NULL) = (status <> 'DELETED'))
)
"""

_EVENTS = f"""
CREATE TABLE dataset_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    dataset_id uuid NOT NULL,
    version_id uuid,
    event_type text NOT NULL CHECK (event_type IN ({_in(EVENT_TYPES)})),
    from_status text CHECK (from_status IS NULL OR from_status IN ({_in(VERSION_STATES)})),
    to_status text NOT NULL CHECK (to_status IN ({_in(VERSION_STATES)})),
    actor_kind text NOT NULL CHECK (actor_kind IN ('user', 'service', 'operator')),
    actor_user_id uuid,
    reason_code text CHECK (reason_code IS NULL OR reason_code IN ({_in(REASON_CODES)})),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_dataset_events_dataset FOREIGN KEY (dataset_id, tenant_id)
        REFERENCES datasets (id, tenant_id),
    CONSTRAINT fk_dataset_events_version FOREIGN KEY (version_id, dataset_id, tenant_id)
        REFERENCES dataset_versions (id, dataset_id, tenant_id),
    CONSTRAINT ck_dataset_events_version_scope
        CHECK ((event_type LIKE 'VERSION\\_%') = (version_id IS NOT NULL)),
    CONSTRAINT ck_dataset_events_user_actor
        CHECK (actor_kind <> 'user' OR actor_user_id IS NOT NULL),
    CONSTRAINT ck_dataset_events_operator_actor
        CHECK (actor_kind <> 'operator' OR actor_user_id IS NULL)
)
"""

_VERSION_TRANSITIONS = {
    "QUARANTINED": ("PROFILING", "REJECTED", "DELETING"),
    "PROFILING": ("PROFILED", "REJECTED", "DELETING"),
    "PROFILED": ("ACTIVE", "REJECTED", "DELETING"),
    "ACTIVE": ("SUPERSEDED", "DELETING"),
    "SUPERSEDED": ("DELETING",),
    "REJECTED": ("DELETING",),
    "DELETING": ("DELETED",),
    "DELETED": (),
}


def _version_transition_case() -> str:
    arms = []
    for src, dsts in _VERSION_TRANSITIONS.items():
        allowed = f"NEW.status IN ({_in(dsts)})" if dsts else "false"
        arms.append(f"WHEN '{src}' THEN {allowed}")
    return "CASE OLD.status " + " ".join(arms) + " ELSE false END"


_FN_DATASETS_GUARD = """
CREATE FUNCTION dataset_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'ACTIVE' OR NEW.active_version_id IS NOT NULL
               OR NEW.last_version_number <> 0 THEN
                RAISE EXCEPTION 'a dataset is created ACTIVE, empty and without a version'
                    USING ERRCODE = '23514';
            END IF;
            NEW.deletion_requested_at := NULL;
            NEW.deleted_at := NULL;
            NEW.created_at := now();
            NEW.updated_at := now();
            RETURN NEW;
        END IF;
        IF OLD.status = 'DELETED' THEN
            RAISE EXCEPTION 'a deleted dataset cannot change' USING ERRCODE = '23514';
        END IF;
        IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
           OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'dataset identity is immutable' USING ERRCODE = '23514';
        END IF;
        IF NEW.status <> OLD.status AND NOT (
            (OLD.status = 'ACTIVE' AND NEW.status = 'DELETING')
            OR (OLD.status = 'DELETING' AND NEW.status = 'DELETED')) THEN
            RAISE EXCEPTION 'invalid dataset transition' USING ERRCODE = '23514';
        END IF;
        IF NEW.status <> 'DELETED' AND (
            NEW.name IS DISTINCT FROM OLD.name
            OR NEW.normalized_name IS DISTINCT FROM OLD.normalized_name
            OR NEW.description IS DISTINCT FROM OLD.description) THEN
            RAISE EXCEPTION 'dataset metadata is immutable' USING ERRCODE = '23514';
        END IF;
        IF NEW.last_version_number <> OLD.last_version_number AND NOT (
            NEW.last_version_number = OLD.last_version_number + 1
            AND OLD.status = 'ACTIVE' AND NEW.status = 'ACTIVE') THEN
            RAISE EXCEPTION 'version numbers are allocated one at a time on an ACTIVE dataset'
                USING ERRCODE = '23514';
        END IF;
        NEW.deletion_requested_at := CASE WHEN OLD.status = 'ACTIVE' AND NEW.status = 'DELETING'
            THEN now() ELSE OLD.deletion_requested_at END;
        NEW.deleted_at := CASE WHEN NEW.status = 'DELETED' THEN now() ELSE OLD.deleted_at END;
        NEW.updated_at := now();
        RETURN NEW;
    END $$
"""


def _fn_versions_guard() -> str:
    return f"""
CREATE FUNCTION dataset_version_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    DECLARE
        ds_status text;
        ds_last integer;
    BEGIN
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'QUARANTINED' OR NEW.rejection_code IS NOT NULL THEN
                RAISE EXCEPTION 'a version is created QUARANTINED' USING ERRCODE = '23514';
            END IF;
            SELECT d.status, d.last_version_number INTO ds_status, ds_last
                FROM public.datasets d
                WHERE d.id = NEW.dataset_id AND d.tenant_id = NEW.tenant_id;
            IF ds_status IS DISTINCT FROM 'ACTIVE' THEN
                RAISE EXCEPTION 'versions can only be added to an ACTIVE dataset'
                    USING ERRCODE = '23514';
            END IF;
            IF NEW.version_number <> ds_last THEN
                RAISE EXCEPTION 'version number must be the allocated one'
                    USING ERRCODE = '23514';
            END IF;
            NEW.profiling_started_at := NULL; NEW.profiled_at := NULL;
            NEW.activated_at := NULL; NEW.superseded_at := NULL; NEW.rejected_at := NULL;
            NEW.deletion_requested_at := NULL; NEW.deleted_at := NULL;
            NEW.created_at := now();
            NEW.updated_at := now();
            RETURN NEW;
        END IF;
        IF OLD.status = 'DELETED' THEN
            RAISE EXCEPTION 'a deleted dataset version cannot change' USING ERRCODE = '23514';
        END IF;
        IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.dataset_id <> OLD.dataset_id
           OR NEW.version_number <> OLD.version_number OR NEW.media_type <> OLD.media_type
           OR NEW.declared_size_bytes <> OLD.declared_size_bytes
           OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'dataset version identity is immutable' USING ERRCODE = '23514';
        END IF;
        IF NEW.status <> OLD.status AND NOT ({_version_transition_case()}) THEN
            RAISE EXCEPTION 'invalid dataset version transition' USING ERRCODE = '23514';
        END IF;
        IF NEW.original_filename IS DISTINCT FROM OLD.original_filename
           AND NEW.status <> 'DELETED' THEN
            RAISE EXCEPTION 'original filename is immutable' USING ERRCODE = '23514';
        END IF;
        IF NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256 AND NOT (
            OLD.content_sha256 IS NULL AND OLD.status = 'QUARANTINED'
            AND NEW.status = 'QUARANTINED') THEN
            RAISE EXCEPTION 'content digest is set once, while QUARANTINED'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.storage_object_key IS DISTINCT FROM OLD.storage_object_key AND NOT (
            (OLD.storage_object_key IS NULL AND OLD.status = 'QUARANTINED'
             AND NEW.status = 'QUARANTINED')
            OR NEW.status = 'DELETED') THEN
            RAISE EXCEPTION 'storage key is set once, while QUARANTINED' USING ERRCODE = '23514';
        END IF;
        IF NEW.rejection_code IS DISTINCT FROM OLD.rejection_code AND NOT (
            OLD.rejection_code IS NULL AND NEW.status = 'REJECTED'
            AND OLD.status <> 'REJECTED') THEN
            RAISE EXCEPTION 'rejection code is set once, on rejection' USING ERRCODE = '23514';
        END IF;
        NEW.profiling_started_at := CASE WHEN NEW.status = 'PROFILING' AND OLD.status <> 'PROFILING'
            THEN now() ELSE OLD.profiling_started_at END;
        NEW.profiled_at := CASE WHEN NEW.status = 'PROFILED' AND OLD.status <> 'PROFILED'
            THEN now() ELSE OLD.profiled_at END;
        NEW.activated_at := CASE WHEN NEW.status = 'ACTIVE' AND OLD.status <> 'ACTIVE'
            THEN now() ELSE OLD.activated_at END;
        NEW.superseded_at := CASE WHEN NEW.status = 'SUPERSEDED' AND OLD.status <> 'SUPERSEDED'
            THEN now() ELSE OLD.superseded_at END;
        NEW.rejected_at := CASE WHEN NEW.status = 'REJECTED' AND OLD.status <> 'REJECTED'
            THEN now() ELSE OLD.rejected_at END;
        NEW.deletion_requested_at := CASE WHEN NEW.status = 'DELETING' AND OLD.status <> 'DELETING'
            THEN now() ELSE OLD.deletion_requested_at END;
        NEW.deleted_at := CASE WHEN NEW.status = 'DELETED' THEN now() ELSE OLD.deleted_at END;
        NEW.updated_at := now();
        RETURN NEW;
    END $$
"""


# Checked at COMMIT (deferred) for every dataset touched in the transaction, so a
# multi-statement activation or deletion is judged only in its final state.
_FN_CONSISTENCY = """
CREATE FUNCTION dataset_consistency_check() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    DECLARE
        ds_id uuid;
        ds_status text;
        ds_pointer uuid;
        live_active uuid;
        n_active integer;
        n_not_deleting integer;
        n_not_deleted integer;
    BEGIN
        -- Separate branches: NEW has no dataset_id column on the datasets table.
        IF TG_TABLE_NAME = 'datasets' THEN
            ds_id := NEW.id;
        ELSE
            ds_id := NEW.dataset_id;
        END IF;
        SELECT d.status, d.active_version_id INTO ds_status, ds_pointer
            FROM public.datasets d WHERE d.id = ds_id;
        SELECT count(*), min(v.id::text)::uuid INTO n_active, live_active
            FROM public.dataset_versions v WHERE v.dataset_id = ds_id AND v.status = 'ACTIVE';
        IF n_active > 1 THEN
            RAISE EXCEPTION 'a dataset has at most one ACTIVE version' USING ERRCODE = '23514';
        END IF;
        IF ds_pointer IS DISTINCT FROM live_active THEN
            RAISE EXCEPTION 'active_version_id must point at the ACTIVE version'
                USING ERRCODE = '23514';
        END IF;
        IF ds_status = 'DELETING' THEN
            SELECT count(*) INTO n_not_deleting FROM public.dataset_versions v
                WHERE v.dataset_id = ds_id AND v.status NOT IN ('DELETING', 'DELETED');
            IF n_not_deleting > 0 THEN
                RAISE EXCEPTION 'a DELETING dataset has only DELETING or DELETED versions'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF ds_status = 'DELETED' THEN
            SELECT count(*) INTO n_not_deleted FROM public.dataset_versions v
                WHERE v.dataset_id = ds_id AND v.status <> 'DELETED';
            IF n_not_deleted > 0 THEN
                RAISE EXCEPTION 'a DELETED dataset has only DELETED versions'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
        RETURN NULL;
    END $$
"""

_POLICIES = (
    ("datasets_app_select", "datasets", "SELECT", _MEMBER, None),
    ("datasets_app_insert", "datasets", "INSERT", None, f"({_ADMIN} AND status = 'ACTIVE')"),
    (
        "datasets_app_update",
        "datasets",
        "UPDATE",
        f"({_ADMIN} AND status <> 'DELETED')",
        f"({_ADMIN} AND status <> 'DELETED')",
    ),
    ("dataset_versions_app_select", "dataset_versions", "SELECT", _MEMBER, None),
    ("dataset_versions_app_insert", "dataset_versions", "INSERT", None, _ADMIN),
    (
        "dataset_versions_app_update",
        "dataset_versions",
        "UPDATE",
        f"({_ADMIN} AND status <> 'DELETED')",
        f"({_ADMIN} AND status <> 'DELETED')",
    ),
    ("dataset_events_app_select", "dataset_events", "SELECT", _ADMIN, None),
    (
        "dataset_events_app_insert",
        "dataset_events",
        "INSERT",
        None,
        f"({_ADMIN} AND actor_kind <> 'operator' AND to_status <> 'DELETED')",
    ),
)

_TABLES = ("datasets", "dataset_versions", "dataset_events")
_FUNCTIONS = ("dataset_guard()", "dataset_version_guard()", "dataset_consistency_check()")


def upgrade() -> None:
    op.execute(_DATASETS)
    op.execute(_VERSIONS)
    op.execute(
        "ALTER TABLE datasets ADD CONSTRAINT fk_datasets_active_version "
        "FOREIGN KEY (active_version_id, id, tenant_id) "
        "REFERENCES dataset_versions (id, dataset_id, tenant_id)"
    )
    op.execute(_EVENTS)

    op.execute(
        "CREATE UNIQUE INDEX uq_datasets_tenant_normalized_name ON datasets "
        "(tenant_id, normalized_name) WHERE normalized_name IS NOT NULL"
    )
    op.execute("CREATE INDEX ix_datasets_tenant_created ON datasets (tenant_id, created_at)")
    op.execute(
        "CREATE UNIQUE INDEX uq_dataset_versions_one_active ON dataset_versions (dataset_id) "
        "WHERE status = 'ACTIVE'"
    )
    op.execute(
        "CREATE INDEX ix_dataset_versions_tenant_dataset ON dataset_versions "
        "(tenant_id, dataset_id, version_number)"
    )
    op.execute(
        "CREATE INDEX ix_dataset_events_tenant_dataset ON dataset_events "
        "(tenant_id, dataset_id, created_at)"
    )

    op.execute(_FN_DATASETS_GUARD)
    op.execute(_fn_versions_guard())
    op.execute(_FN_CONSISTENCY)
    for fn in _FUNCTIONS:
        op.execute(f"REVOKE ALL ON FUNCTION {fn} FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER datasets_guard BEFORE INSERT OR UPDATE ON datasets "
        "FOR EACH ROW EXECUTE FUNCTION dataset_guard()"
    )
    op.execute(
        "CREATE TRIGGER dataset_versions_guard BEFORE INSERT OR UPDATE ON dataset_versions "
        "FOR EACH ROW EXECUTE FUNCTION dataset_version_guard()"
    )
    for table in ("datasets", "dataset_versions"):
        op.execute(
            f"CREATE CONSTRAINT TRIGGER {table}_consistency AFTER INSERT OR UPDATE ON {table} "
            "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
            "EXECUTE FUNCTION dataset_consistency_check()"
        )

    for table in _TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM PUBLIC")
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute("GRANT SELECT, INSERT, UPDATE ON datasets, dataset_versions TO nlw_app")
    op.execute("GRANT SELECT, INSERT ON dataset_events TO nlw_app")
    for name, table, command, using, check in _POLICIES:
        clause = f"CREATE POLICY {name} ON {table} FOR {command} TO nlw_app"
        if using is not None:
            clause += f" USING {using}"
        if check is not None:
            clause += f" WITH CHECK {check}"
        op.execute(clause)


def downgrade() -> None:
    # Disposable environments and tests only (see the module docstring).
    op.execute("DROP TABLE IF EXISTS dataset_events")
    op.execute(
        "ALTER TABLE IF EXISTS datasets DROP CONSTRAINT IF EXISTS fk_datasets_active_version"
    )
    op.execute("DROP TABLE IF EXISTS dataset_versions")
    op.execute("DROP TABLE IF EXISTS datasets")
    for fn in _FUNCTIONS:
        op.execute(f"DROP FUNCTION IF EXISTS {fn}")
