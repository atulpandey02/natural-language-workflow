"""Dataset ingestion: profiles, semantic confirmation, upload idempotency (ADR-030).

Additive on top of ``0024_dataset_lifecycle`` (which is NOT edited):

- ``dataset_profiles``: exactly one immutable ``profile-2`` per dataset version
  (counts, inferred types and bounded statistics; no rows and no sample values).
  It is inserted only while the version is ``PROFILING`` and only with the
  version's own content digest. The tombstone scrubs it to ``NULL``.
- ``dataset_semantic_revisions``: append-only, numbered per version. Admin
  confirmations of the column semantics, recorded with the confirming user
  (bound to the SIGNED user by RLS) and a database timestamp. Inserted only
  while the version is ``PROFILED``. The tombstone scrubs the mapping.
- ``dataset_versions.upload_idempotency_key``: set at insert, immutable, unique
  per dataset (a retried upload initiation returns the same version).
- A storage key's object component must equal the version id (quarantine and
  published keys alike), for every role.
- Purge events carry their deletion receipt (sink, opaque id, deletion-set
  digest); no other event may.
- Lifecycle-event authenticity: an event is accepted only if it records the
  transition this transaction just made (exact from/to, entered at now(), one
  per transition); runtime events name the signed user; a runtime-role
  transition must leave its event (deferred check). No SECURITY DEFINER.
- A processing lease (token + expiry, PostgreSQL time) on PROFILING versions;
  leaving PROFILING for PROFILED/REJECTED requires a live lease.
- Closed vocabularies widen: new rejection codes for the strict pilot CSV policy
  and the operator-only evidence event ``VERSION_OBJECT_PURGED``
  (``DELETING -> DELETING``, actor ``operator``). The runtime insert policy for
  events is re-created so ``nlw_app`` can never write that event.
- ``dataset_version_guard()`` is REPLACED with every 0024 rule plus:
  * the storage key may move from ``quarantine/`` to ``datasets/`` (same tenant,
    dataset and object name) only on ``PROFILING -> PROFILED``;
  * ``PROFILED`` requires the version's profile with the same digest;
  * ``ACTIVE`` requires at least one confirmed semantic revision;
  * the upload idempotency key never changes.

Tenancy: forced RLS on both new tables on the signed context (0016 predicates).
``nlw_app`` reads and inserts as an admin/owner of the signed workspace; it has
no UPDATE or DELETE. ``nlw_worker``, ``nlw_scheduler`` and PUBLIC have nothing.
No SECURITY DEFINER function is added; the guard functions run as the invoker
with a fixed search_path. The signed-policy inventory grows from 61 to 65.

Downgrade restores the 0024 objects exactly. It is for disposable environments
and tests only: never downgrade a live environment that holds dataset metadata,
profiles or semantic confirmations; fix forward.

Revision ID: 0025_dataset_ingestion
Revises: 0024_dataset_lifecycle
"""

import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

from alembic import op

revision: str = "0025_dataset_ingestion"
down_revision: str | Sequence[str] | None = "0024_dataset_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _m0024() -> ModuleType:
    """The 0024 module, for its vocabularies and the original guard (downgrade)."""
    name = "nlw_migration_0024_dataset_lifecycle"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).with_name("0024_dataset_lifecycle.py")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_T = "public.ctx_tenant_id()"
_ADMIN = f"(tenant_id = {_T} AND public.is_current_user_admin_or_owner(tenant_id))"

# Strict pilot CSV policy (nlw.ingest.strict) and processing outcomes.
NEW_REJECTION_CODES = (
    "HEADER_INVALID",
    "HEADER_DUPLICATE",
    "NO_DATA_ROWS",
    "ROW_WIDTH_MISMATCH",
    "CONTENT_MISMATCH",
    "PROCESSING_FAILED",
)
NEW_EVENT_TYPES = ("VERSION_OBJECT_PURGED",)
NEW_REASON_CODES = ("OPERATOR_PURGE",)
PROFILE_CONTRACTS = ("profile-2",)
MAX_PROFILE_BYTES = 1_048_576
MAX_MAPPING_BYTES = 262_144


def rejection_codes() -> tuple[str, ...]:
    return (*_m0024().REJECTION_CODES, *NEW_REJECTION_CODES)


def event_types() -> tuple[str, ...]:
    return (*_m0024().EVENT_TYPES, *NEW_EVENT_TYPES)


def reason_codes() -> tuple[str, ...]:
    return (*_m0024().REASON_CODES, *NEW_REJECTION_CODES, *NEW_REASON_CODES)


def _in(values: Sequence[str]) -> str:
    return ", ".join(f"'{v}'" for v in values)


_PROFILES = f"""
CREATE TABLE dataset_profiles (
    version_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    dataset_id uuid NOT NULL,
    contract_version text NOT NULL CHECK (contract_version IN ({_in(PROFILE_CONTRACTS)})),
    content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{{64}}$'),
    row_count integer NOT NULL CHECK (row_count BETWEEN 1 AND 1000000),
    column_count integer NOT NULL CHECK (column_count BETWEEN 1 AND 200),
    profile jsonb CHECK (profile IS NULL OR (
        jsonb_typeof(profile) = 'object'
        AND octet_length(profile::text) <= {MAX_PROFILE_BYTES})),
    created_at timestamptz NOT NULL DEFAULT now(),
    scrubbed_at timestamptz,
    CONSTRAINT fk_dataset_profiles_version FOREIGN KEY (version_id, dataset_id, tenant_id)
        REFERENCES dataset_versions (id, dataset_id, tenant_id),
    CONSTRAINT ck_dataset_profiles_scrubbed CHECK ((profile IS NULL) = (scrubbed_at IS NOT NULL))
)
"""

_SEMANTICS = f"""
CREATE TABLE dataset_semantic_revisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    dataset_id uuid NOT NULL,
    version_id uuid NOT NULL,
    revision_number integer NOT NULL CHECK (revision_number >= 1),
    mapping jsonb CHECK (mapping IS NULL OR (
        jsonb_typeof(mapping) = 'object'
        AND octet_length(mapping::text) <= {MAX_MAPPING_BYTES})),
    confirmed_by uuid NOT NULL,
    confirmed_at timestamptz NOT NULL DEFAULT now(),
    scrubbed_at timestamptz,
    CONSTRAINT fk_dataset_semantic_revisions_version FOREIGN KEY (version_id, dataset_id, tenant_id)
        REFERENCES dataset_versions (id, dataset_id, tenant_id),
    CONSTRAINT uq_dataset_semantic_revisions_number UNIQUE (version_id, revision_number),
    CONSTRAINT ck_dataset_semantic_revisions_scrubbed
        CHECK ((mapping IS NULL) = (scrubbed_at IS NOT NULL))
)
"""

# Profiles: inserted only for a PROFILING version with the version's own digest;
# afterwards only the tombstone's scrub (profile -> NULL, once) is possible.
_FN_PROFILE_GUARD = """
CREATE FUNCTION dataset_profile_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    DECLARE
        v_status text;
        v_digest text;
    BEGIN
        IF TG_OP = 'INSERT' THEN
            SELECT v.status, v.content_sha256 INTO v_status, v_digest
                FROM public.dataset_versions v
                WHERE v.id = NEW.version_id AND v.dataset_id = NEW.dataset_id
                  AND v.tenant_id = NEW.tenant_id;
            IF v_status IS DISTINCT FROM 'PROFILING' THEN
                RAISE EXCEPTION 'a profile is recorded only while the version is PROFILING'
                    USING ERRCODE = '23514';
            END IF;
            IF v_digest IS NULL OR v_digest <> NEW.content_sha256 THEN
                RAISE EXCEPTION 'the profile digest must equal the version digest'
                    USING ERRCODE = '23514';
            END IF;
            IF NEW.profile IS NULL OR NEW.scrubbed_at IS NOT NULL THEN
                RAISE EXCEPTION 'a profile is recorded unscrubbed' USING ERRCODE = '23514';
            END IF;
            NEW.created_at := now();
            RETURN NEW;
        END IF;
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'dataset profiles are never deleted' USING ERRCODE = '23514';
        END IF;
        IF OLD.profile IS NULL OR NEW.profile IS NOT NULL
           OR NEW.version_id <> OLD.version_id OR NEW.tenant_id <> OLD.tenant_id
           OR NEW.dataset_id <> OLD.dataset_id OR NEW.contract_version <> OLD.contract_version
           OR NEW.content_sha256 <> OLD.content_sha256 OR NEW.row_count <> OLD.row_count
           OR NEW.column_count <> OLD.column_count OR NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'a dataset profile is immutable (only the tombstone scrubs it)'
                USING ERRCODE = '23514';
        END IF;
        NEW.scrubbed_at := now();
        RETURN NEW;
    END $$
"""

# Semantic revisions: append-only, numbered 1, 2, ... per version, only while
# the version is PROFILED; afterwards only the tombstone's scrub is possible.
_FN_SEMANTICS_GUARD = """
CREATE FUNCTION dataset_semantic_revision_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    DECLARE
        v_status text;
        last_n integer;
    BEGIN
        IF TG_OP = 'INSERT' THEN
            SELECT v.status INTO v_status FROM public.dataset_versions v
                WHERE v.id = NEW.version_id AND v.dataset_id = NEW.dataset_id
                  AND v.tenant_id = NEW.tenant_id;
            IF v_status IS DISTINCT FROM 'PROFILED' THEN
                RAISE EXCEPTION 'semantics are confirmed only for a PROFILED version'
                    USING ERRCODE = '23514';
            END IF;
            SELECT coalesce(max(r.revision_number), 0) INTO last_n
                FROM public.dataset_semantic_revisions r WHERE r.version_id = NEW.version_id;
            IF NEW.revision_number <> last_n + 1 THEN
                RAISE EXCEPTION 'semantic revisions are numbered consecutively'
                    USING ERRCODE = '23514';
            END IF;
            IF NEW.mapping IS NULL OR NEW.scrubbed_at IS NOT NULL THEN
                RAISE EXCEPTION 'a semantic revision is recorded unscrubbed'
                    USING ERRCODE = '23514';
            END IF;
            NEW.confirmed_at := now();
            RETURN NEW;
        END IF;
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'semantic revisions are never deleted' USING ERRCODE = '23514';
        END IF;
        IF OLD.mapping IS NULL OR NEW.mapping IS NOT NULL
           OR NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
           OR NEW.dataset_id <> OLD.dataset_id OR NEW.version_id <> OLD.version_id
           OR NEW.revision_number <> OLD.revision_number
           OR NEW.confirmed_by <> OLD.confirmed_by OR NEW.confirmed_at <> OLD.confirmed_at THEN
            RAISE EXCEPTION 'a semantic revision is immutable (only the tombstone scrubs it)'
                USING ERRCODE = '23514';
        END IF;
        NEW.scrubbed_at := now();
        RETURN NEW;
    END $$
"""


def _fn_versions_guard() -> str:
    """The 0024 guard with the ingestion rules added (see the module docstring)."""
    original = _m0024()._fn_versions_guard()
    marker = "        NEW.profiling_started_at := CASE"
    assert original.count(marker) == 1
    head = "        IF NEW.storage_object_key IS DISTINCT FROM OLD.storage_object_key AND NOT ("
    key_rule_0024 = (
        head
        + """
            (OLD.storage_object_key IS NULL AND OLD.status = 'QUARANTINED'
             AND NEW.status = 'QUARANTINED')
            OR NEW.status = 'DELETED') THEN"""
    )
    assert original.count(key_rule_0024) == 1
    key_rule = (
        head
        + """
            (OLD.storage_object_key IS NULL AND OLD.status = 'QUARANTINED'
             AND NEW.status = 'QUARANTINED')
            OR NEW.status = 'DELETED'
            OR (OLD.status = 'PROFILING' AND NEW.status = 'PROFILED'
                AND OLD.storage_object_key LIKE 'quarantine/%'
                AND NEW.storage_object_key
                    = 'datasets/' || substr(OLD.storage_object_key, 12)))
        THEN"""
    )
    added = """        IF NEW.status <> 'PROFILING' THEN
            NEW.processing_lease_token := NULL;
            NEW.processing_lease_expires_at := NULL;
        END IF;
        IF NEW.processing_lease_expires_at IS DISTINCT FROM OLD.processing_lease_expires_at
           AND NEW.processing_lease_expires_at > now() + interval '15 minutes' THEN
            RAISE EXCEPTION 'a processing lease lasts at most 15 minutes'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'PROFILING' AND NEW.status IN ('PROFILED', 'REJECTED') AND (
            OLD.processing_lease_token IS NULL OR OLD.processing_lease_expires_at < now()) THEN
            RAISE EXCEPTION 'leaving PROFILING requires a live processing lease'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.upload_idempotency_key IS DISTINCT FROM OLD.upload_idempotency_key
        THEN
            RAISE EXCEPTION 'the upload idempotency key is immutable'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.status = 'PROFILED' AND OLD.status <> 'PROFILED' AND NOT EXISTS (
            SELECT 1 FROM public.dataset_profiles p
            WHERE p.version_id = NEW.id AND p.tenant_id = NEW.tenant_id
              AND p.content_sha256 = NEW.content_sha256 AND p.profile IS NOT NULL) THEN
            RAISE EXCEPTION 'a version is PROFILED only with its recorded profile'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.status = 'ACTIVE' AND OLD.status <> 'ACTIVE' AND NOT EXISTS (
            SELECT 1 FROM public.dataset_semantic_revisions r
            WHERE r.version_id = NEW.id AND r.tenant_id = NEW.tenant_id
              AND r.mapping IS NOT NULL) THEN
            RAISE EXCEPTION 'a version is ACTIVE only with confirmed semantics'
                USING ERRCODE = '23514';
        END IF;
"""
    replaced = original.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
    replaced = replaced.replace(key_rule_0024, key_rule)
    return replaced.replace(marker, added + marker)


# --- lifecycle-event authenticity (review finding F) ------------------------------
# An event is accepted only if it describes the transition that THIS
# transaction just made: the row is in to_status, entered it at now() (the
# transaction timestamp), came from from_status, and has no other event for that
# transition. Runtime-role transitions must also leave their event (deferred
# check at commit). Everything runs as the invoker: no SECURITY DEFINER.
_ENTERED_AT = (
    "CASE NEW.to_status WHEN 'QUARANTINED' THEN v.created_at "
    "WHEN 'PROFILING' THEN v.profiling_started_at WHEN 'PROFILED' THEN v.profiled_at "
    "WHEN 'ACTIVE' THEN v.activated_at WHEN 'SUPERSEDED' THEN v.superseded_at "
    "WHEN 'REJECTED' THEN v.rejected_at WHEN 'DELETING' THEN v.deletion_requested_at "
    "WHEN 'DELETED' THEN v.deleted_at END"
)
_EVENT_FOR_STATUS = (
    "CASE NEW.to_status WHEN 'QUARANTINED' THEN 'VERSION_CREATED' "
    "WHEN 'PROFILING' THEN 'VERSION_PROFILING_STARTED' WHEN 'PROFILED' THEN 'VERSION_PROFILED' "
    "WHEN 'ACTIVE' THEN 'VERSION_ACTIVATED' WHEN 'SUPERSEDED' THEN 'VERSION_SUPERSEDED' "
    "WHEN 'REJECTED' THEN 'VERSION_REJECTED' WHEN 'DELETING' THEN 'VERSION_DELETION_REQUESTED' "
    "WHEN 'DELETED' THEN 'VERSION_TOMBSTONED' END"
)

_FN_PREVIOUS_STATUS = """
CREATE FUNCTION dataset_version_previous_status() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    BEGIN
        IF TG_OP = 'INSERT' THEN
            NEW.previous_status := NULL;
        ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
            NEW.previous_status := OLD.status;
        ELSE
            NEW.previous_status := OLD.previous_status;
        END IF;
        RETURN NEW;
    END $$
"""


def _fn_event_guard() -> str:
    return f"""
CREATE FUNCTION dataset_event_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    DECLARE
        v record;
        d record;
        entered timestamptz;
        expected_event text;
        dup integer;
    BEGIN
        NEW.created_at := now();
        IF NEW.version_id IS NULL THEN
            SELECT ds.status, ds.created_at, ds.deletion_requested_at, ds.deleted_at INTO d
                FROM public.datasets ds
                WHERE ds.id = NEW.dataset_id AND ds.tenant_id = NEW.tenant_id;
            IF NOT FOUND OR NOT (
                (NEW.event_type = 'DATASET_CREATED' AND NEW.from_status IS NULL
                 AND NEW.to_status = 'ACTIVE' AND d.created_at = now())
                OR (NEW.event_type = 'DATASET_DELETION_REQUESTED'
                    AND NEW.from_status = 'ACTIVE' AND NEW.to_status = 'DELETING'
                    AND d.status = 'DELETING' AND d.deletion_requested_at = now())
                OR (NEW.event_type = 'DATASET_TOMBSTONED' AND NEW.from_status = 'DELETING'
                    AND NEW.to_status = 'DELETED' AND d.status = 'DELETED'
                    AND d.deleted_at = now())) THEN
                RAISE EXCEPTION 'a dataset event must record a transition made in this transaction'
                    USING ERRCODE = '23514';
            END IF;
            SELECT count(*) INTO dup FROM public.dataset_events e
                WHERE e.dataset_id = NEW.dataset_id AND e.version_id IS NULL
                  AND e.event_type = NEW.event_type AND e.created_at = now();
        ELSE
            SELECT vv.status, vv.previous_status, vv.created_at, vv.profiling_started_at,
                   vv.profiled_at, vv.activated_at, vv.superseded_at, vv.rejected_at,
                   vv.deletion_requested_at, vv.deleted_at INTO v
                FROM public.dataset_versions vv
                WHERE vv.id = NEW.version_id AND vv.dataset_id = NEW.dataset_id
                  AND vv.tenant_id = NEW.tenant_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'a version event must name a visible version'
                    USING ERRCODE = '23514';
            END IF;
            IF NEW.event_type = 'VERSION_OBJECT_PURGED' THEN
                -- Evidence, not a transition: only about a version being deleted.
                IF v.status <> 'DELETING' THEN
                    RAISE EXCEPTION 'purge evidence is recorded only for a DELETING version'
                        USING ERRCODE = '23514';
                END IF;
                RETURN NEW;
            END IF;
            entered := {_ENTERED_AT};
            expected_event := {_EVENT_FOR_STATUS};
            IF NEW.event_type IS DISTINCT FROM expected_event
               OR v.status IS DISTINCT FROM NEW.to_status
               OR entered IS DISTINCT FROM now()
               OR NEW.from_status IS DISTINCT FROM v.previous_status THEN
                RAISE EXCEPTION 'a version event must record a transition made in this transaction'
                    USING ERRCODE = '23514';
            END IF;
            SELECT count(*) INTO dup FROM public.dataset_events e
                WHERE e.version_id = NEW.version_id AND e.to_status = NEW.to_status
                  AND e.event_type = NEW.event_type AND e.created_at = now();
        END IF;
        IF dup > 0 THEN
            RAISE EXCEPTION 'a transition has exactly one event' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END $$
"""


# Deferred to COMMIT: a transition made by a RUNTIME role must have left its
# event. (Operator transitions, made with the owner credential, write their
# own events through nlw.ops.datasets; the owner is trusted for this check.)
_FN_EVENT_REQUIRED = """
CREATE FUNCTION dataset_event_required() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog AS $$
    DECLARE
        found integer;
    BEGIN
        IF session_user::text NOT IN ('nlw_app', 'nlw_worker', 'nlw_scheduler') THEN
            RETURN NULL;
        END IF;
        IF TG_TABLE_NAME = 'dataset_versions' THEN
            IF TG_OP = 'UPDATE' AND NEW.status IS NOT DISTINCT FROM OLD.status THEN
                RETURN NULL;
            END IF;
            SELECT count(*) INTO found FROM public.dataset_events e
                WHERE e.version_id = NEW.id AND e.to_status = NEW.status
                  AND e.from_status IS NOT DISTINCT FROM
                      (CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.status END)
                  AND e.created_at = now();
        ELSE
            IF TG_OP = 'UPDATE' AND NEW.status IS NOT DISTINCT FROM OLD.status THEN
                RETURN NULL;
            END IF;
            SELECT count(*) INTO found FROM public.dataset_events e
                WHERE e.dataset_id = NEW.id AND e.version_id IS NULL
                  AND e.to_status = NEW.status AND e.created_at = now();
        END IF;
        IF found <> 1 THEN
            RAISE EXCEPTION 'every dataset lifecycle transition records exactly one event'
                USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    END $$
"""


_EVENTS_INSERT_0024 = "(" + _ADMIN + " AND actor_kind <> 'operator' AND to_status <> 'DELETED')"
_EVENTS_INSERT = (
    "("
    + _ADMIN
    + " AND actor_kind <> 'operator' AND to_status <> 'DELETED'"
    + " AND event_type <> 'VERSION_OBJECT_PURGED'"
    # The recorded actor IS the signed user (no attributing acts to others).
    + " AND actor_user_id = public.ctx_user_id())"
)

_POLICIES = (
    ("dataset_profiles_app_select", "dataset_profiles", "SELECT", _ADMIN, None),
    ("dataset_profiles_app_insert", "dataset_profiles", "INSERT", None, _ADMIN),
    ("dataset_semantic_revisions_app_select", "dataset_semantic_revisions", "SELECT", _ADMIN, None),
    (
        "dataset_semantic_revisions_app_insert",
        "dataset_semantic_revisions",
        "INSERT",
        None,
        f"({_ADMIN} AND confirmed_by = public.ctx_user_id())",
    ),
)
_TABLES = ("dataset_profiles", "dataset_semantic_revisions")


def _replace_check(table: str, name: str, column: str, values: Sequence[str]) -> None:
    op.execute(f"ALTER TABLE {table} DROP CONSTRAINT {name}")
    op.execute(
        f"ALTER TABLE {table} ADD CONSTRAINT {name} "
        f"CHECK ({column} IS NULL OR {column} IN ({_in(values)}))"
    )


def _events_insert_policy(check: str) -> None:
    op.execute("DROP POLICY dataset_events_app_insert ON dataset_events")
    op.execute(
        "CREATE POLICY dataset_events_app_insert ON dataset_events FOR INSERT TO nlw_app "
        f"WITH CHECK {check}"
    )


def upgrade() -> None:
    m = _m0024()
    # --- upload idempotency --------------------------------------------------
    op.execute(
        "ALTER TABLE dataset_versions ADD COLUMN upload_idempotency_key text "
        "CONSTRAINT ck_dataset_versions_idempotency_key CHECK ("
        "upload_idempotency_key IS NULL OR upload_idempotency_key ~ '^[A-Za-z0-9_-]{16,128}$')"
    )
    op.execute(
        "CREATE UNIQUE INDEX uq_dataset_versions_idempotency ON dataset_versions "
        "(dataset_id, upload_idempotency_key) WHERE upload_idempotency_key IS NOT NULL"
    )

    # --- processing lease (database time; ADR-030) ------------------------------
    # One claimant at a time profiles a version. Acquire, stale reclaim and
    # renewal are single compare-and-set UPDATEs evaluated with PostgreSQL's
    # clock (never an application host's); publication and the processor's
    # rejection must present the current token. The guard clears both columns
    # whenever a version leaves PROFILING.
    op.execute(
        "ALTER TABLE dataset_versions ADD COLUMN processing_lease_token uuid, "
        "ADD COLUMN processing_lease_expires_at timestamptz"
    )
    op.execute(
        "ALTER TABLE dataset_versions ADD CONSTRAINT ck_dataset_versions_lease_pair "
        "CHECK ((processing_lease_token IS NULL) = (processing_lease_expires_at IS NULL))"
    )
    op.execute(
        "ALTER TABLE dataset_versions ADD CONSTRAINT ck_dataset_versions_lease_only_profiling "
        "CHECK (status = 'PROFILING' OR processing_lease_token IS NULL)"
    )

    # --- storage keys are bound to the immutable version id -------------------
    # 0024 proves the key names this tenant and dataset; this proves the object
    # component IS this version's id, so no session (runtime or owner) can point
    # a version at another version's object. With the guard's rule that a key
    # may only move quarantine/ -> datasets/ with the SAME object component,
    # both the quarantine and the published key are derived from the id.
    op.execute(
        "ALTER TABLE dataset_versions ADD CONSTRAINT ck_dataset_versions_key_names_version "
        "CHECK (storage_object_key IS NULL OR split_part(storage_object_key, '/', 4) = id::text)"
    )

    # --- closed vocabularies widen (never narrow) ------------------------------
    _replace_check(
        "dataset_versions", "dataset_versions_rejection_code_check", "rejection_code",
        rejection_codes(),
    )  # fmt: skip
    op.execute("ALTER TABLE dataset_events DROP CONSTRAINT dataset_events_event_type_check")
    op.execute(
        "ALTER TABLE dataset_events ADD CONSTRAINT dataset_events_event_type_check "
        f"CHECK (event_type IN ({_in(event_types())}))"
    )
    _replace_check(
        "dataset_events", "dataset_events_reason_code_check", "reason_code", reason_codes()
    )
    op.execute(
        "ALTER TABLE dataset_events ADD CONSTRAINT ck_dataset_events_purge_shape CHECK ("
        "event_type <> 'VERSION_OBJECT_PURGED' OR (actor_kind = 'operator' "
        "AND from_status = 'DELETING' AND to_status = 'DELETING' "
        "AND reason_code = 'OPERATOR_PURGE'))"
    )
    # Purge evidence carries its external deletion receipt (provider-neutral):
    # the sink that holds it, its opaque id, and the deletion-set digest it
    # attests. Exactly purge events carry one; the tombstone verifies it.
    op.execute(
        "ALTER TABLE dataset_events ADD COLUMN receipt_sink text "
        "CHECK (receipt_sink IS NULL OR receipt_sink ~ '^[a-z0-9][a-z0-9._-]{0,63}$'), "
        "ADD COLUMN receipt_id text "
        "CHECK (receipt_id IS NULL OR receipt_id ~ '^[A-Za-z0-9._:-]{1,128}$'), "
        "ADD COLUMN receipt_digest text "
        "CHECK (receipt_digest IS NULL OR receipt_digest ~ '^[0-9a-f]{64}$')"
    )
    op.execute(
        "ALTER TABLE dataset_events ADD CONSTRAINT ck_dataset_events_receipt CHECK ("
        "(event_type = 'VERSION_OBJECT_PURGED') = (receipt_id IS NOT NULL) "
        "AND (receipt_id IS NULL) = (receipt_sink IS NULL) "
        "AND (receipt_id IS NULL) = (receipt_digest IS NULL))"
    )
    _events_insert_policy(_EVENTS_INSERT)

    # --- profiles and semantic revisions ---------------------------------------
    op.execute(_PROFILES)
    op.execute(_SEMANTICS)
    op.execute(
        "CREATE INDEX ix_dataset_profiles_tenant_dataset ON dataset_profiles "
        "(tenant_id, dataset_id)"
    )
    op.execute(
        "CREATE INDEX ix_dataset_semantic_revisions_tenant_version ON dataset_semantic_revisions "
        "(tenant_id, version_id, revision_number)"
    )
    op.execute(_FN_PROFILE_GUARD)
    op.execute(_FN_SEMANTICS_GUARD)
    for fn in ("dataset_profile_guard()", "dataset_semantic_revision_guard()"):
        op.execute(f"REVOKE ALL ON FUNCTION {fn} FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER dataset_profiles_guard BEFORE INSERT OR UPDATE OR DELETE "
        "ON dataset_profiles FOR EACH ROW EXECUTE FUNCTION dataset_profile_guard()"
    )
    op.execute(
        "CREATE TRIGGER dataset_semantic_revisions_guard BEFORE INSERT OR UPDATE OR DELETE "
        "ON dataset_semantic_revisions FOR EACH ROW "
        "EXECUTE FUNCTION dataset_semantic_revision_guard()"
    )
    for table in _TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM PUBLIC")
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"GRANT SELECT, INSERT ON {table} TO nlw_app")
    for name, table, command, using, check in _POLICIES:
        clause = f"CREATE POLICY {name} ON {table} FOR {command} TO nlw_app"
        if using is not None:
            clause += f" USING {using}"
        if check is not None:
            clause += f" WITH CHECK {check}"
        op.execute(clause)

    # --- the version guard learns the ingestion rules (last: it reads the tables)
    op.execute(_fn_versions_guard())

    # --- lifecycle-event authenticity --------------------------------------------
    op.execute(
        "ALTER TABLE dataset_versions ADD COLUMN previous_status text "
        f"CHECK (previous_status IS NULL OR previous_status IN ({_in(_m0024().VERSION_STATES)}))"
    )
    op.execute(_FN_PREVIOUS_STATUS)
    op.execute(_fn_event_guard())
    op.execute(_FN_EVENT_REQUIRED)
    for fn in (
        "dataset_version_previous_status()",
        "dataset_event_guard()",
        "dataset_event_required()",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {fn} FROM PUBLIC")
    # Fires after dataset_versions_guard (alphabetical), so it sees the final status.
    op.execute(
        "CREATE TRIGGER dataset_versions_previous_status BEFORE INSERT OR UPDATE "
        "ON dataset_versions FOR EACH ROW EXECUTE FUNCTION dataset_version_previous_status()"
    )
    op.execute(
        "CREATE TRIGGER dataset_events_guard BEFORE INSERT ON dataset_events "
        "FOR EACH ROW EXECUTE FUNCTION dataset_event_guard()"
    )
    for table in ("datasets", "dataset_versions"):
        op.execute(
            f"CREATE CONSTRAINT TRIGGER {table}_event_required AFTER INSERT OR UPDATE "
            f"ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
            "EXECUTE FUNCTION dataset_event_required()"
        )
    assert m.REJECTION_CODES  # 0024 vocabularies stay a strict prefix


def downgrade() -> None:
    # Disposable environments and tests only (see the module docstring).
    m = _m0024()
    for table in ("datasets", "dataset_versions"):
        op.execute(f"DROP TRIGGER IF EXISTS {table}_event_required ON {table}")
    op.execute("DROP TRIGGER IF EXISTS dataset_events_guard ON dataset_events")
    op.execute("DROP TRIGGER IF EXISTS dataset_versions_previous_status ON dataset_versions")
    for fn in (
        "dataset_event_required()",
        "dataset_event_guard()",
        "dataset_version_previous_status()",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {fn}")
    op.execute("ALTER TABLE dataset_versions DROP COLUMN IF EXISTS previous_status")
    op.execute(m._fn_versions_guard().replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1))
    op.execute("DROP TABLE IF EXISTS dataset_semantic_revisions")
    op.execute("DROP TABLE IF EXISTS dataset_profiles")
    op.execute("DROP FUNCTION IF EXISTS dataset_semantic_revision_guard()")
    op.execute("DROP FUNCTION IF EXISTS dataset_profile_guard()")
    _events_insert_policy(_EVENTS_INSERT_0024)
    op.execute(
        "ALTER TABLE dataset_events DROP CONSTRAINT IF EXISTS ck_dataset_events_receipt, "
        "DROP COLUMN IF EXISTS receipt_sink, DROP COLUMN IF EXISTS receipt_id, "
        "DROP COLUMN IF EXISTS receipt_digest"
    )
    op.execute("ALTER TABLE dataset_events DROP CONSTRAINT ck_dataset_events_purge_shape")
    _replace_check(
        "dataset_events", "dataset_events_reason_code_check", "reason_code", m.REASON_CODES
    )
    op.execute("ALTER TABLE dataset_events DROP CONSTRAINT dataset_events_event_type_check")
    op.execute(
        "ALTER TABLE dataset_events ADD CONSTRAINT dataset_events_event_type_check "
        f"CHECK (event_type IN ({_in(m.EVENT_TYPES)}))"
    )
    _replace_check(
        "dataset_versions", "dataset_versions_rejection_code_check", "rejection_code",
        m.REJECTION_CODES,
    )  # fmt: skip
    op.execute(
        "ALTER TABLE dataset_versions "
        "DROP CONSTRAINT IF EXISTS ck_dataset_versions_key_names_version"
    )
    op.execute(
        "ALTER TABLE dataset_versions DROP CONSTRAINT IF EXISTS ck_dataset_versions_lease_pair, "
        "DROP CONSTRAINT IF EXISTS ck_dataset_versions_lease_only_profiling, "
        "DROP COLUMN IF EXISTS processing_lease_token, "
        "DROP COLUMN IF EXISTS processing_lease_expires_at"
    )
    op.execute("DROP INDEX IF EXISTS uq_dataset_versions_idempotency")
    op.execute("ALTER TABLE dataset_versions DROP COLUMN IF EXISTS upload_idempotency_key")
