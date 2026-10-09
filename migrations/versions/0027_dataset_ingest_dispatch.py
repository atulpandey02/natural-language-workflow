"""Unattended dataset dispatch: the nlw_ingest_dispatch role and its one function (O-7).

A committed processing request whose enqueue was lost (ADR-031) stays pending
until something re-sends its envelope. The dispatcher (``nlw.ingest_dispatch``)
does that unattended, as ``nlw_ingest_dispatch``, which can do exactly one
thing in the dataset tables: call ``dataset_dispatch_pending()``.

- ``dataset_dispatch_pending(limit, min_age_s, fresh_age_s)``: a read-only,
  hardened SECURITY DEFINER function owned by ``nlw_rls_bypass`` (the existing
  NOLOGIN read-only BYPASSRLS function owner, migration 0004 pattern), which
  gets column-level SELECT on exactly the columns it reads. It returns the
  latest request of each waiting version (QUARANTINED with content, or
  PROFILING with an expired/missing lease) that is older than ``min_age_s`` and
  still fresh for the consumer: ids, digests and the request time only. One
  bounded, oldest-first batch (``limit`` clamped to 1..1000), plus aggregate
  stats over ALL waiting versions (count, oldest age, too-old count) for
  monitoring. Never names, filenames, keys, profiles, users or content.
- ``nlw_ingest_dispatch``: CONNECT, USAGE, EXECUTE on that function, and the DR
  recovery-lock columns (like every runtime). No table privilege on any
  dataset table, no signed context, no key, no write anywhere.

The role is provisioned outside Alembic (initdb / ``nlw.ops.roles ensure``),
like ``nlw_ingest``; on deployed targets it stays NOLOGIN (dormant) until O-6.
No RLS policy is added (the signed policy count is unchanged).

DOWNGRADE: disposable databases only.

Revision ID: 0027_dataset_ingest_dispatch
Revises: 0026_dataset_ingest_role
Create Date: 2026-10-08
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0027_dataset_ingest_dispatch"
down_revision: str | Sequence[str] | None = "0026_dataset_ingest_role"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FUNCTION_SIG = "dataset_dispatch_pending(integer, integer, integer)"
REQUEST_COLUMNS = (
    "id",
    "tenant_id",
    "dataset_id",
    "version_id",
    "content_sha256",
    "envelope_sha256",
    "requested_at",
)
VERSION_COLUMNS = ("id", "tenant_id", "status", "content_sha256", "processing_lease_expires_at")
LOCK_COLUMNS = ("id", "restored_at", "validation_completed_at", "runtime_enabled_at")

_FUNCTION = """
CREATE FUNCTION dataset_dispatch_pending(
    p_limit integer, p_min_age_s integer, p_fresh_age_s integer
) RETURNS TABLE (
    request_id uuid,
    tenant_id uuid,
    dataset_id uuid,
    version_id uuid,
    content_sha256 text,
    envelope_sha256 text,
    requested_at_us bigint,
    pending_total bigint,
    oldest_age_s double precision,
    stale_total bigint
)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
    WITH latest AS (
        SELECT DISTINCT ON (r.version_id)
               r.id, r.tenant_id, r.dataset_id, r.version_id,
               r.content_sha256, r.envelope_sha256, r.requested_at
          FROM public.dataset_processing_requests r
          JOIN public.dataset_versions v
            ON v.id = r.version_id AND v.tenant_id = r.tenant_id
         WHERE r.content_sha256 = v.content_sha256
           AND (v.status = 'QUARANTINED'
                OR (v.status = 'PROFILING'
                    AND (v.processing_lease_expires_at IS NULL
                         OR v.processing_lease_expires_at < now())))
         ORDER BY r.version_id, r.requested_at DESC
    ), stats AS (
        SELECT count(*) AS pending_total,
               coalesce(extract(epoch FROM now() - min(requested_at)), 0)::double precision
                   AS oldest_age_s,
               count(*) FILTER (
                   WHERE requested_at <= now() - make_interval(secs => p_fresh_age_s)
               ) AS stale_total
          FROM latest
    )
    SELECT b.id, b.tenant_id, b.dataset_id, b.version_id, b.content_sha256,
           b.envelope_sha256, (extract(epoch FROM b.requested_at) * 1000000)::bigint,
           s.pending_total, s.oldest_age_s, s.stale_total
      FROM stats s
      LEFT JOIN LATERAL (
          SELECT * FROM latest
           WHERE requested_at <= now() - make_interval(secs => greatest(p_min_age_s, 0))
             AND requested_at > now() - make_interval(secs => p_fresh_age_s)
           ORDER BY requested_at, version_id
           LIMIT least(greatest(p_limit, 1), 1000)
      ) b ON true
     ORDER BY b.requested_at, b.version_id
$$
"""


def upgrade() -> None:
    op.execute(
        f"GRANT SELECT ({', '.join(REQUEST_COLUMNS)}) "
        "ON dataset_processing_requests TO nlw_rls_bypass"
    )
    op.execute(f"GRANT SELECT ({', '.join(VERSION_COLUMNS)}) ON dataset_versions TO nlw_rls_bypass")
    op.execute(_FUNCTION)
    op.execute(f"ALTER FUNCTION {FUNCTION_SIG} OWNER TO nlw_rls_bypass")
    op.execute(f"REVOKE ALL ON FUNCTION {FUNCTION_SIG} FROM PUBLIC")

    op.execute(
        "DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO nlw_ingest_dispatch', "
        "current_database()); END $$"
    )
    op.execute("GRANT USAGE ON SCHEMA public TO nlw_ingest_dispatch")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FUNCTION_SIG} TO nlw_ingest_dispatch")
    op.execute(
        f"GRANT SELECT ({', '.join(LOCK_COLUMNS)}) ON dr_restore_events TO nlw_ingest_dispatch"
    )


def downgrade() -> None:
    op.execute(
        f"REVOKE SELECT ({', '.join(LOCK_COLUMNS)}) ON dr_restore_events FROM nlw_ingest_dispatch"
    )
    op.execute(f"DROP FUNCTION {FUNCTION_SIG}")
    op.execute("REVOKE USAGE ON SCHEMA public FROM nlw_ingest_dispatch")
    op.execute(
        "DO $$ BEGIN EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM nlw_ingest_dispatch', "
        "current_database()); END $$"
    )
    op.execute(
        f"REVOKE SELECT ({', '.join(VERSION_COLUMNS)}) ON dataset_versions FROM nlw_rls_bypass"
    )
    op.execute(
        f"REVOKE SELECT ({', '.join(REQUEST_COLUMNS)}) "
        "ON dataset_processing_requests FROM nlw_rls_bypass"
    )
