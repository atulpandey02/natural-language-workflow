"""schedule_authorization

Fail-closed schedule ownership authorization (M12B final correction, Part 4). A
schedule may create occurrences only while its CREATOR remains an active member of
the workspace with a sufficient role (owner/admin — the role schedule creation
requires). If the creator is removed or demoted, occurrence creation is BLOCKED
(no run, no enqueue) with a stable sanitized reason, until an authorized admin
explicitly reassigns/re-enables it.

Adds ``schedules.blocked_reason`` / ``blocked_at`` and a SECURITY DEFINER checker
``schedule_creator_block_reason(uuid)`` (owned by the BYPASSRLS helper role, so the
least-privileged ``nlw_scheduler`` — which cannot read ``memberships`` — can call
it without broad grants). The due-scan excludes blocked schedules and never lets
the model decide authorization. Fully reversible.

Revision ID: 0020_schedule_authorization
Revises: 0019_connector_bindings
Create Date: 2026-09-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020_schedule_authorization"
down_revision: str | Sequence[str] | None = "0019_connector_bindings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("schedules", sa.Column("blocked_reason", sa.Text(), nullable=True))
    op.add_column("schedules", sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=True))
    # The scheduler may set/clear the blocked state (in addition to its existing
    # next_run_at/last_scheduled_for/updated_at grant from 0009).
    op.execute("GRANT UPDATE (blocked_reason, blocked_at) ON schedules TO nlw_scheduler")

    # SECURITY DEFINER authorization checker. Owned by the BYPASSRLS helper role so
    # nlw_scheduler needs no direct read on memberships/schedules. Returns a stable
    # low-cardinality reason, or NULL when the creator is still authorized.
    op.execute("GRANT SELECT (role) ON memberships TO nlw_rls_bypass")
    op.execute("GRANT SELECT (id, created_by, tenant_id) ON schedules TO nlw_rls_bypass")
    op.execute(
        """
        CREATE FUNCTION schedule_creator_block_reason(p_schedule_id uuid) RETURNS text
            LANGUAGE sql
            STABLE
            SECURITY DEFINER
            SET search_path = pg_catalog
            AS $$
                SELECT CASE
                    WHEN m.role IS NULL THEN 'CREATOR_NOT_A_MEMBER'
                    WHEN m.role NOT IN ('owner', 'admin') THEN 'CREATOR_ROLE_INSUFFICIENT'
                    ELSE NULL
                END
                FROM public.schedules s
                LEFT JOIN public.memberships m
                  ON m.user_id = s.created_by AND m.workspace_id = s.tenant_id
                WHERE s.id = p_schedule_id
            $$
        """
    )
    op.execute("ALTER FUNCTION schedule_creator_block_reason(uuid) OWNER TO nlw_rls_bypass")
    op.execute("REVOKE ALL ON FUNCTION schedule_creator_block_reason(uuid) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION schedule_creator_block_reason(uuid) TO nlw_scheduler")
    op.execute("GRANT EXECUTE ON FUNCTION schedule_creator_block_reason(uuid) TO nlw_app")


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS schedule_creator_block_reason(uuid)")
    op.execute("REVOKE SELECT (id, created_by, tenant_id) ON schedules FROM nlw_rls_bypass")
    op.execute("REVOKE SELECT (role) ON memberships FROM nlw_rls_bypass")
    op.execute("REVOKE UPDATE (blocked_reason, blocked_at) ON schedules FROM nlw_scheduler")
    op.drop_column("schedules", "blocked_at")
    op.drop_column("schedules", "blocked_reason")
