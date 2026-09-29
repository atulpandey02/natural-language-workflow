"""Redacted, append-only plan outcome events (Phase 2 plan section 12, B02).

One row per planning attempt, written by the API in the SAME transaction as the
``plan_proposals`` row (or, for a provider failure that writes no proposal, in a
short transaction of its own). The table is the measurement baseline for how
pilot requests fail today, so Phase 2 planning can be compared against it.

Privacy by schema: there is no free-text column. Outcomes, categories, finding
codes and request-shape tags are closed vocabularies enforced by CHECK
constraints; the request is represented only by a length bucket. Feasibility
messages (which can echo field or tool names) are never copied.

Tenancy: RLS on the signed context (same predicates as migration 0016). nlw_app
may INSERT for the workspace in its request context and owners/admins may read
their own workspace's rows; no runtime role may UPDATE or DELETE (append-only).
Cross-tenant reporting is an operator task with the owner credential
(``python -m nlw.ops.outcomes``), never a tenant API.

Revision ID: 0023_plan_outcome_events
Revises: 0022_workspace_creation_grants
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0023_plan_outcome_events"
down_revision: str | Sequence[str] | None = "0022_workspace_creation_grants"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_T = "public.ctx_tenant_id()"
_MEMBER = f"(tenant_id = {_T} AND public.is_current_user_member(tenant_id))"
_ADMIN = f"(tenant_id = {_T} AND public.is_current_user_admin_or_owner(tenant_id))"

_OUTCOMES = ("PASS", "REJECT", "CLARIFY", "APPROVAL", "INFRA_FAIL", "INVALID_OUTPUT")
_CATEGORIES = (
    "UNSUPPORTED_OPERATION",
    "MISSING_CAPABILITY",
    "MODEL_MISUNDERSTANDING",
    "UNDERSPECIFIED_REQUEST",
    "POLICY_REJECTION",
    "SCHEMA_SEMANTIC_FAILURE",
    "PLATFORM_LIMIT",
    "INFRA_FAILURE",
    "INVALID_OUTPUT",
)
_LEN_BUCKETS = ("lt50", "50_199", "200_999", "gte1000")
_SHAPES = (
    "has_time_window",
    "has_comparison",
    "has_top_n",
    "asks_why",
    "asks_export",
    "asks_action",
)


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


_CREATE = f"""
CREATE TABLE plan_outcome_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    proposal_id uuid,
    outcome text NOT NULL CHECK (outcome IN ({_in(_OUTCOMES)})),
    category text CHECK (category IS NULL OR category IN ({_in(_CATEGORIES)})),
    finding_codes text[] NOT NULL DEFAULT '{{}}'
        CHECK (cardinality(finding_codes) <= 32
               AND array_to_string(finding_codes, ',') ~ '^[A-Z_,]*$'
               AND length(array_to_string(finding_codes, ',')) <= 1024),
    clarification_count smallint NOT NULL DEFAULT 0 CHECK (clarification_count BETWEEN 0 AND 100),
    step_count smallint NOT NULL DEFAULT 0 CHECK (step_count BETWEEN 0 AND 1000),
    request_len_bucket text NOT NULL CHECK (request_len_bucket IN ({_in(_LEN_BUCKETS)})),
    request_shape text[] NOT NULL DEFAULT '{{}}'
        CHECK (request_shape <@ ARRAY[{_in(_SHAPES)}]::text[]),
    provider text NOT NULL CHECK (provider ~ '^[a-z0-9_-]{{1,32}}$'),
    model text NOT NULL CHECK (model ~ '^[A-Za-z0-9._:-]{{1,100}}$'),
    contract_version text CHECK (contract_version IS NULL
                                 OR contract_version ~ '^[a-z0-9._-]{{1,40}}$'),
    latency_ms integer CHECK (latency_ms IS NULL OR latency_ms BETWEEN 0 AND 3600000),
    tokens_in integer CHECK (tokens_in IS NULL OR tokens_in >= 0),
    tokens_out integer CHECK (tokens_out IS NULL OR tokens_out >= 0),
    repair_attempted boolean NOT NULL DEFAULT false,
    repair_succeeded boolean,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((outcome = 'INFRA_FAIL') = (proposal_id IS NULL))
)
"""


def upgrade() -> None:
    op.execute(_CREATE)
    op.execute("CREATE INDEX ix_plan_outcome_events_tenant_created ON plan_outcome_events "
               "(tenant_id, created_at)")  # fmt: skip
    op.execute("CREATE INDEX ix_plan_outcome_events_created ON plan_outcome_events (created_at)")
    op.execute("REVOKE ALL ON plan_outcome_events FROM PUBLIC")
    op.execute("GRANT SELECT, INSERT ON plan_outcome_events TO nlw_app")
    op.execute("ALTER TABLE plan_outcome_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE plan_outcome_events FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY plan_outcome_events_app_select ON plan_outcome_events "
        f"FOR SELECT TO nlw_app USING {_ADMIN}"
    )
    op.execute(
        "CREATE POLICY plan_outcome_events_app_insert ON plan_outcome_events "
        f"FOR INSERT TO nlw_app WITH CHECK {_MEMBER}"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS plan_outcome_events")
