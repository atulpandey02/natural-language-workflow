# Pilot analytics

M12C adds a first analytical interface on the existing workflow engine. This is
synthetic pilot functionality awaiting visual UX review, not a launch or a new
execution system. See [ADR-027](../adr/ADR-027-grounded-pilot-analytics.md), the
[inspection note](m12c-implementation-note.md),
[demo script](../runbooks/pilot-analytics-demo.md) and
[validation evidence](../evidence/m12c/validation.md).

## Architecture

```text
Dataset card / natural-language question
    → existing bounded planner → deterministic feasibility → immutable proposal
    → existing materialization → tenant-owned workflow version → run
    → Redis wake-up → signed worker context → registered analytical tool
    → PostgreSQL checkpoint + existing grounded run summary
    → deterministic analytics-1 projection → validated React/Recharts rendering

Completed grounded result + explicit destination selection
    → server-built immutable Slack proposal with source/destination binding
    → source reproduction + existing materialization revalidation
    → second run → independent approval → existing action executor
```

PostgreSQL remains authoritative; Redis carries wake-ups only. No customer data
is seeded into a shared database. The packaged loaders return cached immutable
tuples of frozen records and do not write files or tables. Repeated loading is
idempotent. Plans and checkpoints remain tenant-scoped through existing signed
purpose-bound context and RLS. Existing registry and runtime validation apply to
both new read-only tools. A 5-second tool timeout and 1–8 month window bound work.

`DEMO_TOOLS_ENABLED=true` is the existing operator opt-in for new planning and
the dataset catalog. It remains off unless explicitly enabled. This package does
not change deployment configuration or enable it on any host. Persisted plans
continue to use existing execution/revalidation rules.

### Source files and extension points

| Layer | Implementation |
|---|---|
| Datasets and aggregation | `src/nlw/analytics/datasets.py`, `analysis.py` |
| Tool registration | `src/nlw/tools/analytics_tools.py`, imported by `builtin.py` |
| Contract and projection | `src/nlw/analytics/schema.py`, `results.py` |
| Authorized result and handoff | `src/nlw/analytics/service.py`, `api/routers/analytics.py` |
| Materialization integration | additive precheck in `api/routers/plans.py` |
| Durable handoff binding | migration `0021`, proposal model/repository and provenance response |
| Wire validation / queries | `web/src/lib/analytics.ts`, `api/analytics-hooks.ts` |
| Product UI | `DatasetPicker`, `AnalyticsPanel`, `AnalyticsResult`, `ResponsiveDetails` |

No migration 0001–0020, execution state machine, approval policy, SQL guard,
connector-binding algorithm, scheduler/reconciler, signed context, backup,
recovery or release code changes are needed.

## Dataset definitions

Both datasets are public, synthetic fixtures with snapshot **2026-09-01**.
History spans January–August 2026. "Last six months" always means
**2026-03-01 through 2026-08-31**, not the current date. They contain no real
people, account information, credentials or customer records. Synthetic order,
customer and ticket IDs never appear in result labels or the shared summary.

### Sales operations — `sales-v1`

- Seed: **1203**; **1,641 rows**. Grain: one order containing one product.
- Fields: order date/ID, synthetic customer ID, product, category, region,
  channel, units, unit price in cents, percentage discount and revenue in cents.
- Four categories, eight products, four regions and three channels. Counts vary
  by month; Accessories volume declines after May. Two 45-unit Electronics
  orders in April and July are deliberate anomalies.
- Revenue is `units × unit_price_cents × (100 − discount_percent) // 100`,
  summed in cents before conversion to USD. There are no taxes, refunds or FX.
- Orders count rows; AOV is revenue divided by orders; units sum quantities.
  Each order belongs to exactly one category/product/region, so these groupings
  partition the totals.
- Best/worst category means highest/lowest selected-period revenue. Decline
  compares the last and first selected month's revenue; report a finding at
  **15% or greater decline**, with no causal claim. A one-month window has no
  change comparison. Stable category order resolves ranking ties.
- Default six-month KPIs: **$280,617.20 revenue**, **1,257 orders**,
  **$223.24 AOV**, **3,889 units**. Electronics leads; Accessories is lowest
  and declines **69.0%** between March and August.

### Customer support — `support-v1`

- Seed: **1204**; **1,260 rows**. Grain: one support ticket.
- Fields: ticket ID, UTC creation/resolution timestamps, team, issue category,
  priority, status, SLA target hours, resolution hours, reopened flag and CSAT.
- Three teams, four issues, three priorities. Billing is more frequent; Growth
  resolution times increase over the period. Two 180-hour July tickets are
  deliberate anomalies. Some August tickets remain open at the snapshot.
- Select tickets by **creation month**. SLA compliance is the percentage of
  resolved tickets with resolution hours at or below that ticket's SLA target.
  Open tickets are excluded from that denominator.
- Backlog counts open tickets in the selected creation cohort at the fixed
  snapshot. The monthly backlog column is a cohort breakdown, not reconstructed
  historical month-end backlog. Resolution time is the mean of resolved-ticket
  hours. CSAT averages available 1–5 scores; missing surveys are excluded.
- Recurring issue means ticket frequency by issue category; reopened counts are
  separately available in the supporting table. Team attention means lowest
  resolved-ticket SLA compliance; workload/issue mix must be reviewed before
  causal interpretation. This synthetic fixture correlates team and priority,
  so the comparison is descriptive, not a performance-adjusted ranking.
- Default six-month KPIs: **49.79% SLA compliance**, **25 open tickets**,
  **23.03 hours average resolution**, **4.23/5 CSAT**.

## `analytics-1` contract

All objects reject extra fields. The model supplies neither result text nor
chart props; the backend uses fixed vocabulary and deterministic templates.

| Field / type | Bound or rule |
|---|---|
| Contract | literal `analytics-1` |
| Status | `READY`, `PARTIAL`, `PENDING`, `EMPTY`, `INVALID` |
| Run outcome | existing summary's completed, failed, failed-with-unknown, waiting, in-progress or pending outcome |
| KPIs / charts / tables / findings | at most 8 / 6 / 6 / 8 |
| Charts | only `line` or `bar`; 1–3 series; one unit per chart |
| Tables | 1–4 numeric columns plus one bounded categorical dimension |
| Categories / values | 1–24, matching lengths; unique chart categories |
| Label / finding text | 1–80 / 1–240 characters |
| Numbers | strict finite int/float in ±10¹² or null; strings and booleans rejected |
| Units | USD, count, percent, hours, score |
| Sources | 1–8 per item, drawn from at most 8 result source IDs; step IDs ≤64 safe characters |
| Freshness | at most 2, known fixture/version and fixed as-of/period, synthetic=true |
| Digest | SHA-256 of the ordered result excluding the digest field itself |

Text validation rejects markup delimiters, control characters, HTTP/WWW URLs,
JavaScript URLs and UUID-shaped identifiers. Harmless instruction-like text is
inert text, never interpreted; actual projection labels/findings are code-owned.
The internal tool output is also strict and numeric, with dataset/window identity,
shape, ranges and total reconciliation checks. Raw outputs and extra fields are
never returned by this endpoint.

The projection checks the existing grounded summary's step outcome, checkpoint
completion, tool identity and validated numeric output. Failed, skipped, unknown
or unexecuted steps cannot supply results. A malformed successful checkpoint or
an exceeded contract bound returns `INVALID` with empty result collections.
`PARTIAL` shows only successful evidence and preserves the overall failure or
pending outcome. Slack sharing requires `READY` **and** `COMPLETED`.

The browser revalidates the whole contract, renders fixed Recharts components
and falls back to a clear unavailable state on rejection. It never evaluates
HTML or chart-library configuration supplied in a response.

## API and immutable Slack handoff

| Endpoint | Input / behavior |
|---|---|
| `GET /analytics/datasets` | Member-only public fixture metadata and example questions; empty when demo planning is disabled |
| `GET /runs/{id}/analytics` | Authorized member in the run's tenant; existing non-disclosing 404 for other tenants |
| `POST /runs/{id}/slack-proposal` | Connector UUID and optional allowed Slack channel only; existing plan rate limit |

The handoff endpoint accepts **no message text**. It loads the authorized run,
requires a completed valid result, constructs a ≤4,000-character summary, then
persists a normal immutable proposal with `analytics_source` containing:

- source run UUID and analytics contract version;
- complete result digest and exact UTF-8 message digest;
- selected tenant-owned Slack connector UUID/type/config fingerprint;
- resolved allowed destination/channel identity.

Before every materialization, including an idempotent materialization read,
`validate_handoff` reproduces the result/message, verifies ownership and terminal
success, compares both digests and the contract, validates connector identity,
configuration and channel authorization, and compares the exact stored proposed
and normalized plans. Missing or stale metadata returns
`409 STALE_ANALYTICS_SOURCE`. Ordinary materialization then rechecks feasibility
and builds the existing identity-pinned connector binding.

The existing registry requires independent approval for `slack.send_message`.
Requester self-approval is rejected by API and database controls. The existing
approval preview contains the exact complete immutable text and effective
channel. The worker rechecks the connector binding before I/O. Transmission,
retry and terminal UNKNOWN handling remain unchanged. A changed source requires
a new proposal before materialization; an already accepted immutable proposal
is never refreshed during execution.

The two durable proposals and runs remain visible through the workflow/run
pages, source-analysis links, proposal provenance, message digest and action
audit. Existing summary behavior remains compatible. Handoff proposal list
entries suppress plan/feasibility payloads; full content is on authorized detail
and approval views only.

## Interface and observability

Seven primary links: Home, New analysis, Workflows, Runs, Approvals, Connectors,
Settings. New analysis provides dataset cards, the prompt composer, the existing
plan review/clarification and resubmission. The run page shows polling status,
KPI cards, charts, tooltips, legends, keyboard series toggles, supporting tables,
findings and source links. The right panel contains execution evidence and
action audit. Navigation and details become keyboard-operable nonmodal drawers
at smaller widths; Escape closes a drawer and returns focus. Tables can scroll
horizontally without widening the page. No raw output preview is shown.

New metrics use only fixed labels: result status counts, chart count histogram
(0–6), generation duration. These count endpoint projections/reads, not unique
executions. Existing run/tool/approval metrics already report workflow outcomes.
No tenant, user, run, prompt, title, connector or data-value metric labels added.

## Limitations and non-goals

- Frozen historical synthetic data; "today's risks" cannot mean live conditions.
  Use the displayed snapshot and ask a follow-up if current data is required.
- One selected dataset per analysis. A combined result exceeding fixed bounds
  is unavailable rather than truncated into a misleading successful chart.
- Findings are descriptive rule-based comparisons, not forecasts or causal
  explanations. Missing values stay null; the UI displays "Unavailable".
- No arbitrary SQL/chart configuration, dashboard builder, exports, collaborative
  editing, cross-workflow memory or live connector setup in this package.
- Golden tests exercise a controlled provider response; they do not measure
  live model interpretation. The existing unconfigured stub may clarify instead
  of producing an analytical plan. No provider or live Slack delivery was used.
- Existing launch/operations gates remain in force. This change does not certify
  production readiness or authorize deployment.
