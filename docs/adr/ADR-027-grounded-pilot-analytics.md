# ADR-027 — Grounded analytics and immutable summary handoff

- Status: Accepted for M12C implementation; pending visual UX review
- Date: 2026-09-26

## Context

The pilot needs useful analytical results without letting a model supply UI code
or reinterpret execution outcomes. ADR-026 already establishes deterministic
summaries over PostgreSQL state. Existing steps can order work with `depends_on`,
but cannot bind a completed step's output into another step's arguments. Action
arguments and their approval preview must remain immutable (ADR-013).

## Decision

Introduce `analytics-1`, a strictly bounded presentation contract projected by
code from successful analytical checkpoints and the existing grounded summary.
Only the registered `pilot.sales_analysis` and `pilot.support_analysis` tools
contribute. The contract contains numeric KPIs, line/bar charts, tables, fixed
findings, freshness and source step IDs. No arbitrary chart configuration, HTML,
SQL, styling, URLs or executable content is accepted. Validate with Pydantic on
the server and Zod at the browser boundary. Invalid data produces no charts.

Package two versioned public synthetic datasets as immutable deterministic
loaders. Ordinary tenant-owned plans and checkpoints persist the selected version
and results. These loaders require no customer connector or new data service.
Keep the existing operator-controlled demo-tool visibility gate.

Use Recharts as the single new direct runtime dependency. The repository had no
chart library. Its React components, responsive container, tooltip, legend and
keyboard accessibility support the fixed vocabulary. Chart props remain in
reviewed source code. Supporting tables also expose the values without requiring
chart interaction. Handwritten SVG would duplicate interaction/accessibility
work; a general chart specification language expands the input boundary without
helping this pilot. See [ResponsiveContainer](https://recharts.github.io/en-US/api/ResponsiveContainer/)
and [accessibility](https://github.com/recharts/recharts/wiki/Recharts-and-accessibility).

The user explicitly approved a two-proposal journey:

1. Complete the analytical run and validate its grounded result.
2. The user selects **Send summary to Slack** and a tenant-owned destination.
3. The server constructs the exact bounded message and an immutable second
   proposal. The browser supplies only connector/channel selection.
4. Bind source run, analytics version, complete result digest, exact message
   digest, connector UUID/type/config fingerprint and channel.
5. Before materialization, reproduce the source result and message from
   authorized authoritative state and revalidate every binding. Any mismatch or
   unavailable source fails closed and requires a new proposal.
6. Use ordinary feasibility, materialization, four-eyes approval, connector
   checks and external-action execution. The approver sees the complete message
   and effective channel that will be sent.

Migration `0021` adds nullable `plan_proposals.analytics_source`. Existing RLS
and column-limited app UPDATE privileges preserve its immutability. It adds no
role, grant, policy, state or action mechanism. Proposal detail and workflow
provenance expose the binding; handoff proposal list responses omit payloads.

## Consequences

- Analytics is reproducible, reviewable and attributable to successful work.
  Failed, skipped, unknown and unexecuted steps cannot contribute conclusions.
- One seamless UI journey retains two independently durable workflows/runs,
  visible through source links, proposal provenance and existing action audit.
- No change to execution, approval, transmission, retry or terminal UNKNOWN.
  An accepted immutable message is never silently refreshed during execution.
- One dataset per analysis is the supported pilot flow. Combined projections
  exceeding contract bounds fail safely. Changing dataset generation or contract
  semantics requires a new version; v1 fixtures are historical and frozen.
- Actual model interpretation remains the existing provider's responsibility.
  Local golden tests substitute only the provider response and Slack transport;
  they do not establish live model quality or live delivery.

## Alternatives considered

- Dynamic downstream action arguments: rejected because it changes protected
  execution and approval semantics. The approved two-proposal interface meets
  the product need within existing boundaries.
- Model-generated findings or chart configuration: rejected because unsupported
  claims or executable configuration would widen the trust boundary.
- New analytics tables/warehouse: unnecessary for 2,901 public synthetic rows.
  Existing workflow persistence is sufficient for tenant-owned evidence.
