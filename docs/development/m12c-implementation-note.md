# M12C implementation note

Inspected baseline: `6507d0b1250ccc6134d27ff01354881fdec561f4`, clean
`feat/pilot-analytics-experience`. Read ADR-013, ADR-022, ADR-024, ADR-025,
ADR-026, planner/prompt/budget, feasibility/revalidation, registry/connectors,
materialization, worker execution, summaries, API authorization, Next.js tests
and the Playwright seeded-stack harness before implementation.

## Extension points

- Registered pure read tools can aggregate bounded, packaged synthetic records
  through the existing worker. `postgres.query` can aggregate external tables,
  but there is no built-in analytical tool or safe chart-result projection.
  The fake/static tools do not perform the requested analysis.
- Versioned deterministic fixture loaders need no customer table, credentials,
  SQL, database service or migration. Their read-only records are shared public
  samples; selected versions and results live in existing tenant-owned plans
  and step checkpoints. Demo visibility remains operator-controlled.
- A strict deterministic analytics projection can compose the existing grounded
  summary with validated output from the new registered tools. Its run endpoint
  uses the existing membership, signed context, repository and 404 patterns.
- Extend the existing request → PlanReview → materialize → Run now flow;
  TanStack Query polls authoritative state. Add responsive navigation, result
  cards, evidence details and Recharts (no chart library is currently installed).
  Use only fixed chart renderers and validate the wire contract in the browser.

## Protected contracts

Do not edit migrations 0001–0020, execution/actions state machines, signed
context/RLS/grants, approval decision rules, connector binding, SQL safety,
scheduler/reconciler, backup/recovery or release/deployment code. Keep existing
summary and list contracts compatible. Retain planner budgets, registry/runtime
validation, immutable versions, durable checkpoints, four-eyes approvals and
terminal UNKNOWN. New features compose these controls; they do not bypass them.

## Smallest additive model

- Two versioned fixture loaders and registered analytical tools with bounded
  typed arguments; deterministic aggregation produces validated numeric data.
- `analytics-1` result: bounded metrics, fixed line/bar charts, supporting
  tables, findings, freshness and successful source-step references. No model
  chart code, markup, raw output, secrets or arbitrary chart options.
- Authorized dataset catalog and `GET /runs/{id}/analytics`.
- A Slack handoff endpoint accepts only a source run and destination selection.
  The server constructs the exact message from the completed validated result.
  One nullable JSONB column on `plan_proposals` stores its source run, contract
  version, summary digest and connector/destination binding. Migration 0021
  inherits existing RLS and column-limited UPDATE immutability; no grant or
  policy changes. Materialization revalidates the source and binding.

## Execution boundary and approved interface adaptation

`depends_on` orders steps but carries no output values. `ActionTask.args` copies
the immutable plan; the approver previews those same arguments. A single-run
dynamic Slack summary would require protected execution/approval changes.

The operator explicitly approved two durable proposals/runs: complete analysis,
then select **Send summary to Slack**, review a server-generated bound proposal,
materialize and request independent approval. The exact immutable message and
destination remain visible. Reproduction/digest or connector drift fails closed
before materialization; ordinary runtime connector revalidation remains intact.
No execution-semantics change is needed for this approved adaptation.

## Validation boundaries

Use disposable local PostgreSQL/Redis and controlled provider/HTTP fixtures.
The existing Playwright harness uses local Supabase auth; its stub planner only
clarifies, so a test-only deterministic provider is needed for actual golden
planning through the API. No live model/provider or Slack result will be claimed.
Run the requested suites, migration roundtrip and browser journey, recording
any unavailable prerequisites honestly. No push, PR, merge, deployment or VPS
access is authorized.
