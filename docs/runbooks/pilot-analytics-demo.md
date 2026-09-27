# Pilot analytics demo and golden workflows

Use an already authorized local pilot environment with demo tools enabled,
existing auth/API/worker/Redis/PostgreSQL configured and migrations through
`0021`. Never substitute a real delivery token into the automated fixture.
This task did not enable or deploy anything on a remote host.

## User-facing walkthrough (about five minutes)

1. Sign in and select your workspace. Open **New analysis**. Explain that both
   cards are synthetic and fixed as of **September 1, 2026**.
2. Choose **Sales operations**. The example asks for six-month revenue and order
   trends, best/worst categories, regional performance and decline. Adjust the
   natural-language question, then choose **Plan**.
3. Review the registered tool and bounded window. A feasible proposal shows
   `PASS`; a clarification remains editable. Choose **Materialize workflow**,
   then **Run now**. Observe persisted execution state.
4. On completion, show the four sales KPIs and revenue/order/category/region
   charts. Hover or focus a chart and use arrow keys; use the series toggle.
   Expand a supporting table and follow **Source analyze** into the evidence
   panel. Explain that the Accessories decline is a measured comparison, not a
   claim about its cause.
5. Open **New analysis**, choose **Support operations**, and repeat. Show SLA,
   backlog, average resolution and satisfaction. Explain the resolved-ticket
   SLA denominator and snapshot backlog. Compare issues and teams, then inspect
   the supporting table and completed source step.
6. For the third workflow, return to a completed analysis and explicitly choose
   **Send summary to Slack** after selecting an allowed destination. Review the
   exact immutable text, source run, version, digest and channel. Materialize
   this second workflow and start its run.
7. The run waits for approval. The requester cannot approve their own action.
   A different admin/owner signs in, checks the complete message and destination,
   and approves. In the automated local demonstration only, the HTTP transport
   records a synthetic delivery. Both source analysis and action run remain
   visible. Never claim the fixture posted to Slack.

For a request such as "Analyze today's operational risks and send the approved
summary to our team Slack channel", state the fixed synthetic snapshot and use
the explicit two-proposal sequence. Analysis must finish before the grounded
message can be proposed. There is no dynamic step-output-to-action binding.

## Expected results

| Journey | Execution / result |
|---|---|
| Sales | Real registered aggregation; 4 KPIs, 4 charts, 4 supporting tables, source-grounded category/decline findings |
| Support | Real registered aggregation; 4 KPIs, 5 charts, 3 supporting tables, source-grounded issue/team findings |
| Analysis → Slack | Two durable proposals/runs; server-generated source/destination binding; self-approval denied; separate approver; controlled mock delivery |

An invalid result produces no charts or sharing action. A failed or unknown run
keeps that outcome visible. `PARTIAL` only shows completed source work and cannot
be shared. Source or connector drift before materialization requires a new
proposal. Connector drift before delivery is blocked before I/O. Ambiguous
delivery stays terminal UNKNOWN even after duplicate wake-ups.

## Reproduce automated browser evidence locally

The new opt-in harness composes the existing PostgreSQL fixture with real Redis,
signed API/worker roles, an actual worker subprocess, Uvicorn, a production
Next.js build and Chromium. It uses real local Supabase sign-in and BFF cookies.
Only the model response and Slack HTTP transport are controlled test boundaries;
the browser does not intercept or fabricate API results.

Prerequisites: repository Python/frontend dependencies, Docker, cached local
Supabase images, Supabase CLI and Playwright Chromium. Use an isolated temporary
Supabase workdir so existing projects are untouched. Its status JSON contains
local auth credentials: keep it outside the repository and never commit it.

```sh
# Initialize/start a disposable local Supabase project in a temporary workdir.
supabase init --workdir /tmp/nlw-pilot-auth
supabase start --workdir /tmp/nlw-pilot-auth \
  --exclude studio,realtime,storage-api,imgproxy,postgres-meta,logflare,vector,edge-runtime,mailpit
umask 077
supabase status --workdir /tmp/nlw-pilot-auth -o json > /tmp/nlw-pilot-auth.json

npm --prefix web run build
PILOT_AUTH_CONFIG=/tmp/nlw-pilot-auth.json uv run pytest \
  tests/integration/test_pilot_browser.py -q

# Stop only this disposable local project after reviewing evidence.
supabase stop --workdir /tmp/nlw-pilot-auth
```

`PILOT_AUTH_CONFIG` must point to a loopback auth service. The harness creates
synthetic confirmed users (no email transmission), a workspace, a separate
tenant and a mock-only Slack connector. It launches two Playwright scenarios,
including cross-tenant 404 and requester/approver separation. It stops its web,
API, worker and disposable database/Redis processes on completion. Supabase is
managed separately by the commands above. Screenshots are written to
`web/test-results/pilot-*.png` (ignored), with reviewed copies in
`docs/evidence/m12c/`.

Other focused checks:

```sh
uv run pytest tests/unit/test_pilot_analytics.py \
  tests/integration/test_pilot_analytics_api.py -q
uv run python -m nlw.eval.runner
uv run pytest tests/integration/test_ai_core_smoke.py -q
```

The ordinary full suite skips opt-in live-provider and browser checks unless
their existing explicit gates are set. The pilot browser harness is run
separately and must not be represented as a live-provider evaluation.
