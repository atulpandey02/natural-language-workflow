# M12C validation evidence

Date: 2026-09-26. Branch: `feat/pilot-analytics-experience`.
Baseline: `6507d0b1250ccc6134d27ff01354881fdec561f4` (clean at start).
All execution was local. No VPS, live model provider or real Slack transport was
used. No push, PR, merge or deployment was performed.

## Final visual refinement — 2026-09-26

This pass starts at accepted functional commit `6b8605b`. The earlier functional
validation below is retained as historical evidence. Only frontend presentation,
additive frontend tests, browser evidence and documentation changed in this pass.

### Before and after

The initial inspection found equal blue cards, small KPI values, repeated page
headings, identical chart colors, tiny legend controls and an always-open execution
column competing with the analysis. The [original Sales capture](pilot-sales-desktop.png)
is retained for comparison.

The refinement gives the business result the full content width. A compact KPI
strip uses stable metric colors and identifies measured totals versus derived
averages/rates. Numbered grounded findings sit above asymmetric trend panels;
horizontal category bars make category names easier to read. Supporting tables,
Slack sharing, deterministic execution summary and collapsible evidence each
have a distinct visual treatment. The existing line/bar contract, exact values,
findings and source links remain intact. Lines join recorded observations with
straight segments; no smoothing or additional data points were introduced.

### Checks for this pass

| Check | Result |
|---|---|
| Frontend Prettier / ESLint / TypeScript | Passed |
| Vitest | **132 passed across 30 files**; all existing assertions retained |
| Next.js production build | Passed |
| Original real Playwright journeys | **2/2 passed**: Sales → separate Slack proposal → independent approval; Support |
| Supplemental real browser scenario | **1/1 passed**: partial FAILED/SKIPPED, empty FAILED, separate Slack run with UNKNOWN |
| Frontend test adapter Ruff format / lint | Passed |
| Harness warnings | One existing Starlette/AnyIO deprecation warning per run |
| Protected-file diff against `6b8605b` | Empty for backend, tests/integration, migrations, API/BFF/hooks/contracts, datasets and dependencies |
| Full backend suites | Intentionally not rerun; no shared contract or backend implementation changed |

The ordinary browser harness remains byte-for-byte unchanged. The new opt-in
`web/e2e/visual_states_plugin.py` reuses it with a separate browser spec and
deterministic planner inputs containing the existing `fake.fail` tool. The
existing mock Slack HTTP transport returns its ambiguous outcome. Real auth,
feasibility, materialization, queue, worker, approval and PostgreSQL checkpoints
produce the displayed results. No browser API responses or persisted outcomes
are fabricated. Both harness runs retain the assertion of exactly one synthetic
transmission to `CPILOT`; neither can deliver a real Slack message.

Reproduction after `cd web && npm run build`, from the repository root with a
running disposable local Supabase project:

```sh
PILOT_AUTH_CONFIG=/tmp/nlw-m12c-auth-status.json UV_CACHE_DIR=/tmp/nlw-m12c-uv \
  uv run pytest tests/integration/test_pilot_browser.py -q --tb=short
PILOT_VISUAL_STATES=1 PILOT_AUTH_CONFIG=/tmp/nlw-m12c-auth-status.json \
  UV_CACHE_DIR=/tmp/nlw-m12c-uv uv run python -m pytest \
  tests/integration/test_pilot_browser.py -p web.e2e.visual_states_plugin -q --tb=short
```

The local auth configuration contains credentials and is deliberately outside the
repository. `python -m pytest` is required for the frontend test plugin's module
path. Initial development checks caught TypeScript fixture typing and jsdom's
missing native keyboard activation for `summary`; the latter is covered in the
real browser. The first golden browser run required opening the new disclosure
before checking its source link. No original assertion was removed or relaxed.
Supplemental selectors distinguish loading indicators and duplicated audit
destinations. UNKNOWN uses a fixed 1440×1440 capture: tracing showed that
Playwright's full-page capture briefly sets a 1px viewport, which correctly
collapses responsive drawers. An additional unit check verifies that an open
evidence disclosure survives an ordinary result rerender.

### Responsive and accessibility evidence

- **1440×900 and 1280×800:** two chart columns, wider primary trend, four KPIs,
  desktop navigation, collapsed evidence, no page overflow.
- **768×1024:** two chart columns with readable 12px axes; navigation and evidence
  drawers close with Escape; no page overflow.
- **390×844:** single chart/KPI column, 44px chart controls, bounded exact-value
  tooltip, no page overflow. Wide supporting tables scroll inside their own
  focusable region.
- Real browser assertions cover native disclosure Enter activation, chart arrow
  keys, pointer hover, visible focus, Escape, exact tooltip text, tooltip bounds
  and reduced-motion transitions. Unit tests check keyboard legend controls,
  complete chart text alternatives and every Sales KPI/table cell.
- Series have text labels plus marker shapes and line patterns. Palette and axis
  text contrast against the five principal dark surfaces ranges from **6.26:1**
  upward; this exceeds AA text contrast. The primary Slack button uses dark text
  on mint. Status text remains explicit for FAILED, SKIPPED and UNKNOWN.
- The immutable Slack message is compared verbatim with the server proposal and
  the separate approver's preview. The destination is also checked. Tests retain
  hostile-text rejection and add verification that opening evidence never reveals
  confidential raw step output.

### Final unedited browser screenshots

All images come from the real seeded local browser flows. Full-page images retain
their viewport width and extend vertically; tooltip and proposal images capture
the relevant rendered component. The prior screenshots remain unchanged.

| Screenshot | Evidence |
|---|---|
| [Sales desktop](visual-refinement/pilot-sales-desktop.png) | Full result, 1440px wide, table expanded |
| [Desktop viewport](visual-refinement/pilot-sales-desktop-viewport.png) | Initial 1440×900 composition |
| [Sales laptop](visual-refinement/pilot-sales-laptop.png) | 1280×800 viewport, asymmetric layout |
| [Sales tablet](visual-refinement/pilot-sales-tablet.png) | 768×1024 viewport, two chart columns |
| [Sales mobile](visual-refinement/pilot-sales-mobile.png) | 390×844 viewport, single column |
| [Support desktop](visual-refinement/pilot-support-desktop.png) | SLA, backlog, resolution, satisfaction and issue/team breakdowns |
| [Chart interaction](visual-refinement/pilot-tooltip.png) | Exact-value keyboard tooltip with series marker |
| [Mobile interaction](visual-refinement/pilot-tooltip-mobile.png) | Tooltip contained in the mobile chart |
| [Immutable Slack review](visual-refinement/pilot-slack-proposal.png) | Exact message, destination, source run and digest |
| [Mobile source evidence](visual-refinement/pilot-evidence-mobile.png) | Source opens the secondary evidence drawer |
| [Partial / failed](visual-refinement/pilot-partial-failed.png) | Completed evidence retained; FAILED and SKIPPED visible; no sharing |
| [Failed / empty](visual-refinement/pilot-failed-empty.png) | No completed analytics; no charts invented |
| [UNKNOWN](visual-refinement/pilot-unknown.png) | Separate Slack action remains UNKNOWN and is not reported as success |
| [Proposal](visual-refinement/pilot-proposal-desktop.png) | Original planning experience still works |

### Exact file manifest

Paths are relative to the repository root. No dependency files changed.

```text
web/src/app/analytics.css
web/src/app/globals.css
web/src/app/runs/[id]/page.tsx
web/src/app/runs/[id]/page.test.tsx
web/src/components/AnalyticsPanel.tsx
web/src/components/AnalyticsResult.tsx
web/src/components/AnalyticsResult.test.tsx
web/src/components/PlanReview.tsx
web/src/components/PlanReview.test.tsx
web/src/components/ResponsiveDetails.tsx
web/src/components/ResponsiveDetails.test.tsx
web/src/components/RunSummaryCard.tsx
web/src/lib/analytics-presentation.ts
web/src/lib/analytics-presentation.test.ts
web/e2e/pilot-analytics.spec.ts
web/e2e/pilot-visual-states.spec.ts
web/e2e/visual_states_plugin.py
docs/PROJECT_INDEX.md
docs/evidence/m12c/validation.md
```

The 14 PNG files listed individually in the screenshot table are the remaining
new files, all under `docs/evidence/m12c/visual-refinement/`.

### Review boundary and limitations

Backend execution/security/approval behavior, Slack proposal bindings/digests,
analytics calculations/contracts, seeds, expected values and deployment files
are unchanged from `6b8605b`. No live model/provider or Slack delivery occurred.
No push, PR, merge or deployment was performed. Independent review is next.

Visual validation uses Chromium and the synthetic pilot datasets. Safari,
Firefox, assistive-technology user testing and a full accessibility audit were
not performed. Charts retain the fixed line/bar templates; tables intentionally
scroll within their region on narrow screens. Long full-page captures should be
viewed at native width. This pass does not restyle the rest of the application.

## Accepted functional implementation — historical checks

| Check | Result |
|---|---|
| Ruff format / check | Passed |
| mypy | Passed across 301 source files |
| Complete backend suite | **1,416 passed, 35 skipped, 0 failed** in 1,085.49 seconds; 15 non-failing dependency/test warnings |
| Pilot integration | 10 passed; strengthened exact digest, foreign connector and checkpoint assertions included |
| AI-core smoke | 2 passed (also part of complete backend suite) |
| Migration `0021` | Upgrade to head → downgrade to `0020` → upgrade to head passed; FORCE RLS and column UPDATE denial verified |
| Deterministic corpus | 34/34 passed; [machine-readable results](deterministic-eval.json), [category summary](deterministic-eval.md) |
| Frontend format / lint / typecheck | Passed |
| Vitest | 116 passed across 29 files |
| Next.js production build | Passed |
| Playwright Chromium | 2/2 golden scenarios passed through one opt-in pytest harness; final run 30.25 seconds including setup/teardown |
| Compose rendering | Not applicable; Compose and deployment configuration untouched |
| `git diff --check` | Passed |
| Secret scan | Gitleaks feature-branch scan passed with no leaks; final documentation commit rechecked before handoff |
| Runtime dependency audit | `npm audit --omit=dev`: 0 vulnerabilities |
| Full dependency audit | 5 pre-existing development-tool package advisories; versions unchanged from baseline (details below) |

## Golden workflows and boundaries proved

The browser signs into real **local** Supabase, uses real BFF cookies/workspace
selection, posts a natural-language request, reviews a feasibility result,
materializes a version, receives a `PENDING` run response, and observes results
from an actual worker with PostgreSQL checkpoints and Redis wake-ups.

- **Sales:** 4 KPIs, 4 actual chart SVGs, supporting table, Accessories decline
  finding and completed source-step evidence. The six-month run returns
  $280,617.20, 1,257 orders, $223.24 AOV and 3,889 units.
- **Support:** 4 KPIs and 5 actual charts, including SLA/resolution/satisfaction
  trends, issue frequencies and team comparison. KPIs are 49.79% SLA, 25 open
  tickets, 23.03 hours average resolution and 4.23/5 satisfaction.
- **Slack:** explicit destination selection creates a second immutable proposal;
  exact text/channel and source link are shown. A requester cannot approve it.
  A separate admin signs in and approves. The normal worker calls the existing
  action implementation through `httpx.MockTransport`, which records exactly
  one synthetic message to `CPILOT`. No Slack network delivery occurs.
- **Tenant isolation:** another browser context signs into a different tenant
  and gets 404 for the analysis result, without revenue data. Integration tests
  also cover unauthenticated 401, same-tenant member access, source-run
  substitution and foreign-owned connector substitution.
- **Durability and failure:** duplicate wake-ups leave completed checkpoint
  time/output/attempt unchanged. Source changes, lost output, nonterminal/failed
  sources and changed connector configuration reject the handoff. Valid but
  different data also fails the exact digest comparison. Runtime connector drift
  fails before I/O with `CONNECTOR_CONFIG_CHANGED`, the existing persisted
  reason for STALE_PLAN. An ambiguous mock HTTP response remains terminal UNKNOWN
  with one transmission after repeated wake-ups.
- **Confidentiality and immutability:** extra raw-output fields are invalid and
  never returned; browser-supplied text is rejected; list results omit handoff
  payloads; bound metadata cannot be updated by the application DB role.

Controlled boundaries are the **planner provider response** and **Slack HTTP
transport**. Real planner parsing, limits, feasibility, materialization, signed
database contexts, auth, queue, worker, approval, action code and persistence run
normally. This is not a live model-quality or live-connector benchmark. The
34 credential-gated live-model tests are intentionally skipped in the ordinary
suite; the opt-in browser test is run separately.

The final list-response confidentiality guard was added after the complete run
started and passed its focused integration rerun. The final expanded pilot
assertions also passed all 10 integration tests. Frontend and browser results
above include the last tablet drawer adjustment. Disposable local auth/browser
services were stopped after testing.

## Rendered evidence

Unedited Playwright screenshots. Workspace names, emails, IDs and content are
from disposable local synthetic fixtures. No credentials or raw tool output are
shown. Desktop viewport 1600×1000; tablet 1024×768; mobile 390×844; full-page captures
are taller where indicated.

| Screenshot | What it demonstrates |
|---|---|
| [Proposal](pilot-proposal-desktop.png) | Dataset selection, submitted question, actual feasible plan and composer |
| [Sales result](pilot-sales-desktop.png) | KPIs, four charts, findings, supporting data and evidence panel |
| [Support result](pilot-support-desktop.png) | Service metrics, five charts and grounded issue/team findings |
| [Mobile result](pilot-sales-mobile.png) | Collapsed navigation/details, responsive charts, horizontally scrollable table |
| [Tablet result](pilot-sales-tablet.png) | Both panels collapse into drawers; charts retain two columns; navigation opens and closes by keyboard |
| [Mobile evidence](pilot-evidence-mobile.png) | Open source-step drawer; pointer close and Escape verified |
| [Slack proposal](pilot-slack-proposal.png) | Exact immutable message, channel, source link, message digest and approval requirement |

## Protected invariants

A baseline diff confirms **no changes** to migrations 0001–0020, execution,
worker, signed tenancy context, feasibility/revalidation/binding, auth,
connectors/SQL safety, planner limits/prompts, secrets, scheduler/reconciler,
backup/recovery/rollout, deploy scripts/configuration or CI.

The new migration adds one nullable JSONB column. It changes no grants, RLS,
roles or status machines. The new API composes the existing run summary and
tenant-scoped repositories. The only materialization addition is source/binding
validation for the new handoff proposals. Existing summaries, approval previews,
transmission/retry/UNKNOWN behavior and append-only authorization audit retain
their implementations and regression tests.

Historical evaluation corpus files and committed live benchmark evidence are
byte-for-byte unchanged from baseline. `eval/catalog.py` pins the seven tools
offered in those historical v1/v2 benchmarks while using their real current
registry implementations and feasibility checks. Pilot integration tests use the
full current registry. This prevents newly registered demo tools from silently
changing what historical evidence measured.

## Validation corrections made during development

The initial full run reported 1,398 passed, 34 skipped and 10 failures. These
identified exact catalog/head assumptions and historical evidence binding:

- Expanded the explicit demo-tool test set to include both pilot tools; demo
  default-off and connector-gating assertions remain intact.
- Restored the historical corpus instead of changing its expected tool lists;
  pinned its original catalog for reproducible replay/live-run inputs.
- A secret-field test mistook the substring `port` in `support` for a network
  port. It now checks complete JSON names and additionally enforces exact
  allowlisted tool/connector field sets.
- Head derivation expects additive migration `0021`. The accepted `0020`
  code-only release test remains, with its target explicit; a new test checks
  that this checkout requires migration `0021` and rejects missing image
  migration content. Release and deployment implementations remain untouched.
- The new stale-binding test initially expected exception prose in the summary.
  The unchanged executor persists the precise reason code. The test now checks
  exact persisted error, failed step/run, zero successful steps and zero I/O.

A unit-suite attempt in the restricted filesystem sandbox could not bind local
test sockets (4 failures, 2 setup errors). All **88 tests** in those three test
files passed with the same approved local-test access as the integration
harness. The complete rerun also uses that access. No assertions were removed
or failure states relaxed to compensate for environment restrictions.

## Dependency audit

Recharts `3.10.1` is the only new direct dependency. Runtime audit is clean. The
full audit reports the following unchanged baseline development packages:

| Package | Version (baseline = current) | Severity |
|---|---|---|
| `@vitest/mocker` | 2.1.9 | moderate |
| `esbuild` | 0.21.5 | moderate |
| `vite` | 5.4.21 | high |
| `vite-node` | 2.1.9 | moderate |
| `vitest` | 2.1.9 | critical |

No forced dependency upgrade was applied. These existing development-tool
advisories remain a limitation; resolving them would be a separate toolchain
change. No newly added runtime package was flagged.

## Original functional review boundary

This package stops at focused local commits and a clean working tree. Visual
UX review is next. Frozen synthetic data, a single dataset per analysis, fixed
chart types and rule-based findings are deliberate pilot limits. Existing launch
gates remain unchanged. No final visual-polish pass or production rollout is
included.
