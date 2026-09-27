# M12C validation evidence

Date: 2026-09-26. Branch: `feat/pilot-analytics-experience`.
Baseline: `6507d0b1250ccc6134d27ff01354881fdec561f4` (clean at start).
All execution was local. No VPS, live model provider or real Slack transport was
used. No push, PR, merge or deployment was performed.

## Checks

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

## Review boundary

This package stops at focused local commits and a clean working tree. Visual
UX review is next. Frozen synthetic data, a single dataset per analysis, fixed
chart types and rule-based findings are deliberate pilot limits. Existing launch
gates remain unchanged. No final visual-polish pass or production rollout is
included.
