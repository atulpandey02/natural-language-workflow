# Pilot launch closure — evidence

Branch `feat/staging-custom-domain`, on top of the custom-domain commits (b77dcf3 … d8dfdaa,
unchanged). Everything here uses **synthetic** data only: local Supabase auth, a controlled
planner provider and a mock Slack transport. No real Slack delivery, no cloud or VPS contact,
no Supabase project changes.

## 1. Membership discovery (before building the UI)

| Question | Finding |
| --- | --- |
| Endpoints | `GET /members` (any member); `PATCH`/`DELETE /members/{user_id}` (owner/admin); `GET`/`POST /invitations`, `POST /invitations/{id}/revoke` (owner/admin); `POST /invitations/accept` (any signed-in user). |
| Roles | `owner`, `admin`, `member`. Invitations can grant `admin` or `member` only. |
| Existing identities | An existing user accepts when their account email matches the invited email. |
| Acceptance binding | SECURITY DEFINER `accept_workspace_invitation`: token hash + `users.email` match + pending + not expired. Every failure is the same 400, so it doesn't reveal which check failed. |
| Protections | Membership changes go only through SECURITY DEFINER `manage_membership`. Only owners can touch owner rows or grant owner. The last owner can't be removed (check_violation → 409). Also covered: duplicate pending invites (unique index → 409), per-workspace caps, cross-tenant isolation (RLS) and audit events. |
| Missing capability | **Co-member emails.** The `users_app_self_select` RLS policy lets the API read only the caller's own user row. The smallest secure addition would be a SECURITY DEFINER `workspace_member_directory()` returning (user_id, email) for the caller's workspace only, in a new migration. That is a protected area, so it was **not** built. The roster shows "You · email" for you and "Member since …" for everyone else — never a UUID. |

The browser never writes membership tables. Every change goes through the existing API, which
still enforces RLS and roles.

## 2. Commits

| Commit | Scope |
| --- | --- |
| 1881634 | Members and invitations: roster, role pills, role select (only allowed roles), revoke/remove with confirmation, read-only view for members, invite form, one-time link hidden by default, acceptance flow with a safe `next` return path, Members in the nav. The API adds `joined_at` to the member list. |
| 5845eb5 | One friendly error layer (`lib/friendly-errors.ts`) covering 400/401/403/404/409/`STALE_PLAN`/422/429/503/500, network errors, failed/partial runs and `UNKNOWN` outcomes. `UNKNOWN` never suggests a retry. |
| aabdeca | Sign-in page (NLW headline, capabilities, invitation-only synthetic pilot, show/hide password, inline validation, friendly auth errors). Workspace onboarding (what a workspace is; Ask → Review → Execute → Evidence). First-use Get started panel. |
| 712d279 | Analysis journey in plain language: Prepare plan / Save workflow / Run now, readable steps and safety checks, status labels (exact status kept in `data-status`), plan-request progress and duplicate-submit guard, dataset example questions and preselect, and outcome notices in place of raw engine errors. |
| 5f3abd0 | Slack connector fix: typed schema, friendly field errors, credential material refused and cleared, product Slack vs Alertmanager explained. Backend: a duplicate connector name returns 409 instead of an unhandled 500. |
| 20086c7 | Approval review: no requester UUID, no raw JSON; the exact Slack message is shown verbatim. |
| (this) | Launch browser journeys, CI step, seeded-spec updates, one denial panel for an unreadable run, evidence. |

## 3. Browser journeys (real browser, isolated pilot harness)

`web/e2e/pilot-launch.spec.ts` runs through `tests/integration/test_pilot_browser.py` with
`-p web.e2e.launch_journeys_plugin` and `PILOT_LAUNCH_JOURNEYS=1`. The run uses real local
auth, the API, feasibility checks, the queue, the worker and Postgres. The harness still
asserts **exactly one** mock Slack delivery. CI runs it as a third step of "Required pilot
browser harness (isolated)".

| # | Journey | Where |
| --- | --- | --- |
| 1 | Requester creates a workspace (validation, then create and open, Get started) | launch spec, test 2 |
| 2 | Owner invites the approver as Admin (link hidden until revealed) | launch spec, test 2 |
| 3 | Approver opens the link signed out → "Sign in to accept your invitation" → joins as Admin; the token is scrubbed from the address bar | launch spec, test 2 |
| 4 | Sales analysis ($280,617.20) at 1440/1280/768/390, no horizontal scroll | launch spec, test 2 |
| 5 | Support analysis (SLA compliance trend) | launch spec, test 2 |
| 6 | Requester can't approve their own action (note shown, no Approve button) | launch spec, test 1 |
| 7 | A second admin approves the exact message → run COMPLETED (one mock delivery) | launch spec, test 1 |
| 8 | Outsider: API returns 404 for the run, the page shows one friendly "We couldn't find that", and the used invitation link shows the non-enumerating failure panel | launch spec, test 2 |
| 9 | Connector: `#channel` name and a pasted webhook URL are refused with friendly copy (the URL is cleared and never shown); a duplicate name is a field error | launch spec, test 3 |
| 10 | Mobile (390×844) and keyboard: tab order, show/hide with Enter, submit from the field, open a workspace with Enter, visible focus, no horizontal scroll on the main pages | launch spec, test 4 |
| 11 | Failed, partial and UNKNOWN runs (UNKNOWN explained; "Don't simply run it again") | `pilot-visual-states.spec.ts` (visual-states step) |

The golden spec (`pilot-analytics.spec.ts`) still covers the full Sales → Slack proposal →
approval path, plus Support.

### Final validation (local, at `bad8333`)

| Check | Result |
| --- | --- |
| Backend `uv run pytest` | 1,793 passed, 35 skipped, 0 failed (17 min 22 s). The skips are opt-in suites, including the browser harness (run separately below) and live-model eval. |
| `ruff format --check`, `ruff check`, `mypy` | clean (mypy: 305 source files) |
| Frontend Vitest | 39 files, 231 tests passed |
| Prettier, ESLint (`--max-warnings=0`), `tsc --noEmit`, `next build` | clean |
| Pilot harness: golden journeys | 2 passed, 0 skipped; exactly one mock delivery |
| Pilot harness: failed / partial / UNKNOWN | 1 passed, 0 skipped |
| Pilot harness: launch journeys | 4 passed, 0 skipped; exactly one mock delivery |
| Seeded-stack Playwright (local Compose + local Supabase) | 8 passed |
| `git diff --check`, credential-pattern scan | clean. The only match is the fake `xoxb-…` test fixture that proves such values are refused. |

## 4. Screenshots

In this folder (all synthetic):

- Sign-in: `launch-login-{desktop,laptop,tablet,mobile}.png`, `launch-login-error.png`
- Onboarding: `launch-onboarding-select.png`, `launch-onboarding-home.png`,
  `launch-select-workspace-mobile.png`, `launch-home-mobile.png`
- Members / invitation: `launch-members-invited.png`, `launch-members-joined.png`,
  `launch-members-{tablet,mobile}.png`, `launch-invitation-signin.png`,
  `launch-invitation-accepted.png`, `launch-invitation-invalid.png`
- Analysis: `launch-sales-{desktop,laptop,tablet,mobile}.png`, `launch-support-desktop.png`
- Approval: `launch-approval-requester.png`, `launch-approval-approver.png`
- Friendly errors: `launch-outsider-denied.png`, `launch-connector-invalid.png`,
  `launch-connector-duplicate.png`
- Outcomes: `pilot-partial-failed.png`, `pilot-failed-empty.png`, `pilot-unknown.png`

## 5. Reviewer demo script (local, synthetic)

1. Open `/login` and point out the headline, the three capabilities and the invitation-only
   synthetic note. Submit empty to see inline validation, then a wrong password to see the
   friendly error.
2. Sign in as the owner. On **Choose a workspace**, read the explanation, then create
   "Launch Review" and open it. The **Get started** panel appears.
3. Go to **Members** → invite the approver's email as Admin → **Show link** → copy it → **Done**.
4. In a private window, open the link, sign in as the approver and see
   "You've joined Launch Review as Admin". Choose **Open workspace**.
5. Back as the owner: **Analyze synthetic Sales data** → **Prepare plan** → review the steps
   and checks → **Save workflow** → **Run now**. Walk through the KPIs, findings, charts and
   **Source** evidence links. Repeat for Support.
6. On the Sales run, choose the Slack destination → **Send summary to Slack** → **Save
   workflow** → **Run now**. Open **Approvals**: as the requester you see "someone else must
   approve it" and no buttons.
7. As the approver, open **Approvals** and review the destination and the exact message, then
   choose **Approve**. The run completes. In the harness this is the mock transport; nothing
   reaches Slack.
8. As an unrelated user, open the owner's run URL and see one friendly "We couldn't find that".
9. On **Connectors**, enter `#nlw-product-demo` as the channel and paste a webhook URL as the
   secret reference to see both refused. Then use `C0123ABCD` and `SLACK_DEMO_BOT_TOKEN`.

## 6. Limitations and decisions for review

- **Slack examples.** The brief suggested `#nlw-product-demo` and `SLACK_DEMO_WEBHOOK_URL`, but
  the backend needs a channel **ID** (`^[CGD][A-Z0-9]{2,}$`) and a secret holding a **bot
  token** (sent as the Bearer token to `chat.postMessage`), not a webhook URL. The form
  mentions `#nlw-product-demo` only as the channel whose ID to use, and uses
  `SLACK_DEMO_BOT_TOKEN` as the example reference. `SLACK_DEMO_WEBHOOK_URL` would pass the name
  format, but a webhook URL stored under it would fail authentication.
- **Co-member emails** are not shown (see §1). This needs a reviewed migration.
- **Connector 422 responses** still carry Pydantic text in the API body for API clients. The UI
  never renders it: it shows the generic validation copy plus client-side field rules.
- **Evidence drawer** on a run keeps technical step ids and tool names (for example
  `slack.send_message`, `ACTION_OUTCOME_UNKNOWN`) for audit. The run strip and tables still
  show a short 8-character run reference.
- Signup and password reset are intentionally absent (invitation-only pilot).
- Real Slack delivery, staging and production were not exercised.

## 7. Visual refinement (frontend only)

A light enterprise design: a `#F5F7FB` canvas, white surfaces and a compact navy (`#172033`)
sidebar. Colors carry fixed meanings: indigo for primary actions, cyan for data and evidence,
violet only for AI-drafted content, green for ready or completed, amber for approval or
attention, red for failed or denied, and coral for restrained brand emphasis.

No backend behavior, API contract, authorization, tenancy, planner, execution, approval,
dataset, migration, deployment or connector behavior changed. Grounding is unchanged:

- The report's "What changed" and "Needs attention" sections regroup the backend's
  grounded finding text verbatim, with its source links.
- "Recommended actions" lists NLW next steps and is labeled "not conclusions from the data".

| Area | Change |
| --- | --- |
| Sign-in | Form first (and first on mobile), product value on the navy panel beside it. Invitation return and friendly errors are unchanged. |
| Home and onboarding | A prominent question composer (hands the question to New analysis through session storage, never the URL), Sales and Support sample choices, and Staffing shown as unavailable in this pilot. New workspaces also get a guided analysis, sample data, invite and connect actions. |
| Navigation | Grouped as Analyze / Operate / Workspace, with a coral active marker and a drawer on narrow screens. |
| Evidence chain | A small request → plan → approval → execution → result trail on sign-in, onboarding, New analysis and runs. UNKNOWN, failed and partial runs never show as completed. |
| Analytics | White report canvas, a leading KPI, one full-width primary chart followed by paired breakdowns, and series colors ≥ 3:1 on white. |
| Plan review | Separate sections: proposed workflow (with a violet "Drafted by the AI planner" tag), steps, data and connectors, safety checks, next action. |
| Approvals | Requester, destination, connector, policy reason, evidence link and the exact content together. Green Approve and red-outline Reject; the requester sees a note instead of buttons. |
| Failure states | Every panel now states whether anything changed, as well as what happened, the next step and a compact reference. |

Screenshots (`visual/`): sign-in (desktop, mobile), home and onboarding (desktop, mobile), plan
review, Sales report (desktop, tablet, mobile), Support report, members, connector validation,
approval (requester, approver), denied, partial or failed, and outcome unknown.

The top-level `launch-*.png` files in this folder record the interface before this refinement.

Validation for the refinement:

- Prettier, ESLint, tsc and `next build` clean.
- Vitest: 41 files, 244 tests.
- Pilot harness: launch 4, golden 2, failed/partial/UNKNOWN 1; all passed with 0 skipped.

The golden spec's layout check was updated for the new chart layout. It still verifies
tooltip bounds, keyboard chart inspection, reduced motion and the absence of page-level
horizontal scroll at 1440, 1280, 768 and 390 px.

## 8. Correction pass after independent review (F1–F5)

Starting tip `c6d39b8`. Frontend and test changes only; no backend, migration or API-contract file
changed.

| # | Reproduced defect | Root cause | Correction |
| --- | --- | --- | --- |
| F1 | After a genuine `ACTION_OUTCOME_UNKNOWN`, a failed run-summary read (503) made the run page fall back to the persisted run status `FAILED` and show "You can try again now". | The page used `summary.outcome ?? run.status`, so the raw status stood in for the authoritative outcome. | New `lib/run-outcome.ts`: the summary stays the authority. Persisted action evidence can only escalate (`unknown` → UNKNOWN, including over a `FAILED` summary). Without the summary, a raw `FAILED` becomes the neutral `OUTCOME_UNAVAILABLE` ("We can't confirm this run's full outcome"; "Some steps may have run…"; review evidence or ask an administrator; retry "no"). While the first summary read is in flight, the page makes no claim. UNKNOWN or unconfirmed states never get success styling, and the evidence chain marks them amber. An UNKNOWN step's checkpoint now reads "Checkpoint recorded". |
| F2 | A committed connector with a lost response said "Nothing was changed". An approval enqueue failure (503) said both "Decision saved" and "Nothing was changed". | Every error was assumed to mean no mutation, and the 503 explanation hard-coded "Nothing was changed". | Explicit mutation state on each error: `unchanged`, `changed` or `unknown`. The API client now records the HTTP method and turns dropped connections and cut-off bodies into `RequestInterruptedError`. 4xx rejections are `unchanged`. For writes, 5xx (including ambiguous 502–504), `TypeError`, `AbortError` and interrupted requests are `unknown`: "We couldn't confirm whether your change was saved", then check the list or record before retrying, never "try again now". Reads make no mutation claim. The approval enqueue failure is `changed`: "Your decision was saved. Scheduling the run to continue did not complete." Hard-coded "Nothing was changed" and "Nothing was shared" copy was removed. Mutation hooks now refresh their lists after any outcome, so the user can check. |
| F3 | At 768 px, `$280,617.20` wrapped as `$280,617.2` / `0`. | `overflow-wrap: anywhere` on KPI values, and a 4-column grid kept at tablet widths. | KPI values never wrap (`white-space: nowrap`). They size to their own card with container-query units, capped at the previous sizes, and tablets (601–1200 px) use a 2 × 2 KPI block. The dominant first KPI and first chart are unchanged. |
| F4 | Coral 11 px eyebrows were 2.78:1 on the canvas; placeholders were 3.05:1 on white. | Accent colors were used as small text. | Ink tokens for small text: `--coral-ink`, `--primary-ink`, `--success-ink` and `--placeholder`. `--muted` was darkened slightly (`#667085` → `#5f6b7e`) and `--cyan-ink` adjusted, so secondary text passes on every tint. Coral stays decorative. The new token test (`src/app/contrast.test.ts`, 27 pairs) found and fixed four more failing pairs: green badge, Approve button, cyan tag and indigo-tint text. |
| F5 | Hitting the connector cap showed "A connector with this name already exists." | Every 409 was treated as a duplicate name. | The duplicate-name copy appears only for the stable message `a connector with this name already exists`. The cap (`connectors limit of N reached for this workspace`) gets its own workspace-limit copy. Any other 409 gets the generic conflict message, and the raw body is never shown. The API contract was unchanged; both discriminators already existed. |

### Contrast ratios (WCAG, from the real tokens)

| Pair | Before | After |
| --- | --- | --- |
| Coral eyebrow on canvas | 2.78 | 5.32 (`--coral-ink`) |
| Coral eyebrow on white | — | 5.70 |
| PILOT tag on coral tint | — | 5.06 |
| Placeholder on white | 3.05 | 5.40 |
| Secondary text on canvas / white | 4.64 / 4.97 | 5.03 / 5.40 |
| Secondary text on red tint / indigo tint | 4.42 / 4.39 | 4.79 / 4.76 |
| Green badge on green tint | 3.86 | 5.57 |
| Approve (white on green) | 4.33 | 6.24 |
| Cyan tag on cyan tint | 4.47 | 5.33 |
| Indigo text on indigo tint | 4.43 | 5.79 |
| Focus outline on white / canvas (≥ 3:1) | 5.02 / 4.68 | unchanged |

### Tests (all run locally on the final tree)

- Prettier, ESLint (0 warnings), `tsc` and `next build`: clean.
- Vitest: 43 files, 296 tests. New or extended:
  - `run-outcome.test.ts`;
  - run-page summary loading, 503 and undetermined cases;
  - the mutation-state suite (`TypeError`, `AbortError`, interrupted write, 500/502/503/504, validation, 403, approval enqueue, reads);
  - `contrast.test.ts`;
  - connector 409 cases (duplicate, cap, unknown) and the lost-response case.
- Seeded-stack Playwright (local Compose + local Supabase): 8 tests collected in 3 files, no pilot specs; 8 passed, 0 skipped or flaky.
- Pilot harness, 0 skipped in each:
  - launch 4 passed, now including the connector whose response is lost after it commits;
  - golden 2 passed, now asserting every KPI value is one line inside its card at 1440, 1280, 834, 800, 768, 744 and 390 px with no page overflow;
  - failed / partial / UNKNOWN 1 passed, now including a summary 503 after UNKNOWN (and an actions outage giving the neutral unconfirmed state) plus "Checkpoint recorded".
- Backend (no backend file changed): `test_quota_caps.py` (connector cap), `test_approvals_api.py` (including `test_enqueue_failure_returns_503`, unchanged) and `test_connectors_api.py`: 15 passed.

### Screenshots

Every `visual/` screenshot was regenerated, because the token changes visibly alter secondary text,
eyebrows, badges and the Approve button on every screen. `07-sales-report-tablet.png` shows the
2 × 2 KPI block. The two new captures are `17-unknown-with-summary-503.png` and
`18-connector-lost-response.png`.

### Remaining limitations

- The F1 and F2 browser failures are injected in the browser (Playwright route interception).
  The committed-then-lost connector case really commits on the API; only the reply is dropped.
- The KPI no-wrap check runs in Chromium only.
- When the summary itself is unavailable, its own panel still offers the ordinary retry for
  re-reading it. That retry is a read, not the run.

## 9. Final correction pass (B1–B3)

Starting tip `8d8eb18`. Frontend and test changes only; no backend, migration or API-contract file
changed.

### B1 — conservative run-outcome precedence

Reproduced (by code and unit test before the fix):
- Action evidence `unknown` escalated only a `FAILED` summary. With a `COMPLETED`, `PARTIAL` or
  `IN_PROGRESS` summary it showed that less-cautious state, including a green COMPLETED badge.
- Raw `FAILED` was shown while the summary was still loading.
- With both summary and action reads failed, the page showed the raw run status.

The precedence rule (`lib/run-outcome.ts`), most conservative first:
1. Any persisted action with status `unknown` gives UNKNOWN, whatever the summary says.
2. A summary outcome that is itself UNKNOWN.
3. Summary or action evidence still loading gives `OUTCOME_PENDING`: "Checking this run's recorded
   outcome…", a neutral badge, and no claim of failure, success, mutation or retry.
4. The deterministic summary, once it and the action evidence are read. If only the action read
   failed, the summary stays authoritative, because the backend derives it from the same action rows.
5. Otherwise `OUTCOME_UNAVAILABLE`: "We can't confirm this run's full outcome", "Some steps may have
   run…", and check the evidence or ask an administrator.

Raw run status is never presented as the outcome.

When the outcome is cautious (UNKNOWN, pending or unconfirmed):
- a less-cautious summary card is set aside, with a visible note;
- the analytics badge shows the cautious outcome;
- sharing is withheld;
- a step with an unknown action shows an UNKNOWN badge and "Checkpoint recorded".

A failed evidence read offers **Reload run evidence**, labelled "This only reloads what NLW has
recorded. It doesn't run the workflow again." Backend execution, persistence and resend semantics are
unchanged.

### B2 — no unsafe HTTP 500 copy

Reproduced: a write-side 500 composed "The request didn't complete. It's safe to try again." with
"We couldn't confirm whether your change was saved."

Copy changes:
- The generic `server` and `unexpected` explanations now make no completion, safety or no-change
  claim.
- Write-side 5xx banners are fully composed as: unconfirmed; check the relevant list or record
  before trying again; "Don't repeat it until you've checked."
- Failed reads say "Try loading it again", with read-specific retry text.
- Endpoint contracts that settle the state are encoded as known messages:
  - planner 503/502 → unchanged (plans.py raises before any proposal row);
  - approval enqueue failure → changed ("Your decision was saved. Scheduling the run to continue
    did not complete.");
  - "run created but could not be scheduled" → changed ("The run was created… Don't start it
    again.").

### B3 — large KPI values stay legible

Reproduced: the contract accepts any finite value in ±1e12, and exact forms such as
`-$1,000,000,000,000.00` exceed a KPI card and clipped.

Policy (`kpiDisplay` in `lib/analytics-presentation.ts`):
- An exact form of at most 11 characters is shown unchanged (`$280,617.20`, `49.79%`, `$0.00`,
  "Unavailable" for null).
- Longer values show compact notation to 2 decimals (`$12.35B`, `-$1.00T`, `1.00T%`), marked
  "· rounded".
- The exact value stays available three ways:
  1. screen-reader text inside the value;
  2. a `title` for pointer users;
  3. a keyboard-reachable **Exact value** disclosure whose digits break only at thousands
     separators.
- Every value the contract accepts fits the 11-character budget; a unit test enumerates the
  boundaries.

### Tests (local, final tree)

- Prettier, ESLint (0 warnings), `tsc` and `next build`: clean.
- Vitest: 43 files, 348 tests, including:
  - UNKNOWN against 11 summary outcomes;
  - delayed summary or actions with raw FAILED/COMPLETED;
  - both reads unavailable with raw FAILED/COMPLETED;
  - fully composed banners for POST/PATCH/PUT/DELETE 500, write 502/503/504, GET 500, the known
    changed and unchanged cases, and validation;
  - KPI values for normal, long positive and negative, ±1e12 boundaries, large percentage, zero
    and null.
- Seeded-stack Playwright: 8 tests in 3 files, no pilot specs; 8 passed, 0 skipped, flaky or
  failed.
- Pilot harness, 0 skipped in each:
  - launch 4 passed, including a connector that commits and then gets a 500 (the refreshed list
    shows it; the banner has no "safe to try again", "request didn't complete" or "nothing was
    changed");
  - golden 2 passed, now including contract-boundary KPI values at 1440, 1280, 834, 800, 768,
    744 and 390 px (each shown value one line inside its card, exact value accessible, keyboard
    disclosure inside the card, dominant chart unchanged, no page overflow);
  - failed / partial / UNKNOWN 1 passed, now including UNKNOWN action evidence against rewritten
    COMPLETED and PARTIAL summaries, and the summary 503 after UNKNOWN.
- Backend (unchanged files): `test_quota_caps.py`, `test_approvals_api.py` and
  `test_connectors_api.py`: 15 passed.

### Screenshots

New:
- `visual/19-unknown-vs-conflicting-summary.png`
- `visual/20-kpi-boundary-desktop.png`
- `visual/21-kpi-boundary-mobile.png`

No existing screenshot changed materially: ordinary values render exactly as before.

### Remaining limitations

- The conflicting-summary, boundary-value and 500 scenarios are produced by rewriting real
  responses in the browser (Playwright routing); the backend never emits those combinations
  itself.
- The summary stays authoritative when only the action-evidence read fails.
- Browser checks run in Chromium only.

## 10. Exact-value precision correction

Starting tip `b52b9b9`. Frontend and test changes only.

**Reproduction.** Input `12345678.123456` in hours showed the compact form `12.35M h` (correct,
labelled rounded). The "Exact value" disclosure, screen-reader text and title all showed
`12,345,678.12 h`, silently dropping accepted precision.

**Root cause.** The exact representation reused the two-decimal display formatter
(`formatValue`, `maximumFractionDigits: 2`).

**Compact display vs. exact parsed value.**
- The **display** stays as before: the two-decimal form when it fits 11 characters, otherwise
  compact notation (`$12.35B`, `-$1.00T`).
- A value is marked **rounded** whenever the display differs from the exact value. Besides
  compact values, this now includes short values with hidden precision, such as `0.12 h` for
  `0.123456789`.
- The **exact value** comes from a separate formatter, `exactValue`:
  1. It takes the number's shortest round-trippable decimal form (`String(value)`), which adds no
     floating-point noise and forces no fixed precision.
  2. It expands exponent forms (`1e-7`, `5e-324`) by exact digit shifting.
  3. It splits sign, integer and fraction, and groups only the integer part.
  4. It keeps every fractional digit.
  5. Currency is padded to at least two decimals, which never changes the value.
  6. `-0` reads as `0`.
- This preserves the parsed JavaScript number, not the original JSON spelling (`1.2300` and `1.23`
  are the same number after parsing).

**Accessibility.**
- The exact value is announced once, as screen-reader text in place of the rounded display, and is
  also the `title`.
- The keyboard-reachable **Exact value** disclosure repeats it visually; its copy is `aria-hidden`,
  so it isn't announced twice.
- Digits break only after thousands separators and after every third fractional digit, so even a
  subnormal's long fraction stays inside the card.

**Regression values**, each checked in USD, hours and percent:
- `12345678.123456` and `-12345678.123456`;
- `0.123456789` and `-0.123456789`;
- `999999999999.9999` and `-999999999999.9999`;
- `0` and `-0`;
- the integers `1257` and `-1e12`;
- `null`.

A round-trip test confirms each exact form parses back to the same number, and the exponent cases
cover `1e-7`, `-1.5e-7` and `5e-324`.

**Tests (local, final tree).**
- Prettier, ESLint (0 warnings), `tsc` and `next build`: clean.
- Vitest: 43 files, 363 tests; the focused presentation and result tests are 62 of these.
- Golden Sales/Support pilot journey: 2 passed, 0 skipped. It now renders `-$999,999,999,999.9999`,
  `12,345,678.123456 h`, `-$12,345,678.123456` and `0.123456789%` in the real page. At 1440, 1280,
  834, 800, 768, 744 and 390 px it checks:
  - the displayed value is one line inside its card;
  - the screen-reader text and title equal the full-precision exact value;
  - every disclosure (the first opened by keyboard) shows it completely inside its card;
  - there is no page overflow;
  - the dominant chart layout is unchanged.
- The seeded-stack suite was not rerun. This change touches only KPI rendering on analytics result
  pages, and none of the 8 seeded tests renders an analytics result. Their earlier pass at
  `b52b9b9` still holds.

**Screenshots replaced:** `visual/20-kpi-boundary-desktop.png` and
`visual/21-kpi-boundary-mobile.png`, which now show exact values with more than two fractional
digits.
