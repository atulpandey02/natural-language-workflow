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
