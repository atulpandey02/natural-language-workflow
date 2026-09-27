import { test, expect, type Browser, type Page } from "@playwright/test";
import { env, requireEnv, signIn } from "./helpers";

// Launch-closure journeys, run through the isolated pilot harness
// (tests/integration/test_pilot_browser.py + e2e/launch_journeys_plugin.py):
// real local Supabase auth, API, feasibility, queue, worker and database; the
// planner is the harness's controlled provider and Slack is its mock transport.
// All data is synthetic. Screenshots land in test-results/launch-*.png.

const SHOT = "test-results/launch";
const VIEWPORTS = {
  desktop: { width: 1440, height: 900 },
  laptop: { width: 1280, height: 800 },
  tablet: { width: 768, height: 1024 },
  mobile: { width: 390, height: 844 },
} as const;

const approverEmail = () => process.env.E2E_APPROVER_EMAIL!;
const approverPassword = () => process.env.E2E_APPROVER_PASSWORD!;
const otherEmail = () => process.env.E2E_OTHER_EMAIL!;
const otherPassword = () => process.env.E2E_OTHER_PASSWORD!;

async function noHorizontalScroll(page: Page) {
  await expect
    .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
    .toBe(true);
}

/** Sign in through the form only (no workspace selection), as an invitee would. */
async function signInForm(page: Page, email: string, password: string) {
  await page.getByLabel("Work email").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
}

/** Plan → save → run a sample dataset analysis; returns the run id. */
async function analyze(page: Page, dataset: "sales-v1" | "support-v1") {
  await page.goto(`/workflows/new?dataset=${dataset}`);
  await expect(page.getByLabel(/what should this workflow do/i)).toContainText(dataset);
  const plan = page.getByRole("button", { name: "Prepare plan" });
  await plan.click();
  await expect(page.locator('[data-status="PASS"]')).toBeVisible({ timeout: 30000 });
  await expect(page.getByTestId("plan-status-copy")).toContainText("All checks passed");
  await page.getByRole("button", { name: "Save workflow" }).click();
  await expect(page).toHaveURL(/\/workflows\/[0-9a-f-]{36}$/);
  await page.getByRole("button", { name: /run now/i }).click();
  await expect(page).toHaveURL(/\/runs\/[0-9a-f-]{36}$/);
  await expect(page.getByTestId("analytics-result")).toBeVisible({ timeout: 30000 });
  await expect(page.getByTestId("analytics-result")).toContainText("Synthetic");
  return page.url().split("/runs/")[1];
}

async function newPage(browser: Browser) {
  const context = await browser.newContext();
  return { context, page: await context.newPage() };
}

test.describe("launch closure journeys (synthetic pilot)", () => {
  test.beforeEach(() => {
    requireEnv(
      process.env.E2E_PILOT === "1" && Boolean(process.env.E2E_APPROVER_EMAIL),
      "requires the isolated pilot provider/worker harness",
    );
  });

  // Runs first: the approver's only workspace is still the pre-seeded one.
  test("requester cannot self-approve; a second admin approves (mock delivery)", async ({
    page,
    browser,
  }) => {
    test.setTimeout(150000);
    await page.setViewportSize(VIEWPORTS.desktop);
    await signIn(page, env.adminEmail, env.adminPassword);
    const sourceRun = await analyze(page, "sales-v1");

    await page.getByLabel("Slack destination").selectOption({ label: "pilot-slack · CPILOT" });
    await page.getByRole("button", { name: "Send summary to Slack" }).click();
    await expect(page.locator('[data-status="NEEDS_APPROVAL"]')).toBeVisible();
    await page.getByRole("button", { name: "Save workflow" }).click();
    await page.getByRole("button", { name: /run now/i }).click();
    await expect(page.locator('[data-status="WAITING_APPROVAL"]').first()).toBeVisible({
      timeout: 30000,
    });
    const slackRun = page.url().split("/runs/")[1];

    // (6) The requester sees why they can't approve, and has no controls.
    await page.goto("/approvals");
    const mine = page.locator(".card", { hasText: "Share to Slack" });
    await expect(mine.getByRole("note")).toContainText("someone else must approve it");
    await expect(mine.getByRole("button", { name: "Approve" })).toHaveCount(0);
    await expect(mine).toContainText("Requested by you");
    await expect(mine).not.toContainText(/[0-9a-f]{8}-[0-9a-f]{4}-/);
    await page.screenshot({ path: `${SHOT}-approval-requester.png`, fullPage: true });

    // (7) A different admin reviews the exact message and approves it.
    const { context, page: approver } = await newPage(browser);
    await approver.setViewportSize(VIEWPORTS.desktop);
    await signIn(approver, approverEmail(), approverPassword());
    await approver.goto("/approvals");
    const card = approver.locator(".card", { hasText: "Share to Slack" });
    await expect(card).toContainText("CPILOT");
    await expect(card).toContainText("Requested by another workspace member");
    await expect(approver.getByLabel("Exact message to be sent")).toContainText(
      "Revenue: 280617.2 USD",
    );
    await approver.screenshot({ path: `${SHOT}-approval-approver.png`, fullPage: true });
    await card.getByRole("button", { name: "Approve" }).click();
    await expect(approver.getByText("No pending approvals.")).toBeVisible({ timeout: 15000 });
    await context.close();

    await page.goto(`/runs/${slackRun}`);
    await expect(page.locator('[data-status="COMPLETED"]').first()).toBeVisible({
      timeout: 30000,
    });
    expect(sourceRun).not.toBe(slackRun);
  });

  test("sign-in, onboarding, invitation, joining and outsider denial", async ({
    page,
    browser,
  }) => {
    test.setTimeout(180000);

    // Sign-in page at every target viewport.
    await page.goto("/login");
    await expect(
      page.getByRole("heading", { name: "Turn business questions into governed workflows" }),
    ).toBeVisible();
    await expect(page.getByTestId("pilot-note")).toContainText("synthetic");
    for (const [name, size] of Object.entries(VIEWPORTS)) {
      await page.setViewportSize(size);
      await noHorizontalScroll(page);
      await page.screenshot({ path: `${SHOT}-login-${name}.png`, fullPage: true });
    }
    await page.setViewportSize(VIEWPORTS.desktop);

    // Friendly auth error, never the provider's text.
    await signInForm(page, env.adminEmail, "not-the-password");
    await expect(page.getByTestId("login-error")).toContainText("Email or password is incorrect");
    await expect(page.getByTestId("login-error")).not.toContainText("Invalid login credentials");
    await page.screenshot({ path: `${SHOT}-login-error.png` });

    // (1) The requester creates a new workspace from onboarding.
    await signIn(page, env.adminEmail, env.adminPassword);
    await page.goto("/select-workspace");
    await expect(page.getByText(/A workspace is your team/)).toBeVisible();
    await expect(page.getByRole("list", { name: "How NLW works" })).toContainText("Evidence");
    await page.screenshot({ path: `${SHOT}-onboarding-select.png`, fullPage: true });
    await page.getByRole("button", { name: "Create and open" }).click();
    await expect(page.getByText("Give your workspace a name.")).toBeVisible();
    await page.getByLabel("Workspace name").fill("Launch Review (synthetic)");
    await page.getByRole("button", { name: "Create and open" }).click();
    await page.waitForURL(/\/$/, { timeout: 15000 });
    const started = page.getByTestId("get-started");
    await expect(started).toBeVisible();
    await expect(started.getByRole("link", { name: /Invite a teammate/ })).toBeVisible();
    await expect(page.getByTestId("pilot-limits")).toContainText("synthetic");
    await page.screenshot({ path: `${SHOT}-onboarding-home.png`, fullPage: true });

    // (2) The owner invites the approver as an admin.
    await page.goto("/members");
    const invite = page.getByRole("form", { name: "Invite someone" });
    await invite.getByRole("button", { name: /create invitation/i }).click();
    await expect(invite.getByText("Enter the email address they sign in with.")).toBeVisible();
    await invite.getByLabel("Email address").fill(approverEmail());
    await invite.getByLabel("Role").selectOption("admin");
    await invite.getByRole("button", { name: /create invitation/i }).click();
    const created = page.getByTestId("invitation-created");
    await expect(created).toBeVisible();
    await expect(page.getByTestId("invitation-link")).toHaveCount(0); // hidden by default
    await page.screenshot({ path: `${SHOT}-members-invited.png`, fullPage: true });
    await created.getByRole("button", { name: "Show link" }).click();
    const link = await page.getByTestId("invitation-link").inputValue();
    await created.getByRole("button", { name: "Done" }).click();
    await expect(page.getByTestId("invitation-row")).toHaveCount(1);
    await expect(page.locator("main")).not.toContainText(/[0-9a-f]{8}-[0-9a-f]{4}-/);

    // (3) The approver opens the link signed out, signs in, and joins.
    const invitee = await newPage(browser);
    await invitee.page.setViewportSize(VIEWPORTS.desktop);
    await invitee.page.goto(link);
    await expect(invitee.page).toHaveURL(/\/login$/); // token scrubbed from the bar
    await expect(
      invitee.page.getByRole("heading", { name: "Sign in to accept your invitation" }),
    ).toBeVisible();
    await invitee.page.screenshot({ path: `${SHOT}-invitation-signin.png` });
    await signInForm(invitee.page, approverEmail(), approverPassword());
    const accepted = invitee.page.getByTestId("invitation-accepted");
    await expect(accepted).toContainText("You’ve joined Launch Review (synthetic) as Admin", {
      timeout: 15000,
    });
    await expect(invitee.page).toHaveURL(/\/invitations\/accept$/);
    await invitee.page.screenshot({ path: `${SHOT}-invitation-accepted.png` });
    await invitee.page.getByRole("button", { name: "Open workspace" }).click();
    await invitee.page.waitForURL(/\/$/, { timeout: 15000 });
    await invitee.context.close();

    await page.reload();
    await expect(page.getByTestId("member-row")).toHaveCount(2);
    await expect(page.getByTestId("invitation-row")).toHaveCount(0);
    await page.screenshot({ path: `${SHOT}-members-joined.png`, fullPage: true });

    // (4) Sales analysis in the new workspace.
    const salesRun = await analyze(page, "sales-v1");
    await expect(page.getByTestId("analytics-kpi").first()).toContainText("$280,617.20");
    for (const [name, size] of Object.entries(VIEWPORTS)) {
      await page.setViewportSize(size);
      await noHorizontalScroll(page);
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: `${SHOT}-sales-${name}.png`, fullPage: name === "desktop" });
    }
    await page.setViewportSize(VIEWPORTS.desktop);

    // (5) Support analysis.
    await analyze(page, "support-v1");
    await expect(page.getByRole("heading", { name: "SLA compliance trend" })).toBeVisible();
    await page.screenshot({ path: `${SHOT}-support-desktop.png`, fullPage: true });

    // (8) An outsider gets friendly denial — for data and for the used link.
    const outsider = await newPage(browser);
    await outsider.page.setViewportSize(VIEWPORTS.desktop);
    await signIn(outsider.page, otherEmail(), otherPassword());
    const api = await outsider.page.evaluate(async (id) => {
      const r = await fetch(`/api/nlw/runs/${id}/analytics`);
      return { status: r.status, body: await r.text() };
    }, salesRun);
    expect(api.status).toBe(404);
    expect(api.body).not.toContain("Revenue");
    await outsider.page.goto(`/runs/${salesRun}`);
    const denied = outsider.page.getByTestId("friendly-error").first();
    await expect(denied).toContainText("We couldn't find that");
    await expect(outsider.page.getByTestId("analytics-result")).toHaveCount(0);
    await outsider.page.screenshot({ path: `${SHOT}-outsider-denied.png` });
    await outsider.page.goto(link);
    await expect(outsider.page.getByTestId("invitation-failed")).toBeVisible({ timeout: 15000 });
    await expect(outsider.page.getByTestId("invitation-failed")).not.toContainText(approverEmail());
    await outsider.page.screenshot({ path: `${SHOT}-invitation-invalid.png` });
    await outsider.context.close();
  });

  test("connector form: invalid input is explained, credentials are refused", async ({ page }) => {
    await page.setViewportSize(VIEWPORTS.desktop);
    await signIn(page, env.adminEmail, env.adminPassword);
    await page.goto("/connectors");
    await expect(page.getByLabel("Type")).toHaveValue("slack");
    await page.getByLabel("Name").fill("product-slack");
    await page.getByLabel("Slack workspace").fill("NLW Product Demo");
    await page.getByLabel("Default channel ID").fill("#nlw-product-demo");
    await page.getByLabel("Secret reference").fill("https://hooks.slack.com/services/T0/B0/XYZ");
    await page.getByRole("button", { name: "Create connector" }).click();
    await expect(page.getByText(/Use the channel ID, not its name/)).toBeVisible();
    await expect(page.getByText(/That looks like a credential/)).toBeVisible();
    await expect(page.getByLabel("Secret reference")).toHaveValue("");
    await expect(page.locator("main")).not.toContainText("hooks.slack.com");
    await expect(page.getByTestId("slack-scope-note")).toContainText("Alertmanager");
    await page.screenshot({ path: `${SHOT}-connector-invalid.png`, fullPage: true });

    // A valid connector is accepted; the same name again is a friendly field error.
    await page.getByLabel("Default channel ID").fill("C0123ABCD");
    await page.getByLabel("Secret reference").fill("SLACK_DEMO_BOT_TOKEN");
    await page.getByRole("button", { name: "Create connector" }).click();
    await expect(page.getByText(/“product-slack” added/)).toBeVisible();
    await expect(page.getByRole("cell", { name: "product-slack", exact: true })).toBeVisible();
    await page.getByLabel("Name").fill("product-slack");
    await page.getByLabel("Slack workspace").fill("NLW Product Demo");
    await page.getByLabel("Default channel ID").fill("C0123ABCD");
    await page.getByLabel("Secret reference").fill("SLACK_DEMO_BOT_TOKEN");
    const post = page.waitForResponse(
      (r) => r.url().endsWith("/api/nlw/connectors") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Create connector" }).click();
    expect((await post).status()).toBe(409);
    await expect(page.getByText("A connector with this name already exists.")).toBeVisible();
    await expect(page.locator("main")).not.toContainText(/uq_connector|IntegrityError|psycopg/);
    await page.screenshot({ path: `${SHOT}-connector-duplicate.png`, fullPage: true });

    // F2: the server commits the connector but the response never arrives.
    // The UI must not claim nothing changed, and the refreshed list shows the truth.
    await page.route("**/api/nlw/connectors", async (route) => {
      if (route.request().method() !== "POST") return route.fallback();
      await route.fetch(); // the request reaches the API and commits
      await route.abort("connectionreset"); // …but the browser never gets the reply
    });
    await page.getByLabel("Name").fill("committed-slack");
    await page.getByLabel("Slack workspace").fill("NLW Product Demo");
    await page.getByLabel("Default channel ID").fill("C0123ABCD");
    await page.getByLabel("Secret reference").fill("SLACK_DEMO_BOT_TOKEN");
    await page.getByRole("button", { name: "Create connector" }).click();
    const lost = page.getByTestId("friendly-error");
    await expect(lost).toContainText("We couldn't confirm whether your change was saved.");
    await expect(lost).toContainText("check the relevant list or record before trying again");
    await expect(lost).not.toContainText("Nothing was changed");
    await page.unroute("**/api/nlw/connectors");
    await expect(page.getByRole("cell", { name: "committed-slack", exact: true })).toBeVisible({
      timeout: 15000,
    });
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    await page.screenshot({ path: `${SHOT}-connector-lost-response.png`, fullPage: true });

    // B2: the connector commits, but the browser receives a 500 instead of the reply.
    await page.route("**/api/nlw/connectors", async (route) => {
      if (route.request().method() !== "POST") return route.fallback();
      await route.fetch(); // commits on the API
      await route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({
          error: { code: "internal_error", message: "internal server error" },
        }),
      });
    });
    await page.getByLabel("Name").fill("committed-500-slack");
    await page.getByRole("button", { name: "Create connector" }).click();
    const ambiguous = page.getByTestId("friendly-error");
    await expect(ambiguous).toContainText("We couldn't confirm whether your change was saved.");
    await expect(ambiguous).toContainText("Don't repeat it until you've checked.");
    for (const unsafe of [
      /safe to try again/i,
      /request didn.t complete/i,
      /nothing was changed/i,
      /try again now/i,
    ]) {
      await expect(ambiguous).not.toContainText(unsafe);
    }
    await page.unroute("**/api/nlw/connectors");
    await expect(page.getByRole("cell", { name: "committed-500-slack", exact: true })).toBeVisible({
      timeout: 15000,
    });
  });

  test("mobile and keyboard: sign in and navigate without a pointer", async ({ page }) => {
    await page.setViewportSize(VIEWPORTS.mobile);
    await page.goto("/login");
    await page.keyboard.press("Tab"); // skip link or first control
    const focusOrder: string[] = [];
    for (let i = 0; i < 6; i++) {
      focusOrder.push(
        await page.evaluate(() => {
          const el = document.activeElement as HTMLElement | null;
          return el ? `${el.tagName}:${el.id || el.textContent?.trim() || ""}` : "";
        }),
      );
      await page.keyboard.press("Tab");
    }
    const email = focusOrder.findIndex((f) => f === "INPUT:email");
    const password = focusOrder.findIndex((f) => f === "INPUT:password");
    const toggle = focusOrder.findIndex((f) => f.startsWith("BUTTON:Show"));
    const submit = focusOrder.findIndex((f) => f === "BUTTON:Sign in");
    expect(email).toBeGreaterThanOrEqual(0);
    expect(password).toBeGreaterThan(email);
    expect(toggle).toBeGreaterThan(password);
    expect(submit).toBeGreaterThan(toggle);

    await page.getByLabel("Work email").focus();
    await page.keyboard.type(env.adminEmail);
    await page.keyboard.press("Tab");
    await page.keyboard.type(env.adminPassword);
    await page.keyboard.press("Tab");
    await page.keyboard.press("Enter"); // show password
    await expect(page.getByLabel("Password", { exact: true })).toHaveAttribute("type", "text");
    await page.keyboard.press("Enter"); // hide again
    await expect(page.getByLabel("Password", { exact: true })).toHaveAttribute("type", "password");
    await page.getByLabel("Password", { exact: true }).press("Enter"); // submit from the field
    await page.waitForURL(/\/select-workspace$/, { timeout: 15000 });
    await expect(page.getByTestId("workspace-ready")).toBeVisible();
    await noHorizontalScroll(page);
    await page.screenshot({ path: `${SHOT}-select-workspace-mobile.png`, fullPage: true });
    // Open a workspace with the keyboard.
    await page.getByRole("button", { name: "Open", exact: true }).first().focus();
    await page.keyboard.press("Enter");
    await page.waitForURL(/\/$/, { timeout: 15000 });
    await noHorizontalScroll(page);
    await page.screenshot({ path: `${SHOT}-home-mobile.png`, fullPage: true });

    // The focused control is visibly outlined.
    await page.keyboard.press("Tab");
    const outline = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null;
      if (!el || el === document.body) return "none";
      const s = getComputedStyle(el);
      return `${s.outlineStyle}|${s.boxShadow}`;
    });
    expect(outline).not.toBe("none|none");

    for (const path of ["/members", "/connectors", "/approvals", "/workflows/new"]) {
      await page.goto(path);
      await expect(page.locator("main").first()).toBeVisible();
      await noHorizontalScroll(page);
    }
    await page.goto("/members");
    await expect(page.getByTestId("member-row").first()).toBeVisible();
    await noHorizontalScroll(page);
    await page.screenshot({ path: `${SHOT}-members-mobile.png`, fullPage: true });
    await page.setViewportSize(VIEWPORTS.tablet);
    await noHorizontalScroll(page);
    await page.screenshot({ path: `${SHOT}-members-tablet.png`, fullPage: true });
  });
});
