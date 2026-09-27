import { test, expect, type Page } from "@playwright/test";
import { env, requireEnv, signIn } from "./helpers";

async function assertLayout(page: Page, width: number, height: number) {
  await page.setViewportSize({ width, height });
  await expect
    .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
    .toBe(true);
  const charts = page.getByTestId("analytics-chart");
  const first = await charts.nth(0).boundingBox();
  const second = await charts.nth(1).boundingBox();
  const third = await charts.nth(2).boundingBox();
  expect(first).not.toBeNull();
  expect(second).not.toBeNull();
  expect(third).not.toBeNull();
  // One dominant visualization across the report, then supporting breakdowns.
  expect(second!.y).toBeGreaterThan(first!.y + first!.height);
  if (width > 600) {
    expect(first!.width).toBeGreaterThan(second!.width * 1.8);
    expect(Math.abs(second!.y - third!.y)).toBeLessThan(2);
  } else {
    expect(third!.y).toBeGreaterThan(second!.y + second!.height);
    expect(first!.width).toBeGreaterThan(320);
    expect(Math.abs(first!.width - second!.width)).toBeLessThan(2);
  }
  await expect(page.locator(".workflow-details")).not.toHaveAttribute("open", "");
}

async function inspectRevenue(page: Page) {
  const chart = page.getByTestId("analytics-chart").first();
  await chart.locator(".recharts-line-dot").nth(2).hover();
  await expect(chart.getByRole("status")).toContainText("$47,090.65");
  const svg = chart.locator('svg[role="application"]');
  await svg.focus();
  await page.keyboard.press("ArrowRight");
  await expect(svg).toHaveCSS("outline-style", "solid");
  const tooltip = chart.getByRole("status");
  await expect(tooltip).toBeVisible();
  await expect(tooltip).toContainText("Revenue");
  const label = await tooltip.locator(":scope > strong").textContent();
  const values: Record<string, string> = {
    "2026-03": "$40,647.45",
    "2026-04": "$47,522.80",
    "2026-05": "$47,090.65",
    "2026-06": "$43,789.15",
    "2026-07": "$53,931.15",
    "2026-08": "$47,636.00",
  };
  await expect(tooltip.locator("b")).toHaveText(values[label!]);
  const box = await tooltip.boundingBox();
  const viewport = page.viewportSize()!;
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.width);
  await expect(tooltip.locator(".series-mark")).toHaveCSS("background-color", "rgb(24, 150, 167)");
}

test.describe("synthetic pilot golden analytics", () => {
  test("sign in → plan → materialize → real worker → evidence → bound Slack proposal", async ({
    page,
    browser,
  }) => {
    requireEnv(
      process.env.E2E_PILOT === "1",
      "requires the isolated pilot provider/worker harness",
    );
    test.setTimeout(120000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await signIn(page, env.adminEmail, env.adminPassword);
    await page.goto("/workflows/new");
    await page.getByRole("button", { name: /Sales operations/ }).click();
    await expect(page.getByLabel(/what should this workflow do/i)).toContainText("sales-v1");
    await page.getByRole("button", { name: /^Prepare plan$/ }).click();
    await expect(page.getByText("Analyze synthetic sales data", { exact: true })).toBeVisible();
    await expect(page.locator('[data-status="PASS"]')).toBeVisible();
    await page.screenshot({ path: "test-results/pilot-proposal-desktop.png", fullPage: true });
    await page.getByRole("button", { name: "Save workflow" }).click();
    await expect(page).toHaveURL(/\/workflows\/[0-9a-f-]{36}$/);
    const initial = page.waitForResponse(
      (r) => /\/workflows\/[0-9a-f-]+\/runs$/.test(r.url()) && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: /run now/i }).click();
    const started = await (await initial).json();
    expect(started.status).toBe("PENDING");
    await expect(page).toHaveURL(/\/runs\/[0-9a-f-]{36}$/);
    const runId = page.url().split("/runs/")[1];
    await expect(page.getByTestId("analytics-result")).toBeVisible({ timeout: 30000 });
    await expect(page.getByTestId("analytics-kpi")).toHaveCount(4);
    await expect(page.getByTestId("analytics-chart")).toHaveCount(4);
    await expect(page.getByRole("heading", { name: "What changed" })).toBeVisible();
    await expect(page.getByText(/Accessories revenue declined/)).toBeVisible();
    await expect(page.locator('svg.recharts-surface[role="application"]')).toHaveCount(4);
    const monthly = page
      .locator(".supporting-table > summary")
      .filter({ hasText: "Monthly supporting data" });
    await monthly.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("table", { name: "Monthly supporting data" })).toBeVisible();
    await expect(page.getByTestId("analytics-kpi").first()).toContainText("$280,617.20");
    await assertLayout(page, 1440, 900);
    await expect(page.locator(".table-scroll-cue")).toHaveCount(0);
    await page.emulateMedia({ reducedMotion: "reduce" });
    await expect(page.getByRole("button", { name: "Toggle Revenue" }).first()).toHaveCSS(
      "transition-duration",
      "0s",
    );
    await page.emulateMedia({ reducedMotion: "no-preference" });
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: "test-results/pilot-sales-desktop.png", fullPage: true });
    await page.screenshot({ path: "test-results/pilot-sales-desktop-viewport.png" });
    await inspectRevenue(page);
    await page
      .getByTestId("analytics-chart")
      .first()
      .screenshot({ path: "test-results/pilot-tooltip.png" });
    await page.getByRole("heading", { name: "Sales performance" }).click();
    await assertLayout(page, 1280, 800);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: "test-results/pilot-sales-laptop.png", fullPage: true });
    await page.getByRole("link", { name: "analyze", exact: true }).first().click();
    await expect(page.locator("#evidence-analyze")).toBeVisible();
    await expect(page.locator('#evidence-analyze [data-status="SUCCESS"]')).toBeVisible();
    await page.setViewportSize({ width: 768, height: 1024 });
    await expect(page.locator(".sidebar")).not.toHaveAttribute("open", "");
    await assertLayout(page, 768, 1024);
    await expect(page.locator(".workflow-details")).not.toHaveAttribute("open", "");
    await page.locator(".sidebar > summary").click();
    await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.locator(".sidebar")).not.toHaveAttribute("open", "");
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: "test-results/pilot-sales-tablet.png", fullPage: true });
    await assertLayout(page, 390, 844);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: "test-results/pilot-sales-mobile.png", fullPage: true });
    const mobileTable = page.getByRole("region", { name: "Monthly supporting data" });
    const month = mobileTable.getByRole("rowheader", { name: "2026-03", exact: true });
    await expect(month).toHaveCSS("white-space", "nowrap");
    expect(
      await month.evaluate((cell) => {
        const range = document.createRange();
        range.selectNodeContents(cell);
        return range.getClientRects().length;
      }),
    ).toBe(1);
    await expect(mobileTable).toHaveAccessibleDescription(
      "More columns: scroll horizontally or use ← / → when focused.",
    );
    await expect(mobileTable).toHaveAttribute("tabindex", "0");
    expect(await mobileTable.evaluate((region) => region.scrollWidth > region.clientWidth)).toBe(
      true,
    );
    await mobileTable.focus();
    await page.keyboard.press("ArrowRight");
    await expect.poll(() => mobileTable.evaluate((region) => region.scrollLeft)).toBeGreaterThan(0);
    await mobileTable.evaluate((region) => {
      region.scrollLeft = 0;
    });
    await page.locator(".supporting-table").first().scrollIntoViewIfNeeded();
    await page.screenshot({ path: "test-results/pilot-sales-mobile-table.png" });
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await inspectRevenue(page);
    await page
      .getByTestId("analytics-chart")
      .first()
      .screenshot({ path: "test-results/pilot-tooltip-mobile.png" });
    await page.getByRole("heading", { name: "Sales performance" }).click();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await page.getByRole("link", { name: "analyze", exact: true }).first().click();
    await expect(page.locator("#evidence-analyze")).toBeVisible();
    await page.screenshot({ path: "test-results/pilot-evidence-mobile.png" });
    await page.locator(".workflow-details > summary").click();
    await expect(page.locator(".workflow-details")).not.toHaveAttribute("open", "");
    await page.getByRole("link", { name: "analyze", exact: true }).first().click();
    await page.keyboard.press("Escape");
    await expect(page.locator(".workflow-details")).not.toHaveAttribute("open", "");
    await page.setViewportSize({ width: 1440, height: 900 });

    // Separate tenant signs in through the same real auth + BFF path.
    const outsider = await browser.newContext();
    const otherPage = await outsider.newPage();
    await signIn(otherPage, process.env.E2E_OTHER_EMAIL!, process.env.E2E_OTHER_PASSWORD!);
    const denied = await otherPage.evaluate(async (id) => {
      const response = await fetch(`/api/nlw/runs/${id}/analytics`);
      return { status: response.status, body: await response.text() };
    }, runId);
    expect(denied.status).toBe(404);
    expect(denied.body).not.toContain("Revenue");
    await outsider.close();

    await page.getByLabel("Slack destination").selectOption({ label: "pilot-slack · CPILOT" });
    const proposed = page.waitForResponse(
      (r) => r.url().endsWith(`/runs/${runId}/slack-proposal`) && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Send summary to Slack" }).click();
    const immutable = await (await proposed).json();
    await expect(page.getByRole("heading", { name: "Exact message for approval" })).toBeVisible();
    await expect(page.locator('[data-status="NEEDS_APPROVAL"]')).toBeVisible();
    expect(await page.getByLabel("Immutable Slack message").textContent()).toBe(
      immutable.proposed_plan.steps[0].args.text,
    );
    await expect(page.locator(".message-destination strong")).toHaveText(
      immutable.analytics_source.channel,
    );
    await expect(page.getByRole("link", { name: "Open source analysis run" })).toHaveAttribute(
      "href",
      `/runs/${runId}`,
    );
    await page
      .locator(".handoff-review")
      .screenshot({ path: "test-results/pilot-slack-proposal.png" });
    await page.getByRole("button", { name: "Save workflow" }).click();
    await page.getByRole("button", { name: /run now/i }).click();
    await expect(page.locator('[data-status="WAITING_APPROVAL"]').first()).toBeVisible({
      timeout: 30000,
    });
    const slackRun = page.url().split("/runs/")[1];
    await page.goto("/approvals");
    await expect(page.getByText(/you requested this/i)).toBeVisible();
    const second = await browser.newContext();
    const approver = await second.newPage();
    await signIn(approver, process.env.E2E_APPROVER_EMAIL!, process.env.E2E_APPROVER_PASSWORD!);
    await approver.goto("/approvals");
    await expect(approver.getByText("CPILOT", { exact: false }).first()).toBeVisible();
    expect(await approver.getByLabel("Exact message to be sent").textContent()).toBe(
      immutable.proposed_plan.steps[0].args.text,
    );
    await approver.getByRole("button", { name: /^approve$/i }).click();
    await page.goto(`/runs/${slackRun}`);
    await expect(page.locator('[data-status="COMPLETED"]').first()).toBeVisible({ timeout: 30000 });
    await page.locator(".workflow-details > summary").click();
    await expect(page.getByRole("link", { name: "Open source analysis run" })).toHaveAttribute(
      "href",
      `/runs/${runId}`,
    );
    await second.close();
  });
  test("support workflow renders service metrics and trends", async ({ page }) => {
    requireEnv(
      process.env.E2E_PILOT === "1",
      "requires the isolated pilot provider/worker harness",
    );
    await page.setViewportSize({ width: 1440, height: 900 });
    await signIn(page, env.adminEmail, env.adminPassword);
    await page.goto("/workflows/new");
    await page.getByRole("button", { name: /Support operations/ }).click();
    await page.getByRole("button", { name: /^Prepare plan$/ }).click();
    await page.getByRole("button", { name: "Save workflow" }).click();
    await page.getByRole("button", { name: /run now/i }).click();
    await expect(page.getByTestId("analytics-result")).toBeVisible({ timeout: 30000 });
    await expect(page.getByTestId("analytics-kpi")).toHaveCount(4);
    await expect(page.getByTestId("analytics-chart")).toHaveCount(5);
    await expect(page.getByRole("heading", { name: "SLA compliance trend" })).toBeVisible();
    await assertLayout(page, 1440, 900);
    for (const value of ["49.79%", "25", "23.03 h", "4.23 / 5"]) {
      await expect(page.getByTestId("analytics-kpi").filter({ hasText: value })).toHaveCount(1);
    }
    await page.screenshot({ path: "test-results/pilot-support-desktop.png", fullPage: true });
  });
});
