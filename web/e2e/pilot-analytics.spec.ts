import { test, expect } from "@playwright/test";
import { env, requireEnv, signIn } from "./helpers";

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
    await page.setViewportSize({ width: 1600, height: 1000 });
    await signIn(page, env.adminEmail, env.adminPassword);
    await page.goto("/workflows/new");
    await page.getByRole("button", { name: /Sales operations/ }).click();
    await expect(page.getByLabel(/what should this workflow do/i)).toContainText("sales-v1");
    await page.getByRole("button", { name: /^Plan$/ }).click();
    await expect(page.getByText("pilot.sales_analysis", { exact: true })).toBeVisible();
    await expect(page.getByText("PASS", { exact: true })).toBeVisible();
    await page.screenshot({ path: "test-results/pilot-proposal-desktop.png", fullPage: true });
    await page.getByRole("button", { name: "Materialize workflow" }).click();
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
    await expect(page.getByRole("heading", { name: "What the data shows" })).toBeVisible();
    await expect(page.getByText(/Accessories revenue declined/)).toBeVisible();
    await expect(page.locator('svg.recharts-surface[role="application"]')).toHaveCount(4);
    await page.getByText("Monthly supporting data", { exact: true }).first().click();
    await expect(page.getByRole("table", { name: "Monthly supporting data" })).toBeVisible();
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: "test-results/pilot-sales-desktop.png", fullPage: true });
    await page.getByRole("link", { name: "analyze", exact: true }).first().click();
    await expect(page.locator("#evidence-analyze")).toBeVisible();
    await expect(page.locator("#evidence-analyze")).toContainText("SUCCESS");
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: "test-results/pilot-sales-mobile.png", fullPage: true });
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
    await page.setViewportSize({ width: 1600, height: 1000 });

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
    await page.getByRole("button", { name: "Send summary to Slack" }).click();
    await expect(page.getByRole("heading", { name: "Exact message for approval" })).toBeVisible();
    await expect(page.getByText("NEEDS_APPROVAL", { exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: "Open source analysis run" })).toHaveAttribute(
      "href",
      `/runs/${runId}`,
    );
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: "test-results/pilot-slack-proposal.png", fullPage: true });
    await page.getByRole("button", { name: "Materialize workflow" }).click();
    await page.getByRole("button", { name: /run now/i }).click();
    await expect(page.getByText("WAITING_APPROVAL").first()).toBeVisible({ timeout: 30000 });
    const slackRun = page.url().split("/runs/")[1];
    await page.goto("/approvals");
    await expect(page.getByText(/you requested this/i)).toBeVisible();
    const second = await browser.newContext();
    const approver = await second.newPage();
    await signIn(approver, process.env.E2E_APPROVER_EMAIL!, process.env.E2E_APPROVER_PASSWORD!);
    await approver.goto("/approvals");
    await expect(approver.getByText("CPILOT", { exact: false }).first()).toBeVisible();
    await approver.getByRole("button", { name: /^approve$/i }).click();
    await page.goto(`/runs/${slackRun}`);
    await expect(page.getByText("COMPLETED").first()).toBeVisible({ timeout: 30000 });
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
    await page.setViewportSize({ width: 1600, height: 1000 });
    await signIn(page, env.adminEmail, env.adminPassword);
    await page.goto("/workflows/new");
    await page.getByRole("button", { name: /Support operations/ }).click();
    await page.getByRole("button", { name: /^Plan$/ }).click();
    await page.getByRole("button", { name: "Materialize workflow" }).click();
    await page.getByRole("button", { name: /run now/i }).click();
    await expect(page.getByTestId("analytics-result")).toBeVisible({ timeout: 30000 });
    await expect(page.getByTestId("analytics-kpi")).toHaveCount(4);
    await expect(page.getByTestId("analytics-chart")).toHaveCount(5);
    await expect(page.getByRole("heading", { name: "SLA compliance trend" })).toBeVisible();
    await page.screenshot({ path: "test-results/pilot-support-desktop.png", fullPage: true });
  });
});
