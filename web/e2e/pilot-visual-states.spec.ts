import { test, expect, type Page } from "@playwright/test";
import { env, requireEnv, signIn } from "./helpers";

// Supplemental evidence only. Normal golden journeys retain all their assertions.
// The opt-in plugin supplies planner inputs; every result below comes from the real worker.
test("real failed/partial checkpoints and immutable Slack UNKNOWN outcome", async ({
  page,
  browser,
}) => {
  requireEnv(
    process.env.E2E_PILOT === "1" && process.env.PILOT_VISUAL_STATES === "1",
    "requires isolated visual-state inputs",
  );
  test.setTimeout(120000);
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, env.adminEmail, env.adminPassword);
  async function run(prompt: string, target: Page = page) {
    await target.goto("/workflows/new");
    await target.getByLabel(/what should this workflow do/i).fill(prompt);
    await target.getByRole("button", { name: /^Prepare plan$/ }).click();
    await target.getByRole("button", { name: "Save workflow" }).click();
    await target.getByRole("button", { name: /run now/i }).click();
    await expect(target).toHaveURL(/\/runs\/[0-9a-f-]{36}$/);
  }
  await run("Visual partial: analyze sales-v1, then run the deterministic failure fixture.");
  await expect(page.getByTestId("analytics-result").getByRole("status")).toContainText(
    "Partial results",
    { timeout: 30000 },
  );
  await expect(page.getByTestId("analytics-kpi").first()).toContainText("$280,617.20");
  await expect(
    page.getByTestId("run-summary").locator('[data-status="FAILED"]').first(),
  ).toBeVisible();
  await expect(
    page.getByTestId("run-summary").locator('[data-status="SKIPPED"]').first(),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Send summary to Slack" })).toHaveCount(0);
  await page.screenshot({ path: "test-results/pilot-partial-failed.png", fullPage: true });
  await run("Visual failure: run the deterministic failure fixture before any analysis.");
  await expect(
    page.getByText("No completed analytical evidence is available for this run."),
  ).toBeVisible({ timeout: 30000 });
  await expect(
    page.getByTestId("run-summary").locator('[data-status="FAILED"]').first(),
  ).toBeVisible();
  await expect(page.getByTestId("analytics-chart")).toHaveCount(0);
  await page.screenshot({ path: "test-results/pilot-failed-empty.png", fullPage: true });
  await run("Analyze sales-v1 for the last six months.");
  await expect(page.getByTestId("analytics-result")).toBeVisible({ timeout: 30000 });
  const sourceRun = page.url();
  await page.getByLabel("Slack destination").selectOption({ label: "pilot-slack · CPILOT" });
  await page.getByRole("button", { name: "Send summary to Slack" }).click();
  await page.getByRole("button", { name: "Save workflow" }).click();
  await page.getByRole("button", { name: /run now/i }).click();
  await expect(page.locator('[data-status="WAITING_APPROVAL"]').first()).toBeVisible({
    timeout: 30000,
  });
  const slackRun = page.url();
  const second = await browser.newContext();
  const approver = await second.newPage();
  await signIn(approver, process.env.E2E_APPROVER_EMAIL!, process.env.E2E_APPROVER_PASSWORD!);
  await approver.goto("/approvals");
  await expect(approver.getByText("CPILOT", { exact: false }).first()).toBeVisible();
  await approver.getByRole("button", { name: /^approve$/i }).click();
  await page.goto(slackRun);
  await expect(
    page.getByTestId("run-summary").locator('[data-status="FAILED_WITH_UNKNOWN"]').first(),
  ).toBeVisible({ timeout: 30000 });
  // UNKNOWN is explained, and never with a blind "try again".
  await expect(page.getByText("We can't confirm whether the action happened")).toBeVisible();
  await expect(page.getByText(/Don't simply run it again/)).toBeVisible();
  await expect(
    page.getByTestId("run-summary").locator('[data-status="UNKNOWN"]').first(),
  ).toBeVisible();
  await expect(page.getByTestId("run-summary").locator('[data-status="SUCCESS"]')).toHaveCount(0);
  // Full-page capture briefly resizes Chromium to 1px and triggers drawer collapse.
  // Use a fixed viewport that contains the expanded audit evidence instead.
  await page.setViewportSize({ width: 1440, height: 1440 });
  await page.locator(".workflow-details > summary").click();
  await expect(page.locator(".workflow-details")).toHaveAttribute("open", "");
  await expect(page.getByRole("link", { name: "Open source analysis run" })).toBeVisible();
  await expect(page.getByText("Destination: CPILOT", { exact: true }).first()).toBeVisible();
  await page.screenshot({ path: "test-results/pilot-unknown.png" });
  await expect(page.locator(".workflow-details")).toHaveAttribute("open", "");
  await page.goto(sourceRun);
  await expect(page.getByTestId("analytics-result")).toContainText("Completed");
  await second.close();
});
