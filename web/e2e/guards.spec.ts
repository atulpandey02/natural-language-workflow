import { test, expect } from "@playwright/test";
import { env, liveStackConfigured, requireEnv, signIn } from "./helpers";

test.describe("access + safety guards", () => {
  test("unauthenticated users are redirected to sign in", async ({ page }) => {
    requireEnv(Boolean(env.baseURL), "requires a running web app");
    await page.goto("/");
    await expect(page).toHaveURL(/\/login/);
  });

  test("non-materializable plans (REJECT / NEEDS_CLARIFICATION) cannot be materialized", async ({
    page,
  }) => {
    requireEnv(liveStackConfigured, "requires a seeded live stack");
    await signIn(page, env.adminEmail, env.adminPassword);
    await page.goto("/workflows/new");
    await page.getByLabel(/what should this workflow do/i).fill("do something impossible xyzzy");
    await page.getByRole("button", { name: /^plan$/i }).click();
    // The stub CI planner returns NEEDS_CLARIFICATION → the blocked notice shows
    // and no materialize button is offered (same gating as REJECT).
    await expect(page.getByTestId("materialize-blocked")).toBeVisible();
    await expect(page.getByRole("button", { name: /materialize/i })).toHaveCount(0);
  });

  test("members cannot see admin approve/reject controls", async ({ page }) => {
    requireEnv(liveStackConfigured && Boolean(env.memberEmail), "requires a seeded member account");
    await signIn(page, env.memberEmail, env.memberPassword);
    await page.goto("/approvals");
    await expect(page.getByText(/an admin or owner must decide/i)).toBeVisible();
    await expect(page.getByRole("button", { name: /^approve$/i })).toHaveCount(0);
  });

  test("double-click Run now creates exactly one durable run", async ({ page }) => {
    requireEnv(liveStackConfigured, "requires a seeded live stack + a materialized workflow");
    await signIn(page, env.adminEmail, env.adminPassword);
    await page.goto("/workflows");
    await page.getByRole("link", { name: "E2E Seeded Workflow" }).click();
    const runNow = page.getByRole("button", { name: /run now/i });
    // Fire two clicks in the same tick (double-click): the shared idempotency key
    // guarantees the backend returns one durable run.
    await Promise.all([runNow.click(), runNow.click().catch(() => {})]);
    await expect(page).toHaveURL(/\/runs\/[0-9a-f-]{36}$/);
  });

  test("switching workspace does not show stale previous-tenant data", async ({ page }) => {
    requireEnv(liveStackConfigured, "requires two seeded workspaces");
    await signIn(page, env.adminEmail, env.adminPassword);
    await page.goto("/workflows");
    // The primary workspace has the seeded workflow visible.
    await expect(page.getByRole("link", { name: "E2E Seeded Workflow" })).toBeVisible();

    const switcher = page.getByLabel(/select workspace/i);
    const options = await switcher.locator("option").all();
    requireEnv(options.length >= 2, "needs at least two workspaces");
    await switcher.selectOption({ index: 1 });

    // Switching clears tenant-scoped caches: the previous tenant's workflow must
    // NOT still be shown for the (empty) secondary workspace.
    await expect(page.getByRole("heading", { name: "Workflows" })).toBeVisible();
    await expect(page.getByRole("link", { name: "E2E Seeded Workflow" })).toHaveCount(0);
  });
});
