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

  test("Run now (single click) navigates to the created run", async ({ page }) => {
    requireEnv(liveStackConfigured, "requires a seeded live stack + a materialized workflow");
    await signIn(page, env.adminEmail, env.adminPassword);
    await page.goto("/workflows");
    await page.getByRole("link", { name: "E2E Seeded Workflow" }).click();
    // A single deterministic click must navigate to the created run.
    await page.getByRole("button", { name: /run now/i }).click();
    await expect(page).toHaveURL(/\/runs\/[0-9a-f-]{36}$/);
  });

  test("two concurrent Run-now POSTs sharing one Idempotency-Key create exactly one durable run", async ({
    page,
  }) => {
    requireEnv(liveStackConfigured, "requires a seeded live stack + a materialized workflow");
    await signIn(page, env.adminEmail, env.adminPassword);

    // Determine the seeded workflow's id from its detail URL.
    await page.goto("/workflows");
    await page.getByRole("link", { name: "E2E Seeded Workflow" }).click();
    await expect(page).toHaveURL(/\/workflows\/[0-9a-f-]{36}$/);
    const workflowId = page.url().split("/workflows/")[1];
    expect(workflowId).toMatch(/^[0-9a-f-]{36}$/);

    // Issue TWO concurrent POSTs from the AUTHENTICATED page context, both with
    // the SAME Idempotency-Key. This exercises the real cookies + same-origin
    // BFF (CSRF + bearer + X-Workspace-Id injection) + FastAPI + Postgres. No
    // arbitrary sleeps — the two requests race deterministically in one tick.
    const { a, b } = await page.evaluate(async (id: string) => {
      const key = crypto.randomUUID(); // ONE key for the single logical action
      const once = async () => {
        const res = await fetch(`/api/nlw/workflows/${id}/runs`, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Idempotency-Key": key, Accept: "application/json" },
        });
        const data = (await res.json()) as { run_id?: string };
        return { ok: res.ok, status: res.status, runId: data.run_id };
      };
      const [first, second] = await Promise.all([once(), once()]);
      return { a: first, b: second };
    }, workflowId);

    // Both requests succeed per the endpoint contract …
    expect(a.ok, `first POST failed (status ${a.status})`).toBeTruthy();
    expect(b.ok, `second POST failed (status ${b.status})`).toBeTruthy();
    expect(a.runId).toMatch(/^[0-9a-f-]{36}$/);
    // … and BOTH resolve to the SAME durable run (exactly one for the action).
    expect(b.runId).toBe(a.runId);

    // The single durable run is real and fetchable.
    await page.goto(`/runs/${a.runId}`);
    await expect(page).toHaveURL(new RegExp(`/runs/${a.runId}$`));
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
