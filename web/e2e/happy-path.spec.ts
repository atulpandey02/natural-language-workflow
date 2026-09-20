import { test, expect } from "@playwright/test";
import { env, liveStackConfigured, requireEnv, signIn } from "./helpers";

// Full MVP journey (M10 change #13). Requires a seeded stack: a Supabase user
// with admin/owner role and a tenant-scoped worker secret (e.g. PG_MAIN)
// pre-provisioned before the connector is created.
test.describe("MVP happy path", () => {
  test("sign in → connector → plan → materialize → run now → observe → history", async ({
    page,
  }) => {
    requireEnv(liveStackConfigured, "requires a seeded live stack (set E2E_* env)");
    await signIn(page, env.adminEmail, env.adminPassword);

    // Workspace: select an existing one or create if none.
    if (page.url().includes("/select-workspace")) {
      const open = page.getByRole("button", { name: /open/i }).first();
      if (await open.isVisible().catch(() => false)) {
        await open.click();
      } else {
        await page.getByLabel(/workspace name/i).fill("E2E Workspace");
        await page.getByRole("button", { name: /create \+ open/i }).click();
      }
    }
    await expect(page).toHaveURL(/\/$/);

    // Create a connector referencing a pre-provisioned secret.
    await page.goto("/connectors");
    await page.getByLabel("Type").selectOption("postgres");
    await page.getByLabel("Name").fill("pg-e2e");
    await page.getByLabel("Host").fill("db.internal");
    await page.getByLabel("Database").fill("app");
    await page.getByLabel(/secret reference/i).fill("PG_MAIN");
    await page.getByRole("button", { name: /create connector/i }).click();
    await expect(page.getByText("pg-e2e")).toBeVisible();

    // Natural-language plan → feasibility → materialize.
    await page.goto("/workflows/new");
    await page
      .getByLabel(/what should this workflow do/i)
      .fill("Query yesterday's failed payments and summarize them.");
    await page.getByRole("button", { name: /^plan$/i }).click();
    await page.getByRole("button", { name: /materialize/i }).click();
    await expect(page).toHaveURL(/\/workflows\/[0-9a-f-]{36}$/);

    // Run now (idempotent) → observe run detail.
    await page.getByRole("button", { name: /run now/i }).click();
    await expect(page).toHaveURL(/\/runs\/[0-9a-f-]{36}$/);
    await expect(page.getByText(/steps/i)).toBeVisible();
  });
});
