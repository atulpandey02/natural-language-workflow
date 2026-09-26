import { test, expect } from "@playwright/test";
import { env, liveStackConfigured, requireEnv, signIn } from "./helpers";

// Full MVP journey against the seeded stack (M10). Sign-in also selects a
// workspace (see helpers.signIn). The CI planner is the keyless stub, which
// always returns NEEDS_CLARIFICATION — so the planner + feasibility + materialize
// GATING is asserted here (blocked path), and the run/observe journey uses a
// pre-seeded materialized fake.echo workflow ("E2E Seeded Workflow").
test.describe("MVP happy path", () => {
  test("sign in → connector → plan/feasibility → run seeded workflow → observe → history", async ({
    page,
  }) => {
    requireEnv(liveStackConfigured, "requires a seeded live stack (set E2E_* env)");
    await signIn(page, env.adminEmail, env.adminPassword);

    // Create a connector referencing a pre-provisioned secret (secret_ref only).
    await page.goto("/connectors");
    await page.getByLabel("Type").selectOption("static");
    await page.getByLabel("Name").fill("static-e2e");
    await page.getByLabel(/secret reference/i).fill("STATIC_DEMO");
    await page.getByRole("button", { name: /create connector/i }).click();
    await expect(page.getByText("static-e2e")).toBeVisible();

    // Natural-language plan → feasibility. The stub planner cannot infer intent,
    // so the proposal is NEEDS_CLARIFICATION and materialization is BLOCKED.
    await page.goto("/workflows/new");
    await page
      .getByLabel(/what should this workflow do/i)
      .fill("Summarize yesterday's failed payments.");
    await page.getByRole("button", { name: /^plan$/i }).click();
    await expect(page.getByTestId("materialize-blocked")).toBeVisible();
    await expect(page.getByRole("button", { name: /materialize/i })).toHaveCount(0);

    // Run the pre-seeded materialized workflow and observe it complete.
    await page.goto("/workflows");
    await page.getByRole("link", { name: "E2E Seeded Workflow" }).click();

    // Provenance travels through the real BFF path. The seeded version was
    // inserted directly (no plan proposal), so the BACKEND answers 404 "no
    // provenance for this version" — which the page must surface, not hide.
    // The BFF's own rejection ("Unknown resource.") must never appear.
    const provenance = page.getByTestId("workflow-provenance-error");
    await expect(provenance).toBeVisible();
    await expect(provenance).toContainText("no provenance for this version");
    await expect(provenance).not.toContainText("Unknown resource.");

    await page.getByRole("button", { name: /run now/i }).click();
    await expect(page).toHaveURL(/\/runs\/[0-9a-f-]{36}$/);
    await expect(page.getByText("COMPLETED").first()).toBeVisible({ timeout: 30000 });
    await expect(page.getByText("fake.echo").first()).toBeVisible();

    // The deterministic result summary is fetched through the real BFF path
    // and rendered for an authorized member (previously blocked by the
    // allowlist and silently omitted).
    await expect(page.getByTestId("run-summary")).toBeVisible({ timeout: 15000 });
    await expect(page.getByTestId("summary-headline")).not.toBeEmpty();
    await expect(page.getByTestId("run-summary-error")).toHaveCount(0);
  });
});
