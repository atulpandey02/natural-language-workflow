import { test, expect, type Page } from "@playwright/test";
import { env, liveStackConfigured, requireEnv, signIn } from "./helpers";

// M11.5 P3A — multi-user invitation flow.
//
// This IS a genuine two-real-user, two-context end-to-end test:
//   * Context A (default page): e2e-admin@example.com — owner of "E2E Primary" /
//     "E2E Secondary" — creates an invitation and reads the roster back.
//   * Context B (browser.newContext(), isolated cookies): e2e-invited@example.com
//     — a real Supabase user provisioned by seed.mjs as an app-user with NO
//     membership in any workspace — signs in fresh and redeems the raw token.
//
// seed.mjs was extended (not worked around) to represent the second identity:
//   const INVITED = { email: "e2e-invited@example.com", password: "…" };
//   await createUser(INVITED);
//   const invitedToken = await signIn(INVITED);
//   await apiGet("/me", invitedToken);   // provision app-user row, NO membership
// Because the invited user starts in no workspace, acceptance creates a brand
// new membership through the real invite → token → accept path, which is exactly
// what P3A must prove. We deliberately do NOT reuse the seeded member here (it is
// already a member of Primary), so nothing about the assertion is pre-satisfied.
//
// Tolerant of fullyParallel:false and shared seeded state: the roster assertion
// compares the admin-row count before vs. after acceptance rather than assuming
// an exact roster.

test.describe("members + invitations (multi-user)", () => {
  test("owner invites a new user who accepts and joins with the admin role", async ({
    page,
    browser,
  }) => {
    requireEnv(
      liveStackConfigured && Boolean(env.invitedEmail && env.invitedPassword),
      "requires a seeded live stack + the invited (non-membered) account",
    );

    // --- Context A: owner creates the invitation ---------------------------
    await signIn(page, env.adminEmail, env.adminPassword);
    await page.goto("/members");
    await expect(page.getByRole("heading", { name: "Members" })).toBeVisible();

    // Baseline count of roster rows already carrying the admin role, so the
    // assertion holds even under shared seeded state.
    const adminCells = page.getByRole("cell", { name: "admin", exact: true });
    const adminBefore = await adminCells.count();

    const inviteForm = page.getByRole("form", { name: "invite member" });
    await inviteForm.getByLabel("Email").fill(env.invitedEmail);
    await inviteForm.getByLabel("Role").selectOption("admin");
    await inviteForm.getByRole("button", { name: /create invitation/i }).click();

    // The raw token is surfaced exactly once in the UI for manual copying.
    const tokenBox = page.getByTestId("invitation-token");
    await expect(tokenBox).toBeVisible();
    const token = (await tokenBox.locator("pre").innerText()).trim();
    expect(token.length).toBeGreaterThan(0);

    // --- Context B: the invited user accepts (isolated cookies) ------------
    const contextB = await browser.newContext();
    try {
      const pageB = await contextB.newPage();

      // The invited user has no workspace yet, so we drive the login form
      // directly instead of the signIn() helper (which expects a selectable
      // workspace) and then go straight to the accept URL. The proxy exempts
      // /invitations/accept from the workspace requirement.
      await pageB.goto("/login");
      await pageB.getByLabel("Email").fill(env.invitedEmail);
      await pageB.getByLabel("Password").fill(env.invitedPassword);
      await pageB.getByRole("button", { name: /sign in/i }).click();
      await pageB.waitForURL(/\/(select-workspace)?$/, { timeout: 15000 });

      await pageB.goto(`/invitations/accept?token=${encodeURIComponent(token)}`);

      const accepted = pageB.getByTestId("invitation-accepted");
      await expect(accepted).toBeVisible({ timeout: 15000 });
      // The granted role is shown to the invitee.
      await expect(accepted).toContainText("admin");

      // The raw token must NOT linger in the address bar / history after use.
      await expect(pageB).toHaveURL(/\/invitations\/accept$/);

      // Route into the app (selects the joined workspace + hard-navigates).
      await pageB.getByRole("button", { name: /continue to workspace/i }).click();
      await pageB.waitForURL(/\/$/, { timeout: 15000 });
    } finally {
      await contextB.close();
    }

    // --- Context A: the roster now shows the invited user as admin ---------
    await page.reload();
    await expect(page.getByRole("heading", { name: "Members" })).toBeVisible();
    await expect
      .poll(async () => countAdminCells(page), { timeout: 15000 })
      .toBeGreaterThan(adminBefore);
  });
});

async function countAdminCells(page: Page): Promise<number> {
  return page.getByRole("cell", { name: "admin", exact: true }).count();
}
