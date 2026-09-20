import { type Page, test, expect } from "@playwright/test";

// Shared E2E helpers. Credentials + base URL come from the environment so the
// same specs run against local, CI, or staging with a seeded Supabase project.
export const env = {
  baseURL: process.env.E2E_BASE_URL,
  memberEmail: process.env.E2E_MEMBER_EMAIL ?? "",
  memberPassword: process.env.E2E_MEMBER_PASSWORD ?? "",
  adminEmail: process.env.E2E_ADMIN_EMAIL ?? "",
  adminPassword: process.env.E2E_ADMIN_PASSWORD ?? "",
};

// Required mode (M10 gate): when E2E_REQUIRED=1 the suite must NOT silently
// skip — missing configuration fails the job instead.
export const E2E_REQUIRED = process.env.E2E_REQUIRED === "1";

export const liveStackConfigured = Boolean(env.baseURL && env.adminEmail && env.adminPassword);

/**
 * Gate a test on a precondition. In required mode a missing precondition FAILS
 * the test (throws); otherwise it skips (ordinary local dev). Never silently
 * skips in required mode.
 */
export function requireEnv(condition: boolean, reason: string): void {
  if (condition) return;
  if (E2E_REQUIRED) {
    throw new Error(`E2E_REQUIRED=1 but ${reason}. Configure the seeded stack env.`);
  }
  test.skip(true, reason);
}

export async function signIn(page: Page, email: string, password: string): Promise<void> {
  // Capture browser console errors (e.g. CSP/CORS blocks) for a secret-safe
  // diagnostic if sign-in fails. Never logs password/token/cookie.
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });

  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();

  try {
    await page.waitForURL(/\/(select-workspace)?$/, { timeout: 15000 });
  } catch {
    // Still on /login: surface the visible auth error + console errors, never
    // the submitted credentials or any token.
    let banner = "";
    const alert = page.getByRole("alert");
    if (await alert.count()) banner = (await alert.first().innerText()).trim();
    const errors = consoleErrors.slice(0, 5).join(" | ");
    throw new Error(
      `sign-in did not navigate away from /login. ` +
        `auth banner: ${banner || "(none)"}. console errors: ${errors || "(none)"}`,
    );
  }

  // Ensure a workspace is active so tenant pages don't bounce to
  // /select-workspace.
  if (page.url().includes("/select-workspace")) {
    // Wait for the workspaces query to finish rendering BEFORE inspecting the
    // list — do not use the presence of an Open button as the readiness signal.
    await expect(page.getByTestId("workspace-ready")).toBeVisible({ timeout: 15000 });

    const open = page.getByRole("button", { name: /^open$/i });
    const openCount = await open.count();

    const isWorkspacePost = (r: { url: () => string; request: () => { method: () => string } }) =>
      r.url().includes("/api/workspace") && r.request().method() === "POST";

    if (openCount === 0) {
      // Required seeded CI guarantees a workspace — a missing one is a real
      // failure, NOT something to paper over by creating a new (wrong) tenant.
      if (E2E_REQUIRED) {
        throw new Error("seeded workspace missing on /select-workspace (0 Open buttons)");
      }
      // Local/non-required convenience only: create one.
      await page.getByLabel(/workspace name/i).fill("E2E Workspace");
      const [res] = await Promise.all([
        page.waitForResponse(isWorkspacePost),
        page.getByRole("button", { name: /create \+ open/i }).click(),
      ]);
      expect(res.ok()).toBeTruthy();
    } else {
      // Require a successful workspace write before expecting navigation.
      const [res] = await Promise.all([
        page.waitForResponse(isWorkspacePost),
        open.first().click(),
      ]);
      expect(res.ok()).toBeTruthy();
    }

    // Diagnostic (never log the value): the signed selection cookie must exist.
    const cookies = await page.context().cookies();
    expect(cookies.some((c) => c.name === "nlw_ws")).toBeTruthy();

    // Production hard-navigates after the cookie write, so this is deterministic.
    await page.waitForURL(/\/$/, { timeout: 15000 });
  }
  await expect(page).toHaveURL(/\/$/);
}
