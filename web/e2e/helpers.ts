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
  await expect(page).toHaveURL(/\/(select-workspace)?$/);
}
