import { type Page, expect } from "@playwright/test";

// Shared E2E helpers. Credentials + base URL come from the environment so the
// same specs run against local, CI, or staging with a seeded Supabase project.
export const env = {
  baseURL: process.env.E2E_BASE_URL,
  memberEmail: process.env.E2E_MEMBER_EMAIL ?? "",
  memberPassword: process.env.E2E_MEMBER_PASSWORD ?? "",
  adminEmail: process.env.E2E_ADMIN_EMAIL ?? "",
  adminPassword: process.env.E2E_ADMIN_PASSWORD ?? "",
};

export const liveStackConfigured = Boolean(env.baseURL && env.adminEmail && env.adminPassword);

export async function signIn(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/(select-workspace)?$/);
}
