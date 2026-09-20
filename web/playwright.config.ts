import { defineConfig } from "@playwright/test";

// E2E runs against a fully seeded stack (backend + worker + scheduler + web +
// Caddy + Supabase auth, with a tenant-scoped worker secret pre-provisioned).
// Provide E2E_BASE_URL + credentials via env. With E2E_REQUIRED=1 the suite
// fails (never skips) when that configuration is absent — see global-setup.
export default defineConfig({
  testDir: "./e2e",
  globalSetup: "./e2e/global-setup.ts",
  fullyParallel: false,
  forbidOnly: process.env.E2E_REQUIRED === "1",
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    trace: "on-first-retry",
  },
});
