import { defineConfig } from "@playwright/test";
import { specRouting } from "./e2e/routing";

// E2E runs against a fully seeded stack (backend + worker + scheduler + web +
// Caddy + Supabase auth, with a tenant-scoped worker secret pre-provisioned).
// Provide E2E_BASE_URL + credentials via env. With E2E_REQUIRED=1 the suite
// fails (never skips) when that configuration is absent — see global-setup.
// Harness-only pilot specs are routed to their own job — see e2e/routing.ts.
// E2E_JSON_REPORT additionally writes a JSON report that CI checks for
// collected, skipped and failed counts.
const jsonReport = process.env.E2E_JSON_REPORT;
export default defineConfig({
  testDir: "./e2e",
  ...specRouting(process.env),
  globalSetup: "./e2e/global-setup.ts",
  fullyParallel: false,
  forbidOnly: process.env.E2E_REQUIRED === "1",
  reporter: jsonReport ? [["list"], ["json", { outputFile: jsonReport }]] : [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    trace: "on-first-retry",
  },
});
