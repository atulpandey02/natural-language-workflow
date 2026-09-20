import { defineConfig } from "@playwright/test";

// E2E runs against a fully seeded stack (backend + Supabase + a Postgres worker
// secret pre-provisioned). Provide E2E_BASE_URL and test credentials via env;
// specs self-skip when the environment is absent so CI stays green until wired.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    trace: "on-first-retry",
  },
});
