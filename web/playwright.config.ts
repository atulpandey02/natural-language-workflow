import { defineConfig } from "@playwright/test";
import { specRouting } from "./e2e/routing";

// E2E runs against a fully seeded stack (backend + worker + scheduler + web +
// Caddy + Supabase auth, with a tenant-scoped worker secret pre-provisioned).
// Provide E2E_BASE_URL + credentials via env. With E2E_REQUIRED=1 the suite
// fails (never skips) when that configuration is absent — see global-setup.
// Harness-only pilot specs are routed to their own job — see e2e/routing.ts.
// E2E_JSON_REPORT additionally writes a JSON report that CI checks for
// collected, skipped and failed counts.
//
// E2E_FAILURE_EVIDENCE=1 (staging-validation only) keeps screenshots and video
// of FAILED tests (plus Playwright's error-context.md), which CI uploads after
// scripts/ci/collect_browser_evidence.sh has redacted and scanned them. No HTML
// report is written: it embeds raw authenticated report data. Traces stay OFF
// everywhere: they record request headers, session cookies and authorization
// material, so they are never captured or uploaded.
const jsonReport = process.env.E2E_JSON_REPORT;
const failureEvidence = process.env.E2E_FAILURE_EVIDENCE === "1";
type Reporter = [string] | [string, Record<string, unknown>];
const reporters: Reporter[] = [["list"]];
if (jsonReport) reporters.push(["json", { outputFile: jsonReport }]);
export default defineConfig({
  testDir: "./e2e",
  ...specRouting(process.env),
  globalSetup: "./e2e/global-setup.ts",
  fullyParallel: false,
  forbidOnly: process.env.E2E_REQUIRED === "1",
  reporter: reporters,
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    trace: "off",
    screenshot: failureEvidence ? "only-on-failure" : "off",
    video: failureEvidence ? "retain-on-failure" : "off",
  },
});
