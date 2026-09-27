// Explicit Playwright spec routing (see .github/workflows/e2e.yml).
//
// - "Required Playwright E2E (seeded stack)": every spec EXCEPT the harness-only
//   pilot specs. Those cannot run against the compose stack: they need the
//   controlled planner provider, dedicated worker and mock Slack transport.
// - "Required pilot browser harness (isolated)": ONLY the pilot specs, launched by
//   tests/integration/test_pilot_browser.py, which sets E2E_PILOT=1.
//
// Both jobs run in required mode (E2E_REQUIRED=1), so neither may skip a spec it
// collects. Routing by file name keeps the split visible and testable.
export const HARNESS_ONLY_SPEC = /(^|[\\/])pilot-[^\\/]*\.spec\.ts$/;

export function specRouting(
  env: Record<string, string | undefined>,
): { testMatch: RegExp } | { testIgnore: RegExp } {
  return env.E2E_PILOT === "1"
    ? { testMatch: HARNESS_ONLY_SPEC }
    : { testIgnore: HARNESS_ONLY_SPEC };
}
