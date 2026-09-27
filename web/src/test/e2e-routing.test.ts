// @vitest-environment node
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { HARNESS_ONLY_SPEC, specRouting } from "../../e2e/routing";

const e2eDir = join(__dirname, "..", "..", "e2e");
const specs = readdirSync(e2eDir).filter((name) => name.endsWith(".spec.ts"));
const collectedBy = (env: Record<string, string | undefined>) => {
  const routing = specRouting(env);
  return specs.filter((name) => {
    const path = join(e2eDir, name);
    return "testMatch" in routing ? routing.testMatch.test(path) : !routing.testIgnore.test(path);
  });
};

describe("Playwright spec routing between the seeded-stack and pilot-harness jobs", () => {
  it("splits every spec into exactly one required job", () => {
    const seeded = collectedBy({ E2E_REQUIRED: "1" });
    const pilot = collectedBy({ E2E_REQUIRED: "1", E2E_PILOT: "1" });
    expect(seeded.length).toBeGreaterThan(0);
    expect(pilot.length).toBeGreaterThan(0);
    expect(seeded.filter((name) => pilot.includes(name))).toEqual([]);
    expect([...seeded, ...pilot].sort()).toEqual([...specs].sort());
  });

  it("never lets the seeded-stack job collect a spec that requires the pilot harness", () => {
    const seeded = collectedBy({ E2E_REQUIRED: "1" });
    for (const name of specs) {
      const needsHarness = readFileSync(join(e2eDir, name), "utf8").includes("E2E_PILOT");
      expect({ name, harness: HARNESS_ONLY_SPEC.test(name) }).toEqual({
        name,
        harness: needsHarness,
      });
      if (needsHarness) expect(seeded).not.toContain(name);
    }
  });

  it("keeps the existing golden and visual-state pilot specs in the pilot job", () => {
    expect(collectedBy({ E2E_PILOT: "1" })).toEqual(
      expect.arrayContaining(["pilot-analytics.spec.ts", "pilot-visual-states.spec.ts"]),
    );
  });
});
