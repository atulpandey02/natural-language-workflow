import { describe, expect, it } from "vitest";
import { isAllowed } from "./allowlist";

const UUID = "11111111-2222-3333-4444-555555555555";

describe("BFF allowlist", () => {
  it("allows the exact endpoints M10 uses", () => {
    expect(isAllowed("GET", "/workflows")).toBe(true);
    expect(isAllowed("GET", `/workflows/${UUID}`)).toBe(true);
    expect(isAllowed("POST", `/workflows/${UUID}/runs`)).toBe(true);
    expect(isAllowed("GET", `/runs/${UUID}/steps`)).toBe(true);
    expect(isAllowed("POST", `/approvals/${UUID}/approve`)).toBe(true);
    expect(isAllowed("PATCH", `/schedules/${UUID}`)).toBe(true);
  });

  it("is not a generic tunnel", () => {
    expect(isAllowed("DELETE", `/workflows/${UUID}`)).toBe(false); // no such method
    expect(isAllowed("GET", "/admin")).toBe(false);
    expect(isAllowed("POST", "/runs")).toBe(false); // runs are read-only here
    expect(isAllowed("GET", "/step_runs")).toBe(false);
    expect(isAllowed("GET", "/../secrets")).toBe(false);
  });
});
