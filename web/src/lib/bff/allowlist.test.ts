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

  it("allows the M11.5 members + invitations endpoints", () => {
    expect(isAllowed("GET", "/members")).toBe(true);
    expect(isAllowed("PATCH", `/members/${UUID}`)).toBe(true);
    expect(isAllowed("DELETE", `/members/${UUID}`)).toBe(true);
    expect(isAllowed("GET", "/invitations")).toBe(true);
    expect(isAllowed("POST", "/invitations")).toBe(true);
    expect(isAllowed("POST", `/invitations/${UUID}/revoke`)).toBe(true);
    expect(isAllowed("POST", "/invitations/accept")).toBe(true);
  });

  it("does not over-allow members / invitations", () => {
    expect(isAllowed("DELETE", "/members")).toBe(false); // collection is read-only
    expect(isAllowed("POST", `/members/${UUID}`)).toBe(false);
    expect(isAllowed("DELETE", `/invitations/${UUID}`)).toBe(false); // revoke, not delete
    expect(isAllowed("POST", `/invitations/${UUID}`)).toBe(false);
  });

  it("allows the run summary + workflow provenance reads the UI consumes", () => {
    expect(isAllowed("GET", `/runs/${UUID}/summary`)).toBe(true);
    expect(isAllowed("GET", `/workflow-versions/${UUID}/provenance`)).toBe(true);
  });

  it("does not over-allow summary / provenance (method, nested, near-miss paths)", () => {
    // Read-only: no other method.
    expect(isAllowed("POST", `/runs/${UUID}/summary`)).toBe(false);
    expect(isAllowed("DELETE", `/runs/${UUID}/summary`)).toBe(false);
    expect(isAllowed("POST", `/workflow-versions/${UUID}/provenance`)).toBe(false);
    expect(isAllowed("PATCH", `/workflow-versions/${UUID}/provenance`)).toBe(false);
    // Exact segments only: no trailing/nested/sibling variants.
    expect(isAllowed("GET", `/runs/${UUID}/summary/`)).toBe(false);
    expect(isAllowed("GET", `/runs/${UUID}/summary/${UUID}`)).toBe(false);
    expect(isAllowed("GET", `/runs/${UUID}/summaries`)).toBe(false);
    expect(isAllowed("GET", `/runs/${UUID}/steps/${UUID}/summary`)).toBe(false);
    expect(isAllowed("GET", "/runs/summary")).toBe(false);
    expect(isAllowed("GET", `/workflow-versions/${UUID}/provenance/`)).toBe(false);
    expect(isAllowed("GET", `/workflow-versions/${UUID}/provenance/${UUID}`)).toBe(false);
    expect(isAllowed("GET", `/workflow-versions/${UUID}/provenances`)).toBe(false);
    expect(isAllowed("GET", "/workflow-versions/provenance")).toBe(false);
    expect(isAllowed("GET", `/workflows/${UUID}/provenance`)).toBe(false);
    // Same id discipline as every other rule: a 36-char UUID shape, nothing else.
    expect(isAllowed("GET", "/runs/not-a-uuid/summary")).toBe(false);
    expect(isAllowed("GET", `/runs/${UUID}x/summary`)).toBe(false);
    expect(isAllowed("GET", "/workflow-versions/1/provenance")).toBe(false);
  });

  it("does not expose the backend-only schedule unblock endpoint (no UI consumes it)", () => {
    // Deliberate: a backend endpoint is not exposed merely because it exists.
    // Add an exact POST rule here only together with a real unblock UI.
    expect(isAllowed("POST", `/schedules/${UUID}/unblock`)).toBe(false);
    expect(isAllowed("GET", `/schedules/${UUID}/unblock`)).toBe(false);
  });

  it("is not a generic tunnel", () => {
    expect(isAllowed("DELETE", `/workflows/${UUID}`)).toBe(false); // no such method
    expect(isAllowed("GET", "/admin")).toBe(false);
    expect(isAllowed("POST", "/runs")).toBe(false); // runs are read-only here
    expect(isAllowed("GET", "/step_runs")).toBe(false);
    expect(isAllowed("GET", "/../secrets")).toBe(false);
  });
});
