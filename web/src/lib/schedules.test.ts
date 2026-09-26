import { describe, expect, it } from "vitest";
import { blockedReasonText, scheduleStatus } from "./schedules";

describe("scheduleStatus precedence", () => {
  it("reports blocked even when enabled=true (the audited defect)", () => {
    expect(scheduleStatus({ enabled: true, blocked_reason: "CREATOR_NOT_A_MEMBER" })).toBe(
      "blocked",
    );
  });
  it("reports blocked when disabled AND blocked", () => {
    expect(scheduleStatus({ enabled: false, blocked_reason: "CREATOR_ROLE_INSUFFICIENT" })).toBe(
      "blocked",
    );
  });
  it("otherwise active if enabled, else disabled", () => {
    expect(scheduleStatus({ enabled: true, blocked_reason: null })).toBe("active");
    expect(scheduleStatus({ enabled: false, blocked_reason: null })).toBe("disabled");
  });
});

describe("blockedReasonText", () => {
  it("maps the known reason codes to prose", () => {
    expect(blockedReasonText("CREATOR_NOT_A_MEMBER")).toMatch(/no longer a member/);
    expect(blockedReasonText("CREATOR_ROLE_INSUFFICIENT")).toMatch(/admin or owner role/);
  });
  it("never echoes an unknown code or internal detail", () => {
    const text = blockedReasonText("SELECT * FROM memberships WHERE role = 'owner' -- policy_x");
    expect(text).toMatch(/^Blocked:/);
    expect(text).not.toMatch(/SELECT|memberships|policy_x/);
  });
  it("is null when not blocked", () => {
    expect(blockedReasonText(null)).toBeNull();
    expect(blockedReasonText(undefined)).toBeNull();
    expect(blockedReasonText("")).toBeNull();
  });
});
