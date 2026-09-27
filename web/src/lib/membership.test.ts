import { describe, expect, it } from "vitest";
import {
  assignableRoles,
  canManageRow,
  invitableRoles,
  invitationLink,
  memberSince,
  roleLabel,
} from "./membership";

// These mirror manage_membership / the invitation endpoints; the backend stays
// authoritative — these only decide which controls a role is shown.
describe("membership presentation rules", () => {
  it("lets only an owner grant owner; members grant nothing", () => {
    expect(assignableRoles("owner")).toEqual(["owner", "admin", "member"]);
    expect(assignableRoles("admin")).toEqual(["admin", "member"]);
    expect(assignableRoles("member")).toEqual([]);
    expect(assignableRoles(undefined)).toEqual([]);
  });

  it("never invites an owner, and only managers invite", () => {
    expect(invitableRoles("owner")).toEqual(["member", "admin"]);
    expect(invitableRoles("admin")).toEqual(["member", "admin"]);
    expect(invitableRoles("member")).toEqual([]);
  });

  it("keeps owner rows owner-only and never offers controls on your own row", () => {
    expect(canManageRow("owner", "owner", false)).toBe(true);
    expect(canManageRow("admin", "owner", false)).toBe(false);
    expect(canManageRow("admin", "member", false)).toBe(true);
    expect(canManageRow("member", "member", false)).toBe(false);
    expect(canManageRow("owner", "member", true)).toBe(false);
  });

  it("builds an encoded one-time link and friendly labels", () => {
    expect(invitationLink("https://app.example", "a b+c")).toBe(
      "https://app.example/invitations/accept?token=a%20b%2Bc",
    );
    expect(roleLabel("admin")).toBe("Admin");
    expect(roleLabel("weird")).toBe("Member");
    expect(memberSince(null)).toBe("Workspace member");
    expect(memberSince("not a date")).toBe("Workspace member");
    expect(memberSince("2026-09-20T10:00:00Z")).toMatch(/^Member since /);
  });
});
