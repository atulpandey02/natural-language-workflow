import { describe, expect, it } from "vitest";
import { loginSearchFor, safeNextPath } from "./next-path";

describe("post-login return path", () => {
  it("accepts only the invitation-accept page with a token", () => {
    expect(safeNextPath("/invitations/accept?token=abc_DEF-123.x~")).toBe(
      "/invitations/accept?token=abc_DEF-123.x~",
    );
  });

  it.each([
    null,
    "",
    "/",
    "/runs",
    "/invitations/accept",
    "/invitations/accept?token=",
    "https://evil.example/invitations/accept?token=x",
    "//evil.example/invitations/accept?token=x",
    "/invitations/accept?token=x&next=//evil.example",
    "/invitations/accept?token=x#frag",
    "/invitations/accept?token=a//b",
    "/invitations/accept?token=a\\b",
    "/invitations/accept?token=<script>",
    `/invitations/accept?token=${"a".repeat(800)}`,
  ])("drops %s", (raw) => {
    expect(safeNextPath(raw)).toBeNull();
  });

  it("carries only the accept page forward through the login redirect", () => {
    expect(loginSearchFor("/invitations/accept", "?token=tok123")).toBe(
      `?next=${encodeURIComponent("/invitations/accept?token=tok123")}`,
    );
    expect(loginSearchFor("/runs", "?id=1")).toBe(""); // other queries never leak into /login
    expect(loginSearchFor("/invitations/accept", "?token=a&x=//evil")).toBe("");
    expect(loginSearchFor("/invitations/accept", "")).toBe("");
  });
});
