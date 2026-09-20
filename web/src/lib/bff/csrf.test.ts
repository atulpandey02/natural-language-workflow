import { describe, expect, it } from "vitest";
import { isSameOrigin, requiresCsrfCheck } from "./csrf";
import type { NextRequest } from "next/server";

function fakeReq(headers: Record<string, string>): NextRequest {
  return {
    headers: { get: (k: string) => headers[k.toLowerCase()] ?? null },
  } as unknown as NextRequest;
}

describe("requiresCsrfCheck", () => {
  it("guards mutating methods only", () => {
    expect(requiresCsrfCheck("POST")).toBe(true);
    expect(requiresCsrfCheck("patch")).toBe(true);
    expect(requiresCsrfCheck("DELETE")).toBe(true);
    expect(requiresCsrfCheck("GET")).toBe(false);
  });
});

describe("isSameOrigin", () => {
  it("accepts a same-origin Origin", () => {
    expect(
      isSameOrigin(fakeReq({ host: "app.example.com", origin: "https://app.example.com" })),
    ).toBe(true);
  });

  it("rejects a cross-origin Origin and a missing Origin", () => {
    expect(
      isSameOrigin(fakeReq({ host: "app.example.com", origin: "https://evil.example.com" })),
    ).toBe(false);
    expect(isSameOrigin(fakeReq({ host: "app.example.com" }))).toBe(false);
  });
});
