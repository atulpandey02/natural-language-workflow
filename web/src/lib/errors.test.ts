import { describe, expect, it } from "vitest";
import { ApiError, toApiError, userMessageForStatus } from "./errors";

describe("toApiError", () => {
  it("parses the backend error envelope", () => {
    const err = toApiError(409, { error: { code: "conflict", message: "cap reached" } }, "req-1");
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(409);
    expect(err.code).toBe("conflict");
    expect(err.message).toBe("cap reached");
    expect(err.requestId).toBe("req-1");
  });

  it("falls back safely on a non-enveloped body", () => {
    const err = toApiError(500, "boom");
    expect(err.code).toBe("error");
    expect(err.status).toBe(500);
  });
});

describe("userMessageForStatus", () => {
  it("maps status codes to safe UX messages", () => {
    expect(userMessageForStatus(401, "x")).toMatch(/session/i);
    expect(userMessageForStatus(403, "x")).toMatch(/permission/i);
    expect(userMessageForStatus(429, "x")).toMatch(/going too fast/i);
    expect(userMessageForStatus(503, "x")).toMatch(/unavailable/i);
    expect(userMessageForStatus(409, "cap reached")).toBe("cap reached");
    expect(userMessageForStatus(422, "bad field")).toBe("bad field");
  });
});
