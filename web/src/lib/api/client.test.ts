import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./client";
import { ApiError } from "@/lib/errors";

function mockFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  const fn = vi.fn(
    async (_input: string | URL | Request, _init?: RequestInit) =>
      new Response(body === null ? "" : JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json", ...headers },
      }),
  );
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => vi.unstubAllGlobals());

describe("api client", () => {
  it("calls the same-origin BFF and returns parsed JSON", async () => {
    const fn = mockFetch(200, [{ id: "1" }]);
    const data = await api.get<{ id: string }[]>("/workflows");
    expect(data[0].id).toBe("1");
    expect(fn.mock.calls[0][0]).toBe("/api/nlw/workflows");
  });

  it("throws a typed ApiError with the request id on failure", async () => {
    mockFetch(409, { error: { code: "conflict", message: "cap" } }, { "X-Request-Id": "r-9" });
    await expect(api.post("/connectors", {})).rejects.toMatchObject({
      status: 409,
      code: "conflict",
      requestId: "r-9",
    });
    await expect(api.post("/connectors", {})).rejects.toBeInstanceOf(ApiError);
  });

  it("forwards the Idempotency-Key header when provided", async () => {
    const fn = mockFetch(201, { run_id: "abc" });
    await api.post("/workflows/x/runs", undefined, "key-123");
    const init = fn.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["Idempotency-Key"]).toBe("key-123");
  });
});
