import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import type { ReactNode } from "react";
import { renderHook, act } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api/client", () => ({ api: { post: vi.fn() } }));
import { api } from "@/lib/api/client";
import { useRunNow } from "./hooks";

const post = api.post as unknown as Mock;

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

function keysUsed(): string[] {
  return post.mock.calls.map((c) => c[2] as string);
}

afterEach(() => post.mockReset());

describe("useRunNow idempotency key", () => {
  it("reuses ONE key across a double-click (two clicks, same logical action)", async () => {
    post.mockResolvedValue({ run_id: "r1", status: "PENDING", idempotent_hit: false });
    const { result } = renderHook(() => useRunNow("wf-1"), { wrapper });

    await act(async () => {
      await Promise.all([result.current.trigger(), result.current.trigger()]);
    });

    const keys = keysUsed();
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBe(keys[1]); // same key => backend dedupes to one run
  });

  it("reuses the SAME key when retrying a failed/ambiguous attempt", async () => {
    post.mockRejectedValueOnce(new Error("network")).mockResolvedValueOnce({
      run_id: "r1",
      status: "PENDING",
      idempotent_hit: true,
    });
    const { result } = renderHook(() => useRunNow("wf-1"), { wrapper });

    const keyBefore = result.current.currentKey();
    await act(async () => {
      await expect(result.current.trigger()).rejects.toThrow();
    });
    // A failed attempt must NOT rotate the key.
    expect(result.current.currentKey()).toBe(keyBefore);

    await act(async () => {
      await result.current.trigger(); // retry succeeds
    });

    const keys = keysUsed();
    expect(keys[0]).toBe(keyBefore); // failed attempt
    expect(keys[1]).toBe(keyBefore); // retry reused the SAME key
  });

  it("mints a NEW key only after a confirmed success (next logical action)", async () => {
    post.mockResolvedValue({ run_id: "r1", status: "PENDING", idempotent_hit: false });
    const { result } = renderHook(() => useRunNow("wf-1"), { wrapper });

    const firstKey = result.current.currentKey();
    await act(async () => {
      await result.current.trigger();
    });
    const secondKey = result.current.currentKey();
    expect(secondKey).not.toBe(firstKey);

    await act(async () => {
      await result.current.trigger();
    });
    expect(keysUsed()).toEqual([firstKey, secondKey]);
  });
});
