import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import type { ReactNode } from "react";
import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api/client", () => ({ api: { get: vi.fn(), post: vi.fn(), del: vi.fn() } }));
import { api } from "@/lib/api/client";
import { ApiError, RequestInterruptedError } from "@/lib/errors";
import { isMarkedNotQueued, loadPending } from "@/lib/datasets";
import { useUploadFlow, useVersion, type UploadDeps } from "./dataset-hooks";
import type { DatasetVersionOut } from "./types";

const get = api.get as unknown as Mock;
const D = "22222222-2222-4222-8222-222222222222";
const V = "11111111-1111-4111-8111-111111111111";

function version(over: Partial<DatasetVersionOut> = {}): DatasetVersionOut {
  return {
    id: V,
    dataset_id: D,
    version_number: 1,
    status: "QUARANTINED",
    original_filename: "orders.csv",
    media_type: "text/csv",
    declared_size_bytes: 12,
    content_sha256: null,
    rejection_code: null,
    created_by: "u",
    created_at: "2026-10-14T10:00:00Z",
    activated_at: null,
    superseded_at: null,
    rejected_at: null,
    deletion_requested_at: null,
    has_content: false,
    profiling_started_at: null,
    profiled_at: null,
    ...over,
  };
}

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

function csv(name = "orders.csv", body = "a,b\n1,2\n3,4\n", lastModified = 1): File {
  return new File([body], name, { type: "text/csv", lastModified });
}

function deps(over: Partial<UploadDeps> = {}): UploadDeps & { initiate: Mock; send: Mock } {
  let n = 0;
  return {
    newKey: () => `key-${++n}`,
    initiate: vi.fn().mockResolvedValue(version()),
    send: vi.fn().mockImplementation((_d, _v, file: File, onProgress) => {
      onProgress({ loaded: file.size / 2, total: file.size });
      onProgress({ loaded: file.size, total: file.size });
      return Promise.resolve(version({ has_content: true }));
    }),
    ...over,
  } as UploadDeps & { initiate: Mock; send: Mock };
}

beforeEach(() => window.sessionStorage.clear());
afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("useUploadFlow", () => {
  it("initiates with an Idempotency-Key, sends the file and reports progress", async () => {
    const d = deps();
    const { result } = renderHook(() => useUploadFlow(D, 1000, d), { wrapper });
    await act(() => result.current.start(csv()));
    expect(d.initiate).toHaveBeenCalledWith(
      D,
      { original_filename: "orders.csv", declared_size_bytes: 12 },
      "key-1",
    );
    expect(d.send).toHaveBeenCalledTimes(1);
    expect(result.current.state).toMatchObject({ phase: "done", outcome: "queued", versionId: V });
    expect(result.current.state.progress).toEqual({ loaded: 12, total: 12 });
    expect(loadPending(D)).toBeNull(); // finished: the next upload is a new version
  });

  it("a lost initiation response is retried with the SAME key (no second version)", async () => {
    const d = deps();
    d.initiate.mockRejectedValueOnce(new RequestInterruptedError("POST"));
    const { result } = renderHook(() => useUploadFlow(D, 1000, d), { wrapper });
    await act(() => result.current.start(csv()));
    expect(result.current.state).toMatchObject({ phase: "failed", outcome: "interrupted" });
    expect(result.current.canRetry).toBe(true);
    await act(() => result.current.start(csv()));
    expect(d.initiate.mock.calls.map((c) => c[2])).toEqual(["key-1", "key-1"]);
    expect(result.current.state.outcome).toBe("queued");
  });

  it("a lost upload response does not resend bytes the version already holds", async () => {
    const d = deps();
    d.send.mockRejectedValueOnce(new RequestInterruptedError("PUT"));
    const { result } = renderHook(() => useUploadFlow(D, 1000, d), { wrapper });
    await act(() => result.current.start(csv()));
    expect(result.current.state.outcome).toBe("interrupted");
    // The server had stored it: the retried initiation returns the same version, with content.
    d.initiate.mockResolvedValueOnce(version({ has_content: true }));
    await act(() => result.current.start(csv()));
    expect(d.initiate.mock.calls.map((c) => c[2])).toEqual(["key-1", "key-1"]);
    expect(d.send).toHaveBeenCalledTimes(1);
    expect(result.current.state).toMatchObject({ phase: "done", outcome: "queued", versionId: V });
  });

  it("survives a reload: the remembered key resumes the same version", async () => {
    const d = deps();
    d.send.mockRejectedValueOnce(new RequestInterruptedError("PUT"));
    const first = renderHook(() => useUploadFlow(D, 1000, d), { wrapper });
    await act(() => first.result.current.start(csv()));
    first.unmount(); // the page reloads; sessionStorage persists
    expect(loadPending(D)).toMatchObject({ key: "key-1", versionId: V, filename: "orders.csv" });
    const again = renderHook(() => useUploadFlow(D, 1000, d), { wrapper });
    await act(() => again.result.current.start(csv()));
    expect(d.initiate.mock.calls.map((c) => c[2])).toEqual(["key-1", "key-1"]);
  });

  it("a committed upload that was not queued is remembered and needs recovery", async () => {
    const d = deps();
    d.send.mockRejectedValueOnce(
      new ApiError({ status: 503, code: "PROCESSING_NOT_QUEUED", message: "x" }),
    );
    const { result } = renderHook(() => useUploadFlow(D, 1000, d), { wrapper });
    await act(() => result.current.start(csv()));
    expect(result.current.state).toMatchObject({
      phase: "done",
      outcome: "not_queued",
      versionId: V,
    });
    expect(isMarkedNotQueued(V)).toBe(true);
    expect(loadPending(D)).toBeNull();
  });

  it("a different file gets a different key", async () => {
    const d = deps();
    d.send.mockRejectedValueOnce(new RequestInterruptedError("PUT"));
    const { result } = renderHook(() => useUploadFlow(D, 1000, d), { wrapper });
    await act(() => result.current.start(csv()));
    await act(() => result.current.start(csv("other.csv", "x,y\n1,2\n", 9)));
    expect(d.initiate.mock.calls.map((c) => c[2])).toEqual(["key-1", "key-2"]);
  });

  it.each([
    [new ApiError({ status: 413, code: "CONTENT_TOO_LARGE", message: "x" }), "too_large"],
    [new ApiError({ status: 409, code: "CONTENT_CONFLICT", message: "x" }), "conflict"],
    [new ApiError({ status: 403, code: "forbidden", message: "x" }), "forbidden"],
    [new ApiError({ status: 500, code: "internal_error", message: "Traceback secret" }), "unknown"],
  ])("classifies a refused upload (%s)", async (error, outcome) => {
    const d = deps();
    d.send.mockRejectedValueOnce(error);
    const { result } = renderHook(() => useUploadFlow(D, 1000, d), { wrapper });
    await act(() => result.current.start(csv()));
    expect(result.current.state).toMatchObject({ phase: "failed", outcome });
  });

  it("refuses an oversized or non-CSV file before sending anything", async () => {
    const d = deps();
    const { result } = renderHook(() => useUploadFlow(D, 5, d), { wrapper });
    await act(() => result.current.start(csv()));
    expect(result.current.state.refused).toMatch(/maximum is 5 bytes/);
    await act(() => result.current.start(csv("orders.xlsx")));
    expect(result.current.state.refused).toBe("Choose a .csv file.");
    expect(d.initiate).not.toHaveBeenCalled();
    expect(d.send).not.toHaveBeenCalled();
  });
});

describe("useVersion polling", () => {
  it("polls a queued version with backoff and stops at a settled state", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    get
      .mockResolvedValueOnce(version({ has_content: true }))
      .mockResolvedValueOnce(version({ status: "PROFILING", has_content: true }))
      .mockResolvedValue(version({ status: "PROFILED", has_content: true }));
    const { result } = renderHook(() => useVersion(D, V), { wrapper });
    await waitFor(() => expect(result.current.data?.status).toBe("QUARANTINED"));
    await act(async () => void (await vi.advanceTimersByTimeAsync(1000)));
    await waitFor(() => expect(result.current.data?.status).toBe("PROFILING"));
    await act(async () => void (await vi.advanceTimersByTimeAsync(2000)));
    await waitFor(() => expect(result.current.data?.status).toBe("PROFILED"));
    const calls = get.mock.calls.length;
    await act(async () => void (await vi.advanceTimersByTimeAsync(120_000)));
    expect(get.mock.calls.length).toBe(calls); // settled: no further polling
  });

  it("never polls a version waiting for its file", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    get.mockResolvedValue(version());
    const { result } = renderHook(() => useVersion(D, V), { wrapper });
    await waitFor(() => expect(result.current.data).toBeDefined());
    await act(async () => void (await vi.advanceTimersByTimeAsync(60_000)));
    expect(get).toHaveBeenCalledTimes(1);
  });
});
