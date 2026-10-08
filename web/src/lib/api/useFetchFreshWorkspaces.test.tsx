import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import type { ReactNode } from "react";
import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api/client", () => ({ api: { get: vi.fn() } }));
import { api } from "@/lib/api/client";
import { useFetchFreshWorkspaces, useWorkspaces } from "./hooks";
import type { WorkspaceOut } from "./types";

const get = api.get as unknown as Mock;
const OLD = { id: "ws-old", name: "Personal" } as WorkspaceOut;
const JOINED = { id: "ws-joined", name: "Launch Review" } as WorkspaceOut;

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return { client, wrapper };
}

afterEach(() => get.mockReset());

describe("useFetchFreshWorkspaces", () => {
  it("issues a new request instead of joining a pre-change fetch still in flight", async () => {
    // The page-mount fetch is answered from before the membership existed and
    // is still in flight (no cached data) when the caller asks for a fresh list.
    const stale = deferred<WorkspaceOut[]>();
    get.mockReturnValueOnce(stale.promise).mockResolvedValueOnce([OLD, JOINED]);
    const { client, wrapper } = setup();
    renderHook(() => useWorkspaces(), { wrapper });
    await waitFor(() => expect(get).toHaveBeenCalledTimes(1));

    // Control: a plain invalidate dedupes onto the in-flight, pre-change request.
    void client.invalidateQueries({ queryKey: ["workspaces"] });
    expect(get).toHaveBeenCalledTimes(1);

    const { result } = renderHook(() => useFetchFreshWorkspaces(), { wrapper });
    let list: WorkspaceOut[] = [];
    await act(async () => {
      const pending = result.current();
      stale.resolve([OLD]);
      list = await pending;
    });

    expect(get).toHaveBeenCalledTimes(2);
    expect(list).toEqual([OLD, JOINED]);
    expect(client.getQueryData(["workspaces"])).toEqual([OLD, JOINED]);
  });

  it("refetches even when a cached list exists", async () => {
    get.mockResolvedValueOnce([OLD, JOINED]);
    const { client, wrapper } = setup();
    client.setQueryData(["workspaces"], [OLD]);
    const { result } = renderHook(() => useFetchFreshWorkspaces(), { wrapper });
    let list: WorkspaceOut[] = [];
    await act(async () => {
      list = await result.current();
    });
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith("/workspaces");
    expect(list).toEqual([OLD, JOINED]);
  });
});
