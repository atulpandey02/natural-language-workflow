import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import type { ReactNode } from "react";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Bind each hook's REAL request path to the BFF allowlist. The BFF is a
// security boundary that rejects anything not explicitly allowed, so a hook
// whose URL is not allowlisted fails silently in production (404 before the
// upstream is ever contacted). This test fails if either side drifts.
vi.mock("@/lib/api/client", () => ({ api: { get: vi.fn() } }));
import { api } from "@/lib/api/client";
import { isAllowed } from "@/lib/bff/allowlist";
import { useRunSummary, useWorkflowProvenance } from "./hooks";

const get = api.get as unknown as Mock;
const ID = "11111111-2222-3333-4444-555555555555";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

afterEach(() => get.mockReset());

describe("summary / provenance hooks request allowlisted paths", () => {
  it("useRunSummary requests GET /runs/{id}/summary, which the BFF allows", async () => {
    get.mockResolvedValue({ run_status: "COMPLETED", outcome: "SUCCESS", steps: [] });
    renderHook(() => useRunSummary(ID), { wrapper });
    await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
    const path = get.mock.calls[0][0] as string;
    expect(path).toBe(`/runs/${ID}/summary`);
    expect(isAllowed("GET", path)).toBe(true);
  });

  it("useWorkflowProvenance requests GET /workflow-versions/{id}/provenance, which the BFF allows", async () => {
    get.mockResolvedValue({ workflow_version_id: ID, request_text: "x" });
    renderHook(() => useWorkflowProvenance(ID), { wrapper });
    await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
    const path = get.mock.calls[0][0] as string;
    expect(path).toBe(`/workflow-versions/${ID}/provenance`);
    expect(isAllowed("GET", path)).toBe(true);
  });

  it("useWorkflowProvenance does not request anything without a version id", async () => {
    renderHook(() => useWorkflowProvenance(null), { wrapper });
    await new Promise((r) => setTimeout(r, 20));
    expect(get).not.toHaveBeenCalled();
  });
});
