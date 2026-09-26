import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";
import { ApiError } from "@/lib/errors";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));
vi.mock("@/components/AppShell", () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock("@/components/ScheduleForm", () => ({ ScheduleForm: () => null }));
vi.mock("@/lib/api/hooks", () => ({
  useCurrentWorkspace: vi.fn(),
  useRunNow: vi.fn(),
  useRuns: vi.fn(),
  useSchedules: vi.fn(),
  useWorkflow: vi.fn(),
  useWorkflowProvenance: vi.fn(),
}));

import WorkflowDetailPage from "./page";
import {
  useCurrentWorkspace,
  useRunNow,
  useRuns,
  useSchedules,
  useWorkflow,
  useWorkflowProvenance,
} from "@/lib/api/hooks";

const mockCurrent = useCurrentWorkspace as unknown as Mock;
const mockRunNow = useRunNow as unknown as Mock;
const mockRuns = useRuns as unknown as Mock;
const mockSchedules = useSchedules as unknown as Mock;
const mockWorkflow = useWorkflow as unknown as Mock;
const mockProvenance = useWorkflowProvenance as unknown as Mock;

const WF_ID = "11111111-2222-3333-4444-555555555555";
const VER_ID = "66666666-7777-8888-9999-000000000000";

const WORKFLOW = {
  id: WF_ID,
  name: "Nightly report",
  current_version_id: VER_ID,
  created_at: "2026-09-26T00:00:00Z",
  current_version: {
    id: VER_ID,
    workflow_id: WF_ID,
    version: 1,
    plan: { steps: [{ id: "a", tool: "fake.echo", args: {} }] },
  },
};

const PROVENANCE = {
  workflow_version_id: VER_ID,
  request_text: "Summarize yesterday's failed payments.",
  request_sha256: "abc",
  provider: "anthropic",
  model: "claude-haiku-4-5-20251001",
  planner_contract_version: "1",
  status: "PASS",
  created_at: "2026-09-26T00:00:00Z",
};

function setup(prov: { data?: unknown; error?: unknown }): void {
  mockCurrent.mockReturnValue({ data: { tenant_id: "t1", role: "member" } });
  mockRunNow.mockReturnValue({ trigger: vi.fn(), isPending: false, currentKey: () => "k" });
  mockRuns.mockReturnValue({ isLoading: false, error: null, data: [] });
  mockSchedules.mockReturnValue({ isLoading: false, error: null, data: [] });
  mockWorkflow.mockReturnValue({ isLoading: false, error: null, data: WORKFLOW });
  mockProvenance.mockReturnValue({ isLoading: false, error: prov.error ?? null, data: prov.data });
}

// React's `use()` returns synchronously for a thenable that already carries
// `status: "fulfilled"` (the documented thenable fast path), so the page renders
// without a Suspense round-trip in jsdom.
function settled<T>(value: T): Promise<T> {
  const p = Promise.resolve(value) as Promise<T> & { status?: string; value?: T };
  p.status = "fulfilled";
  p.value = value;
  return p;
}

function renderPage() {
  return render(<WorkflowDetailPage params={settled({ id: WF_ID })} />);
}

afterEach(() => vi.clearAllMocks());

describe("WorkflowDetailPage provenance", () => {
  it("asks for provenance of the CURRENT version and renders the original request", async () => {
    setup({ data: PROVENANCE });
    renderPage();
    const card = await screen.findByTestId("workflow-provenance");
    expect(card).toHaveTextContent("Summarize yesterday's failed payments.");
    expect(card).toHaveTextContent("anthropic/claude-haiku-4-5-20251001");
    expect(mockProvenance).toHaveBeenCalledWith(VER_ID);
    expect(screen.queryByTestId("workflow-provenance-error")).not.toBeInTheDocument();
  });

  it("shows the safe error UI instead of silently dropping the panel on failure", async () => {
    setup({
      error: new ApiError({ status: 404, code: "not_found", message: "Unknown resource." }),
    });
    renderPage();
    const card = await screen.findByTestId("workflow-provenance-error");
    expect(card).toHaveTextContent("Original request");
    expect(card).toHaveTextContent("Unknown resource.");
    expect(screen.queryByTestId("workflow-provenance")).not.toBeInTheDocument();
  });

  it("maps a permission failure to the status-aware message", async () => {
    setup({ error: new ApiError({ status: 403, code: "forbidden", message: "nope" }) });
    renderPage();
    const card = await screen.findByTestId("workflow-provenance-error");
    expect(card).toHaveTextContent("You do not have permission");
    expect(card).not.toHaveTextContent("nope");
  });

  it("renders nothing for provenance while it is still loading", async () => {
    setup({});
    renderPage();
    await screen.findByText("Nightly report");
    expect(screen.queryByTestId("workflow-provenance")).not.toBeInTheDocument();
    expect(screen.queryByTestId("workflow-provenance-error")).not.toBeInTheDocument();
  });
});
