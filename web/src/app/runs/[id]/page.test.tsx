import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ApiError } from "@/lib/errors";

// Isolate the page: stub the shell, mock every hook it reads.
vi.mock("@/components/AppShell", () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock("@/lib/api/hooks", () => ({
  useRun: vi.fn(),
  useRunSteps: vi.fn(),
  useRunActions: vi.fn(),
  useRunSummary: vi.fn(),
  useWorkflowProvenance: vi.fn(() => ({ data: undefined })),
}));

vi.mock("@/components/AnalyticsPanel", () => ({
  AnalyticsPanel: () => <div>Analytics panel</div>,
}));

import RunDetailPage from "./page";
import { useRun, useRunActions, useRunSteps, useRunSummary } from "@/lib/api/hooks";

const mockRun = useRun as unknown as Mock;
const mockSteps = useRunSteps as unknown as Mock;
const mockActions = useRunActions as unknown as Mock;
const mockSummary = useRunSummary as unknown as Mock;

const ID = "11111111-2222-3333-4444-555555555555";

const RUN = {
  id: ID,
  workflow_id: "w",
  workflow_version_id: "v",
  status: "COMPLETED",
  trigger: "manual",
  schedule_id: null,
  scheduled_for: null,
  error: null,
  started_at: null,
  finished_at: null,
  created_at: "2026-09-26T00:00:00Z",
};

const SUMMARY = {
  run_status: "COMPLETED",
  outcome: "SUCCESS",
  headline: "1 of 1 steps succeeded",
  steps: [{ step_id: "a", tool: "fake.echo", outcome: "SUCCESS", detail: "ok" }],
  total_steps: 1,
  succeeded: 1,
  failed: 0,
  unknown: 0,
  skipped: 0,
  truncated: false,
};

function setup(summary: { data?: unknown; error?: unknown; isLoading?: boolean }): void {
  mockRun.mockReturnValue({ isLoading: false, error: null, data: RUN });
  mockSteps.mockReturnValue({ isLoading: false, error: null, data: [] });
  mockActions.mockReturnValue({ isLoading: false, error: null, data: [] });
  mockSummary.mockReturnValue({
    isLoading: summary.isLoading ?? false,
    error: summary.error ?? null,
    data: summary.data,
  });
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
  return render(<RunDetailPage params={settled({ id: ID })} />);
}

afterEach(() => vi.clearAllMocks());

describe("RunDetailPage result summary", () => {
  it("does not expose raw step output even when evidence is expanded", async () => {
    setup({ data: SUMMARY });
    mockSteps.mockReturnValue({
      data: [
        {
          step_id: "a",
          tool: "fake.echo",
          status: "COMPLETED",
          output_preview: { confidential: "PRIVATE_TOOL_OUTPUT" },
        },
      ],
    });
    renderPage();
    await screen.findByTestId("run-summary");
    fireEvent.click(screen.getByText("Workflow & evidence details", { selector: "summary" }));
    expect(screen.getByRole("heading", { name: "Workflow & evidence" })).toBeVisible();
    expect(screen.queryByText(/PRIVATE_TOOL_OUTPUT/)).toBeNull();
  });
  it("renders the summary card when the summary read succeeds", async () => {
    setup({ data: SUMMARY });
    renderPage();
    expect(await screen.findByTestId("run-summary")).toBeInTheDocument();
    expect(screen.getByTestId("summary-headline")).toHaveTextContent("1 of 1 steps succeeded");
    expect(screen.queryByTestId("run-summary-error")).not.toBeInTheDocument();
  });

  it("shows the safe error UI instead of silently dropping the panel on failure", async () => {
    // A BFF rejection (404 before the backend is reached) used to remove the
    // panel with no trace; it must now be visible to the operator.
    setup({
      error: new ApiError({
        status: 404,
        code: "not_found",
        message: "Unknown resource.",
        requestId: "5f2c9a1e-8b7d-4c3a-9e1f-0a2b3c4d5e6f",
      }),
    });
    renderPage();
    const card = await screen.findByTestId("run-summary-error");
    expect(card).toHaveTextContent("Result summary");
    expect(screen.getByRole("alert")).toHaveTextContent("We couldn't find that");
    expect(screen.getByRole("alert")).not.toHaveTextContent("Unknown resource.");
    expect(screen.getByRole("alert")).toHaveTextContent("Reference: 5f2c9a1e-8b7");
    expect(screen.queryByTestId("run-summary")).not.toBeInTheDocument();
  });

  it("maps an outage to the status-aware message, never the raw error", async () => {
    setup({
      error: new ApiError({ status: 503, code: "service_unavailable", message: "upstream" }),
    });
    renderPage();
    await screen.findByTestId("run-summary-error");
    expect(screen.getByRole("alert")).toHaveTextContent("Temporarily unavailable");
    expect(screen.getByRole("alert")).not.toHaveTextContent("upstream");
  });

  it("shows neither the card nor an error while the summary is still loading", async () => {
    setup({ isLoading: true });
    renderPage();
    // The run header renders once params resolve; the summary area stays empty.
    await screen.findByText(/^Run /);
    expect(screen.queryByTestId("run-summary")).not.toBeInTheDocument();
    expect(screen.queryByTestId("run-summary-error")).not.toBeInTheDocument();
  });

  it.each([
    ["FAILED", "This run didn't finish"],
    ["FAILED_WITH_UNKNOWN", "We can't confirm whether the action happened"],
  ])("explains a %s run instead of showing the engine's raw error", async (outcome, title) => {
    setup({ data: { ...SUMMARY, run_status: "FAILED", outcome } });
    mockRun.mockReturnValue({
      isLoading: false,
      error: null,
      data: {
        ...RUN,
        status: "FAILED",
        error: "slack.send_message: ReadTimeout after 10.0s (httpx) tenant=9b1deb4d",
      },
    });
    renderPage();
    const notice = await screen.findByText(title);
    expect(notice.closest("[data-testid=friendly-error]")).toHaveAttribute("role", "status");
    expect(document.body.textContent).not.toMatch(/ReadTimeout|httpx|tenant=/);
    if (outcome === "FAILED_WITH_UNKNOWN") {
      expect(document.body.textContent).toMatch(/Don't simply run it again/);
      expect(document.body.textContent).not.toMatch(/You can try again now/);
    }
  });

  it("shows one explanation, not a cascade, when the run can't be loaded", async () => {
    setup({ error: new ApiError({ status: 404, code: "not_found", message: "run not found" }) });
    mockRun.mockReturnValue({
      isLoading: false,
      error: new ApiError({ status: 404, code: "not_found", message: "run not found" }),
      data: undefined,
    });
    renderPage();
    expect(await screen.findByText("We couldn't find that")).toBeInTheDocument();
    expect(screen.getAllByTestId("friendly-error")).toHaveLength(1);
    expect(screen.queryByText("Analytics panel")).toBeNull();
    expect(screen.getByRole("link", { name: "Back to runs" })).toHaveAttribute("href", "/runs");
  });
});
