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

  describe("conservative outcome precedence (F1/B1)", () => {
    const unknownAction = {
      step_id: "a",
      tool: "slack.send_message",
      destination_summary: "CPILOT",
      status: "unknown",
      attempts: 1,
      error_class: "ACTION_OUTCOME_UNKNOWN",
      http_status: null,
      last_attempt_at: null,
      next_attempt_at: null,
    };
    const outage = new ApiError({
      status: 503,
      code: "service_unavailable",
      message: "upstream",
      method: "GET",
    });
    const refetch = vi.fn();

    function arrange(
      runStatus: string,
      summary: { data?: unknown; error?: unknown; isLoading?: boolean },
      actions: { data?: unknown; error?: unknown; isLoading?: boolean },
    ) {
      setup(summary);
      mockSummary.mockReturnValue({
        isLoading: summary.isLoading ?? false,
        error: summary.error ?? null,
        data: summary.data,
        refetch,
      });
      mockRun.mockReturnValue({
        isLoading: false,
        error: null,
        data: { ...RUN, status: runStatus, error: "raw engine text" },
      });
      mockActions.mockReturnValue({
        isLoading: actions.isLoading ?? false,
        error: actions.error ?? null,
        data: actions.data,
        refetch,
      });
    }

    const stripStatus = () =>
      document.querySelector(".run-strip [data-status]")?.getAttribute("data-status");

    function expectNoSuccessOrRerun() {
      const text = document.body.textContent ?? "";
      expect(text).not.toMatch(/You can try again now|You can run the workflow again/);
      expect(text).not.toContain("This run didn't finish");
      expect(text).not.toContain("Nothing was changed");
      expect(document.querySelector(".run-strip .badge.ok")).toBeNull();
      expect(screen.queryByTestId("run-summary")).toBeNull();
    }

    it.each(["COMPLETED", "PARTIAL", "IN_PROGRESS", "FAILED", "WAITING_APPROVAL"])(
      "UNKNOWN action evidence overrides a %s summary",
      async (summaryOutcome) => {
        arrange(
          "COMPLETED",
          { data: { ...SUMMARY, run_status: summaryOutcome, outcome: summaryOutcome } },
          { data: [unknownAction] },
        );
        renderPage();
        expect(
          await screen.findByText("We can't confirm whether the action happened"),
        ).toBeVisible();
        expect(stripStatus()).toBe("ACTION_OUTCOME_UNKNOWN");
        expect(screen.getByTestId("run-summary-conflict")).toBeVisible();
        expect(screen.getAllByText(/Don't simply run it again/).length).toBeGreaterThan(0);
        // The unknown step reads "recorded" with a warning badge, never success.
        expect(document.querySelector("#evidence-a [data-status]")).toHaveAttribute(
          "data-status",
          "UNKNOWN",
        );
        expectNoSuccessOrRerun();
      },
    );

    it.each([
      ["summary loading", { isLoading: true }],
      ["summary 503", { error: outage }],
    ])("UNKNOWN action evidence with %s → UNKNOWN", async (_label, summary) => {
      arrange("FAILED", summary, { data: [unknownAction] });
      renderPage();
      expect(await screen.findByText("We can't confirm whether the action happened")).toBeVisible();
      expect(stripStatus()).toBe("ACTION_OUTCOME_UNKNOWN");
      expectNoSuccessOrRerun();
    });

    it("delayed summary with raw FAILED shows a neutral check, not FAILED", async () => {
      arrange("FAILED", { isLoading: true }, { data: [] });
      renderPage();
      expect(await screen.findByText("Checking this run's recorded outcome…")).toBeVisible();
      expect(stripStatus()).toBe("OUTCOME_PENDING");
      expect(screen.queryByRole("alert")).toBeNull();
      expectNoSuccessOrRerun();
    });

    it("delayed actions with raw COMPLETED shows a neutral check, not success", async () => {
      arrange("COMPLETED", { data: SUMMARY }, { isLoading: true });
      renderPage();
      expect(await screen.findByText("Checking this run's recorded outcome…")).toBeVisible();
      expect(stripStatus()).toBe("OUTCOME_PENDING");
      expectNoSuccessOrRerun();
    });

    it.each(["FAILED", "COMPLETED"])(
      "both evidence reads unavailable with raw %s → unconfirmed",
      async (runStatus) => {
        arrange(runStatus, { error: outage }, { error: outage });
        renderPage();
        expect(await screen.findByText("We can't confirm this run's full outcome")).toBeVisible();
        expect(stripStatus()).toBe("OUTCOME_UNAVAILABLE");
        const text = document.body.textContent ?? "";
        expect(text).toContain("Some steps may have run, including actions outside NLW.");
        expect(text).toMatch(/ask an administrator, before running it again/);
        expectNoSuccessOrRerun();
        // The only retry offered reloads evidence, and says so.
        const reload = screen.getByRole("button", { name: "Reload run evidence" });
        expect(screen.getByTestId("reload-evidence")).toHaveTextContent(
          "It doesn't run the workflow again.",
        );
        reload.click();
        expect(refetch).toHaveBeenCalled();
      },
    );

    it.each([
      ["COMPLETED", "ok"],
      ["FAILED", "fail"],
      ["FAILED_WITH_UNKNOWN", "warn"],
    ])("ordinary %s summary is shown as-is", async (summaryOutcome, style) => {
      arrange(
        summaryOutcome === "COMPLETED" ? "COMPLETED" : "FAILED",
        { data: { ...SUMMARY, outcome: summaryOutcome } },
        { data: [] },
      );
      renderPage();
      await screen.findByTestId("run-summary");
      expect(stripStatus()).toBe(summaryOutcome);
      expect(document.querySelector(".run-strip .badge")).toHaveClass(style);
      expect(screen.queryByTestId("reload-evidence")).toBeNull();
    });
  });
});
