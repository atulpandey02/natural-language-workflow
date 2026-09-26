import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import fixture from "@/test/analytics-fixture.json";
const state = vi.hoisted(() => ({
  data: undefined as unknown,
  error: null as unknown,
  isLoading: false,
}));
const mutateAsync = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api/analytics-hooks", () => ({
  useRunAnalytics: () => state,
  useSlackProposal: () => ({ mutateAsync, isPending: false, error: null }),
}));
vi.mock("@/lib/api/hooks", () => ({
  useConnectors: () => ({
    data: [
      {
        id: "connector",
        name: "Team",
        type: "slack",
        status: "active",
        config: { default_channel: "CPILOT" },
      },
    ],
  }),
}));
vi.mock("./AnalyticsResult", () => ({ AnalyticsResultView: () => <div>Validated result</div> }));
vi.mock("./PlanReview", () => ({ PlanReview: () => <div>Immutable proposal review</div> }));
import { AnalyticsPanel } from "./AnalyticsPanel";
beforeEach(() => {
  state.data = undefined;
  state.error = null;
  state.isLoading = false;
  mutateAsync.mockReset();
});
describe("analytics result states and server-owned Slack message", () => {
  it("shows accessible loading", () => {
    state.isLoading = true;
    render(<AnalyticsPanel runId="r" />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading analytical evidence");
  });
  it("shows read errors", () => {
    state.error = new Error("Result unavailable");
    render(<AnalyticsPanel runId="r" />);
    expect(screen.getByRole("alert")).toHaveTextContent("Result unavailable");
  });
  it("sends only connector and channel to the backend", async () => {
    state.data = fixture;
    mutateAsync.mockResolvedValue({ id: "proposal" });
    render(<AnalyticsPanel runId="r" />);
    fireEvent.change(screen.getByLabelText("Slack destination"), {
      target: { value: "connector:CPILOT" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send summary to Slack" }));
    await waitFor(() =>
      expect(mutateAsync).toHaveBeenCalledWith({ connector_id: "connector", channel: "CPILOT" }),
    );
    expect(await screen.findByText("Immutable proposal review")).toBeVisible();
  });
  it("does not offer sharing for partial or failed work", () => {
    state.data = { ...fixture, status: "PARTIAL", run_outcome: "FAILED" };
    render(<AnalyticsPanel runId="r" />);
    expect(screen.queryByRole("button", { name: "Send summary to Slack" })).toBeNull();
  });
});
