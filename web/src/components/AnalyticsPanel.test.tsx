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
    expect(screen.getByRole("button", { name: "Send summary to Slack" })).toBeEnabled();
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
  it.each([
    [
      "INVALID",
      {
        ...fixture,
        status: "INVALID",
        metrics: [],
        tables: [],
        visualizations: [],
        findings: [],
        source_step_ids: [],
      },
    ],
    ["malformed READY", { status: "READY" }],
    ["rejected contract", { ...fixture, contract_version: "analytics-2" }],
    ["rejected markup", { ...fixture, title: "<script>alert(1)</script>" }],
    ["unexpected raw fields", { ...fixture, raw_output: "confidential" }],
    ["partial", { ...fixture, status: "PARTIAL", run_outcome: "FAILED" }],
    ["failed READY", { ...fixture, run_outcome: "FAILED" }],
    ["partial UNKNOWN", { ...fixture, status: "PARTIAL", run_outcome: "FAILED_WITH_UNKNOWN" }],
    ["UNKNOWN READY", { ...fixture, run_outcome: "FAILED_WITH_UNKNOWN" }],
  ])("does not expose sharing for %s analytics", (_label, data) => {
    state.data = data;
    render(<AnalyticsPanel runId="r" />);
    expect(screen.queryByLabelText("Slack destination")).toBeNull();
    expect(screen.queryByRole("button", { name: "Send summary to Slack" })).toBeNull();
    expect(mutateAsync).not.toHaveBeenCalled();
  });
  it("hides cached READY sharing when the latest query rejects its result", () => {
    state.data = fixture;
    state.error = new Error("This analysis could not be validated.");
    render(<AnalyticsPanel runId="r" />);
    expect(screen.getByRole("alert")).toHaveTextContent("could not be validated");
    expect(screen.queryByRole("button", { name: "Send summary to Slack" })).toBeNull();
  });
  it("hides the share action and existing proposal review if analytics becomes invalid", async () => {
    state.data = fixture;
    mutateAsync.mockResolvedValue({ id: "proposal" });
    const { rerender } = render(<AnalyticsPanel runId="r" />);
    fireEvent.change(screen.getByLabelText("Slack destination"), {
      target: { value: "connector:CPILOT" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send summary to Slack" }));
    expect(await screen.findByText("Immutable proposal review")).toBeVisible();
    state.data = { status: "READY" };
    rerender(<AnalyticsPanel runId="r" />);
    expect(screen.queryByRole("button", { name: "Send summary to Slack" })).toBeNull();
    expect(screen.queryByText("Immutable proposal review")).toBeNull();
    expect(mutateAsync).toHaveBeenCalledTimes(1);
  });
});
