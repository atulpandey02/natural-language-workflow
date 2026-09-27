import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { PlanReview } from "./PlanReview";
import type { PlanProposalOut, FeasibilityStatus } from "@/lib/api/types";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

function proposal(status: FeasibilityStatus): PlanProposalOut {
  return {
    id: "11111111-2222-3333-4444-555555555555",
    status,
    workflow_name: "Test WF",
    provider: "stub",
    model: "stub",
    proposed_plan: { steps: [{ id: "a", tool: "fake.echo" }] },
    normalized_plan: null,
    feasibility: { findings: [] },
    clarification_questions: status === "NEEDS_CLARIFICATION" ? ["Which table?"] : null,
    workflow_version_id: null,
  };
}

function renderReview(status: FeasibilityStatus) {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <PlanReview proposal={proposal(status)} />
    </QueryClientProvider>,
  );
}

describe("PlanReview materialization gating", () => {
  it("shows the immutable Slack text and destination verbatim with no editable message", () => {
    const message = "Sales summary\nRevenue: $280,617.20\nLiteral <script>text</script> & symbols";
    const client = new QueryClient();
    const data: PlanProposalOut = {
      ...proposal("NEEDS_APPROVAL"),
      proposed_plan: {
        steps: [{ id: "send", tool: "slack.post_message", args: { text: message } }],
      },
      analytics_source: {
        source_run_id: "source-run",
        contract_version: "analytics-1",
        message_digest: "a".repeat(64),
        connector_id: "connector",
        channel: "CPILOT",
        result_digest: "b".repeat(64),
        connector_type: "slack",
        config_fingerprint: "c".repeat(64),
      },
    };
    const { container } = render(
      <QueryClientProvider client={client}>
        <PlanReview proposal={data} />
      </QueryClientProvider>,
    );
    expect(screen.getByLabelText("Immutable Slack message").textContent).toBe(message);
    expect(screen.getByText("CPILOT")).toBeVisible();
    expect(screen.getByRole("link", { name: "Open source analysis run" })).toHaveAttribute(
      "href",
      "/runs/source-run",
    );
    expect(screen.getByText("a".repeat(64))).toBeVisible();
    expect(container.querySelector("script, textarea, [contenteditable='true']")).toBeNull();
  });
  it("offers Materialize for PASS", () => {
    renderReview("PASS");
    expect(screen.getByRole("button", { name: /materialize/i })).toBeInTheDocument();
    expect(screen.queryByTestId("materialize-blocked")).toBeNull();
  });

  it("offers Materialize for NEEDS_APPROVAL", () => {
    renderReview("NEEDS_APPROVAL");
    expect(screen.getByRole("button", { name: /materialize/i })).toBeInTheDocument();
  });

  it("blocks Materialize for REJECT", () => {
    renderReview("REJECT");
    expect(screen.queryByRole("button", { name: /materialize/i })).toBeNull();
    expect(screen.getByTestId("materialize-blocked")).toBeInTheDocument();
  });

  it("blocks Materialize for NEEDS_CLARIFICATION", () => {
    renderReview("NEEDS_CLARIFICATION");
    expect(screen.queryByRole("button", { name: /materialize/i })).toBeNull();
    expect(screen.getByText(/Which table\?/)).toBeInTheDocument();
  });
});
