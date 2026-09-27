import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
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
  it("offers Save workflow for PASS", () => {
    renderReview("PASS");
    expect(screen.getByRole("button", { name: /save workflow/i })).toBeInTheDocument();
    expect(screen.queryByTestId("materialize-blocked")).toBeNull();
  });

  it("offers Save workflow for NEEDS_APPROVAL", () => {
    renderReview("NEEDS_APPROVAL");
    expect(screen.getByRole("button", { name: /save workflow/i })).toBeInTheDocument();
  });

  it("blocks saving for REJECT", () => {
    renderReview("REJECT");
    expect(screen.queryByRole("button", { name: /save workflow/i })).toBeNull();
    expect(screen.getByTestId("materialize-blocked")).toBeInTheDocument();
  });

  it("blocks saving for NEEDS_CLARIFICATION", () => {
    renderReview("NEEDS_CLARIFICATION");
    expect(screen.queryByRole("button", { name: /save workflow/i })).toBeNull();
    expect(screen.getByText(/Which table\?/)).toBeInTheDocument();
  });

  it("reads as plain language: step labels, friendly checks, no raw codes or messages", () => {
    const client = new QueryClient();
    const data: PlanProposalOut = {
      ...proposal("REJECT"),
      proposed_plan: {
        steps: [
          { id: "sales", tool: "pilot.sales_analysis" },
          {
            id: "send",
            tool: "slack.send_message",
            connector: "pilot-slack",
            depends_on: ["sales"],
          },
        ],
      },
      feasibility: {
        findings: [
          { code: "SQL_REJECTED", severity: "error", message: "psycopg: relation users denied" },
          { code: "MYSTERY_CODE", severity: "error", message: "internal detail 42" },
        ],
      },
    };
    const { container } = render(
      <QueryClientProvider client={client}>
        <PlanReview proposal={data} />
      </QueryClientProvider>,
    );
    expect(screen.getByText("Blocked")).toBeInTheDocument();
    expect(screen.getByTestId("plan-status-copy")).toHaveTextContent(/can't be used/);
    expect(screen.getByText("Analyze synthetic sales data")).toBeInTheDocument();
    expect(screen.getByText("Share to Slack (after approval)")).toBeInTheDocument();
    expect(screen.getByText("step 1")).toBeInTheDocument();
    const findings = screen.getByTestId("plan-findings");
    expect(findings).toHaveTextContent(/only safe, read-only queries/);
    expect(findings).toHaveTextContent("A safety check flagged this plan.");
    const text = container.textContent ?? "";
    for (const raw of [
      "SQL_REJECTED",
      "MYSTERY_CODE",
      "psycopg",
      "internal detail",
      "REJECT",
      "pilot.sales_analysis",
    ]) {
      expect(text).not.toContain(raw);
    }
  });

  it("separates the workflow, its data bindings, safety checks and the next action", () => {
    const client = new QueryClient();
    render(
      <QueryClientProvider client={client}>
        <PlanReview
          proposal={{
            ...proposal("PASS"),
            proposed_plan: { steps: [{ id: "analyze", tool: "pilot.sales_analysis" }] },
          }}
        />
      </QueryClientProvider>,
    );
    expect(screen.getByRole("heading", { level: 2, name: "Test WF" })).toBeVisible();
    expect(screen.getByText(/Drafted by the AI planner/)).toHaveClass("ai-tag");
    expect(screen.getByRole("region", { name: "Data and connectors" })).toHaveTextContent(
      "Synthetic sales-v1",
    );
    expect(screen.getByRole("region", { name: "Safety checks" })).toHaveTextContent(
      "All checks passed",
    );
    expect(
      within(screen.getByRole("region", { name: "Next action" })).getByRole("button", {
        name: "Save workflow",
      }),
    ).toBeEnabled();
  });
});
