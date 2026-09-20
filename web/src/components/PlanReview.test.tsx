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
