import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { PlanProposalOut, FeasibilityStatus } from "@/lib/api/types";

// The real clarification flow: submit a request, receive NEEDS_CLARIFICATION with a
// question, then EDIT the request and re-submit to receive an actionable proposal.
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));
vi.mock("@/components/AppShell", () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

function proposal(status: FeasibilityStatus, id: string): PlanProposalOut {
  return {
    id,
    status,
    workflow_name: "WF",
    provider: "stub",
    model: "stub",
    proposed_plan: { steps: [{ id: "a", tool: "fake.echo" }] },
    normalized_plan: status === "PASS" ? { steps: [{ id: "a", tool: "fake.echo" }] } : null,
    feasibility: { findings: [] },
    clarification_questions:
      status === "NEEDS_CLARIFICATION" ? ["Which table should I query?"] : null,
    workflow_version_id: null,
  };
}

const mutateAsync = vi.fn();
vi.mock("@/lib/api/hooks", () => ({
  useCreatePlan: () => ({ mutateAsync, isPending: false, error: null }),
  useMaterialize: () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false, error: null }),
}));

import NewWorkflowPage from "./page";

function renderPage() {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <NewWorkflowPage />
    </QueryClientProvider>,
  );
}

describe("new-workflow clarification + edit/resubmit flow", () => {
  it("shows the clarification question, then resolves it on an edited resubmit", async () => {
    mutateAsync
      .mockResolvedValueOnce(proposal("NEEDS_CLARIFICATION", "p1"))
      .mockResolvedValueOnce(proposal("PASS", "p2"));
    renderPage();

    const textarea = screen.getByLabelText(/what should this workflow do/i);
    fireEvent.change(textarea, { target: { value: "Summarize failed payments." } });
    fireEvent.click(screen.getByRole("button", { name: /^plan$/i }));

    // The actionable clarification question is displayed and Materialize is blocked.
    await waitFor(() =>
      expect(screen.getByText(/which table should i query\?/i)).toBeInTheDocument(),
    );
    expect(screen.getByTestId("materialize-blocked")).toBeInTheDocument();

    // The user EDITS the request (the textarea keeps its value) and re-submits.
    fireEvent.change(textarea, {
      target: { value: "Query the payments table for yesterday's failures." },
    });
    fireEvent.click(screen.getByRole("button", { name: /^plan$/i }));

    // The clarification is gone and an actionable proposal (Materialize) is offered.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /materialize/i })).toBeInTheDocument(),
    );
    expect(screen.queryByText(/which table should i query\?/i)).toBeNull();
    expect(mutateAsync).toHaveBeenCalledTimes(2);
  });
});
