import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";

vi.mock("@/components/AppShell", () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock("@/lib/api/hooks", () => ({
  useApprovals: vi.fn(),
  useCurrentWorkspace: vi.fn(),
  useDecideApproval: vi.fn(() => ({ mutate: vi.fn(), isPending: false, error: null })),
  useMe: vi.fn(() => ({ data: { id: "me-user-id-0000-0000-000000000000" } })),
}));

import ApprovalsPage from "./page";
import { useApprovals, useCurrentWorkspace } from "@/lib/api/hooks";

const REQUESTER = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d";
function approval(overrides: object = {}) {
  return {
    id: "a1",
    run_id: "11111111-2222-3333-4444-555555555555",
    step_id: "send",
    tool: "slack.send_message",
    connector_name: "pilot-slack",
    status: "pending",
    requested_at: "2026-09-27T10:00:00Z",
    decided_at: null,
    requested_by_user_id: REQUESTER,
    viewer_can_decide: true,
    destination: "CPILOT",
    payload_review_blocked: false,
    preview: { tool: "slack.send_message", args: { text: "Sales summary\nRevenue: $1" } },
    ...overrides,
  };
}

function setup(role: string, items: object[]) {
  (useCurrentWorkspace as unknown as Mock).mockReturnValue({ data: { role } });
  (useApprovals as unknown as Mock).mockReturnValue({ isLoading: false, error: null, data: items });
}

afterEach(() => vi.clearAllMocks());

describe("ApprovalsPage", () => {
  it("shows the action, destination and exact message without ids or raw JSON", () => {
    setup("admin", [approval()]);
    const { container } = render(<ApprovalsPage />);
    expect(screen.getByRole("heading", { name: "Share to Slack (after approval)" })).toBeVisible();
    expect(screen.getByText("CPILOT")).toBeVisible();
    expect(screen.getByLabelText("Exact message to be sent").textContent).toBe(
      "Sales summary\nRevenue: $1",
    );
    expect(screen.getByText("another workspace member")).toBeVisible();
    const text = container.textContent ?? "";
    expect(text).not.toContain(REQUESTER);
    expect(text).not.toContain("slack.send_message");
    expect(text).not.toMatch(/"args"|"tool"/);
    expect(screen.getByRole("button", { name: "Approve" })).toBeEnabled();
  });

  it("tells the requester someone else must approve (no controls)", () => {
    setup("owner", [
      approval({
        requested_by_user_id: "me-user-id-0000-0000-000000000000",
        viewer_can_decide: false,
      }),
    ]);
    render(<ApprovalsPage />);
    expect(screen.getByText("you")).toBeVisible();
    expect(screen.getByRole("note")).toHaveTextContent("someone else must approve it");
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("hides decision controls from plain members", () => {
    setup("member", [approval()]);
    render(<ApprovalsPage />);
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.getByText(/an admin or owner must decide them/)).toBeVisible();
  });
});
