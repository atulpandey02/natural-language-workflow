import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";

const replace = vi.fn();
let search = "?token=tok_123";
vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace, push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(search),
}));
vi.mock("@/lib/api/hooks", () => ({
  useAcceptInvitation: vi.fn(),
  useMe: vi.fn(),
  useFetchFreshWorkspaces: vi.fn(),
}));
vi.mock("@/lib/workspace-client", () => ({
  hardNavigate: vi.fn(),
  postWorkspaceSelection: vi.fn(),
}));

import AcceptInvitationPage from "./page";
import { useAcceptInvitation, useFetchFreshWorkspaces, useMe } from "@/lib/api/hooks";
import { ApiError } from "@/lib/errors";

const WS = "33333333-2222-3333-4444-555555555555";

let fetchFreshWorkspaces: Mock;

beforeEach(() => {
  search = "?token=tok_123";
  (useMe as Mock).mockReturnValue({ data: { id: "u1", email: "approver@pilot.example" } });
  fetchFreshWorkspaces = vi.fn().mockResolvedValue([{ id: WS, name: "NLW Pilot Workspace" }]);
  (useFetchFreshWorkspaces as Mock).mockReturnValue(fetchFreshWorkspaces);
  vi.spyOn(window.history, "replaceState");
});
afterEach(() => vi.clearAllMocks());

describe("Accept invitation", () => {
  it("joins the workspace, names it and never shows its identifier", async () => {
    const mutateAsync = vi.fn().mockResolvedValue({ workspace_id: WS, role: "admin" });
    (useAcceptInvitation as Mock).mockReturnValue({ mutateAsync });
    const { container } = render(<AcceptInvitationPage />);
    expect(await screen.findByText(/joined NLW Pilot Workspace as Admin/)).toBeVisible();
    expect(mutateAsync).toHaveBeenCalledTimes(1);
    expect(mutateAsync).toHaveBeenCalledWith("tok_123");
    expect(container.innerHTML).not.toContain(WS);
    expect(screen.getByTestId("accept-identity")).toHaveTextContent("approver@pilot.example");
    expect(window.history.replaceState).toHaveBeenCalledWith(null, "", "/invitations/accept");
  });

  it("names the joined workspace from a list fetched after acceptance, never a stale one", async () => {
    // Regression: the list fetched on mount predates the membership. The page
    // must not render the confirmation until a post-acceptance list resolves.
    const order: string[] = [];
    let resolveList!: (v: unknown) => void;
    const mutateAsync = vi.fn(async () => {
      order.push("accept");
      return { workspace_id: WS, role: "admin" };
    });
    fetchFreshWorkspaces.mockImplementation(() => {
      order.push("list");
      return new Promise((r) => (resolveList = r));
    });
    (useAcceptInvitation as Mock).mockReturnValue({ mutateAsync });
    render(<AcceptInvitationPage />);

    await waitFor(() => expect(fetchFreshWorkspaces).toHaveBeenCalledTimes(1));
    expect(order).toEqual(["accept", "list"]);
    // Accepted, but the name is not resolved yet: no generic placeholder card.
    expect(screen.queryByTestId("invitation-accepted")).toBeNull();
    expect(screen.getByText("Checking your invitation…")).toBeVisible();

    await act(async () => resolveList([{ id: WS, name: "Launch Review (synthetic)" }]));
    expect(screen.getByTestId("invitation-accepted")).toHaveTextContent(
      "You’ve joined Launch Review (synthetic) as Admin.",
    );
    expect(mutateAsync).toHaveBeenCalledTimes(1);
  });

  it("still confirms the accepted invitation if the workspace list cannot be fetched", async () => {
    const mutateAsync = vi.fn().mockResolvedValue({ workspace_id: WS, role: "member" });
    fetchFreshWorkspaces.mockRejectedValue(new Error("network"));
    (useAcceptInvitation as Mock).mockReturnValue({ mutateAsync });
    const { container } = render(<AcceptInvitationPage />);
    expect(await screen.findByTestId("invitation-accepted")).toHaveTextContent(
      "You’ve joined the workspace as Member.",
    );
    expect(screen.queryByTestId("invitation-failed")).toBeNull();
    expect(container.innerHTML).not.toContain(WS);
  });

  it("explains a rejected invitation without saying why it was rejected", async () => {
    const mutateAsync = vi
      .fn()
      .mockRejectedValue(
        new ApiError({ status: 400, code: "bad_request", message: "invitation is not valid" }),
      );
    (useAcceptInvitation as Mock).mockReturnValue({ mutateAsync });
    render(<AcceptInvitationPage />);
    const panel = await screen.findByTestId("invitation-failed");
    expect(panel).toHaveTextContent("This invitation is not valid.");
    expect(panel).toHaveTextContent("signed in with the invited email");
    expect(panel.textContent).not.toMatch(/expired|revoked|used by|wrong user/i);
    expect(fetchFreshWorkspaces).not.toHaveBeenCalled();
  });

  it("fails friendly without a token and never calls the API", async () => {
    search = "";
    const mutateAsync = vi.fn();
    (useAcceptInvitation as Mock).mockReturnValue({ mutateAsync });
    render(<AcceptInvitationPage />);
    expect(await screen.findByTestId("invitation-failed")).toBeVisible();
    expect(mutateAsync).not.toHaveBeenCalled();
  });
});
