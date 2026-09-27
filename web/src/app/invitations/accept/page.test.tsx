import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";

const replace = vi.fn();
let search = "?token=tok_123";
vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace, push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(search),
}));
vi.mock("@/lib/api/hooks", () => ({
  useAcceptInvitation: vi.fn(),
  useMe: vi.fn(),
  useWorkspaces: vi.fn(),
}));
vi.mock("@/lib/workspace-client", () => ({
  hardNavigate: vi.fn(),
  postWorkspaceSelection: vi.fn(),
}));

import AcceptInvitationPage from "./page";
import { useAcceptInvitation, useMe, useWorkspaces } from "@/lib/api/hooks";
import { ApiError } from "@/lib/errors";

const WS = "33333333-2222-3333-4444-555555555555";

beforeEach(() => {
  search = "?token=tok_123";
  (useMe as Mock).mockReturnValue({ data: { id: "u1", email: "approver@pilot.example" } });
  (useWorkspaces as Mock).mockReturnValue({ data: [{ id: WS, name: "NLW Pilot Workspace" }] });
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
