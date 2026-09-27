import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("@/lib/api/hooks", () => ({
  useWorkspaces: vi.fn(),
  useCreateWorkspace: vi.fn(),
}));
vi.mock("@/lib/workspace-client", () => ({
  postWorkspaceSelection: vi.fn(),
  hardNavigate: vi.fn(),
}));

import SelectWorkspacePage from "./page";
import { useWorkspaces, useCreateWorkspace } from "@/lib/api/hooks";
import { postWorkspaceSelection, hardNavigate } from "@/lib/workspace-client";

const mockWorkspaces = useWorkspaces as unknown as Mock;
const mockCreate = useCreateWorkspace as unknown as Mock;
const mockPost = postWorkspaceSelection as unknown as Mock;
const mockNav = hardNavigate as unknown as Mock;

function setCreate() {
  mockCreate.mockReturnValue({ mutateAsync: vi.fn(), isPending: false, error: null });
}

afterEach(() => vi.clearAllMocks());

describe("SelectWorkspace", () => {
  it("does not expose workspace-ready while loading", () => {
    mockWorkspaces.mockReturnValue({ isLoading: true, error: null, data: undefined });
    setCreate();
    render(<SelectWorkspacePage />);
    expect(screen.queryByTestId("workspace-ready")).toBeNull();
  });

  it("exposes workspace-ready once loaded", () => {
    mockWorkspaces.mockReturnValue({
      isLoading: false,
      error: null,
      data: [{ id: "w1", name: "Alpha", role: "owner" }],
    });
    setCreate();
    render(<SelectWorkspacePage />);
    expect(screen.getByTestId("workspace-ready")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open" })).toBeInTheDocument();
  });

  it("hard-navigates on a successful workspace selection", async () => {
    mockWorkspaces.mockReturnValue({
      isLoading: false,
      error: null,
      data: [{ id: "w1", name: "Alpha", role: "owner" }],
    });
    setCreate();
    mockPost.mockResolvedValue(undefined);
    render(<SelectWorkspacePage />);
    await userEvent.click(screen.getByRole("button", { name: "Open" }));
    await waitFor(() => expect(mockNav).toHaveBeenCalledWith("/"));
  });

  it("does not navigate and shows a safe error on a failed selection", async () => {
    mockWorkspaces.mockReturnValue({
      isLoading: false,
      error: null,
      data: [{ id: "w1", name: "Alpha", role: "owner" }],
    });
    setCreate();
    mockPost.mockRejectedValue(new Error("Could not switch workspace. Please try again."));
    render(<SelectWorkspacePage />);
    await userEvent.click(screen.getByRole("button", { name: "Open" }));
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(mockNav).not.toHaveBeenCalled();
  });
});

describe("SelectWorkspace onboarding", () => {
  it("explains workspaces and the journey before creation", () => {
    mockWorkspaces.mockReturnValue({ isLoading: false, error: null, data: [] });
    setCreate();
    render(<SelectWorkspacePage />);
    expect(screen.getByRole("heading", { level: 1, name: "Welcome to NLW" })).toBeInTheDocument();
    expect(screen.getByText(/A workspace is your team/)).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "How NLW works" })).toHaveTextContent(
      /Ask.*Review.*Execute.*Evidence/,
    );
    expect(screen.getByTestId("no-workspaces")).toBeInTheDocument();
  });

  it("shows friendly role labels", () => {
    mockWorkspaces.mockReturnValue({
      isLoading: false,
      error: null,
      data: [{ id: "w1", name: "Alpha", role: "admin" }],
    });
    setCreate();
    render(<SelectWorkspacePage />);
    expect(screen.getByText(/· Admin/)).toBeInTheDocument();
  });

  it("validates the name, then creates and opens the workspace", async () => {
    mockWorkspaces.mockReturnValue({ isLoading: false, error: null, data: [] });
    const mutateAsync = vi.fn().mockResolvedValue({ id: "w9", name: "Pilot" });
    mockCreate.mockReturnValue({ mutateAsync, isPending: false, error: null });
    mockPost.mockResolvedValue(undefined);
    render(<SelectWorkspacePage />);
    await userEvent.click(screen.getByRole("button", { name: "Create and open" }));
    expect(screen.getByText("Give your workspace a name.")).toBeInTheDocument();
    expect(mutateAsync).not.toHaveBeenCalled();
    await userEvent.type(screen.getByLabelText("Workspace name"), "  Pilot  ");
    await userEvent.click(screen.getByRole("button", { name: "Create and open" }));
    await waitFor(() => expect(mockNav).toHaveBeenCalledWith("/"));
    expect(mutateAsync).toHaveBeenCalledWith("Pilot");
    expect(mockPost).toHaveBeenCalledWith("w9");
  });
});
