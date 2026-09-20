import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("@/lib/api/hooks", () => ({
  useWorkspaces: vi.fn(),
  useCurrentWorkspace: vi.fn(),
}));
vi.mock("@/lib/workspace-client", () => ({
  postWorkspaceSelection: vi.fn(),
  hardReload: vi.fn(),
}));

import { WorkspaceSwitcher } from "./WorkspaceSwitcher";
import { useWorkspaces, useCurrentWorkspace } from "@/lib/api/hooks";
import { postWorkspaceSelection, hardReload } from "@/lib/workspace-client";

const mockWorkspaces = useWorkspaces as unknown as Mock;
const mockCurrent = useCurrentWorkspace as unknown as Mock;
const mockPost = postWorkspaceSelection as unknown as Mock;
const mockReload = hardReload as unknown as Mock;

function setup() {
  mockWorkspaces.mockReturnValue({
    isLoading: false,
    data: [
      { id: "a", name: "A", role: "owner" },
      { id: "b", name: "B", role: "owner" },
    ],
  });
  mockCurrent.mockReturnValue({ data: { tenant_id: "a", role: "owner" } });
}

afterEach(() => vi.clearAllMocks());

describe("WorkspaceSwitcher", () => {
  it("hard-reloads after a successful workspace change", async () => {
    setup();
    mockPost.mockResolvedValue(undefined);
    render(<WorkspaceSwitcher />);
    await userEvent.selectOptions(screen.getByLabelText("Select workspace"), "b");
    await waitFor(() => expect(mockReload).toHaveBeenCalled());
    expect(mockPost).toHaveBeenCalledWith("b");
  });

  it("does not reload and shows an error on a failed change", async () => {
    setup();
    mockPost.mockRejectedValue(new Error("nope"));
    render(<WorkspaceSwitcher />);
    await userEvent.selectOptions(screen.getByLabelText("Select workspace"), "b");
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(mockReload).not.toHaveBeenCalled();
  });
});
