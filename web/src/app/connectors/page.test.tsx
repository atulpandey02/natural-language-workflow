import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";

// Isolate the page's role-gating logic: stub the shell and the form, mock hooks.
vi.mock("@/components/AppShell", () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock("@/components/ConnectorForm", () => ({
  ConnectorForm: () => <form aria-label="create connector" />,
}));
vi.mock("@/lib/api/hooks", () => ({
  useConnectors: vi.fn(),
  useCurrentWorkspace: vi.fn(),
}));

import ConnectorsPage from "./page";
import { useConnectors, useCurrentWorkspace } from "@/lib/api/hooks";

const mockConnectors = useConnectors as unknown as Mock;
const mockCurrent = useCurrentWorkspace as unknown as Mock;

function setRole(role: string): void {
  mockConnectors.mockReturnValue({ isLoading: false, error: null, data: [] });
  mockCurrent.mockReturnValue({ data: { tenant_id: "t1", role } });
}

afterEach(() => vi.clearAllMocks());

describe("ConnectorsPage role gating", () => {
  it("shows the create form for an owner", () => {
    setRole("owner");
    render(<ConnectorsPage />);
    expect(screen.getByLabelText("create connector")).toBeInTheDocument();
    expect(screen.queryByText(/an admin or owner must add/i)).toBeNull();
  });

  it("shows the create form for an admin", () => {
    setRole("admin");
    render(<ConnectorsPage />);
    expect(screen.getByLabelText("create connector")).toBeInTheDocument();
  });

  it("hides the create form from a member and explains why", () => {
    setRole("member");
    render(<ConnectorsPage />);
    // The mutation control is not rendered; backend + RLS remain authoritative.
    expect(screen.queryByLabelText("create connector")).toBeNull();
    expect(screen.getByText(/an admin or owner must add/i)).toBeInTheDocument();
  });
});
