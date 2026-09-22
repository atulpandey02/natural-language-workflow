import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";

// Isolate the page's rendering + role-gating: stub the shell, mock all hooks.
vi.mock("@/components/AppShell", () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock("@/lib/api/hooks", () => ({
  useMembers: vi.fn(),
  useCurrentWorkspace: vi.fn(),
  useChangeMemberRole: vi.fn(),
  useRemoveMember: vi.fn(),
  useInvitations: vi.fn(),
  useCreateInvitation: vi.fn(),
  useRevokeInvitation: vi.fn(),
}));

import MembersPage from "./page";
import {
  useMembers,
  useCurrentWorkspace,
  useChangeMemberRole,
  useRemoveMember,
  useInvitations,
  useCreateInvitation,
  useRevokeInvitation,
} from "@/lib/api/hooks";

const mockMembers = useMembers as unknown as Mock;
const mockCurrent = useCurrentWorkspace as unknown as Mock;
const mockChangeRole = useChangeMemberRole as unknown as Mock;
const mockRemove = useRemoveMember as unknown as Mock;
const mockInvitations = useInvitations as unknown as Mock;
const mockCreateInvite = useCreateInvitation as unknown as Mock;
const mockRevoke = useRevokeInvitation as unknown as Mock;

const MEMBERS = [
  { user_id: "11111111-2222-3333-4444-555555555555", role: "owner" as const },
  { user_id: "66666666-7777-8888-9999-000000000000", role: "member" as const },
];

function mutation() {
  return { mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false, error: null };
}

function setRole(role: string): void {
  mockMembers.mockReturnValue({ isLoading: false, error: null, data: MEMBERS });
  mockCurrent.mockReturnValue({ data: { tenant_id: "t1", role } });
  mockChangeRole.mockReturnValue(mutation());
  mockRemove.mockReturnValue(mutation());
  mockInvitations.mockReturnValue({ isLoading: false, error: null, data: [] });
  mockCreateInvite.mockReturnValue(mutation());
  mockRevoke.mockReturnValue(mutation());
}

afterEach(() => vi.clearAllMocks());

describe("MembersPage", () => {
  it("renders the roster for any member", () => {
    setRole("member");
    render(<MembersPage />);
    expect(screen.getByText("owner")).toBeInTheDocument();
    // The user ids appear in the roster.
    expect(screen.getByText(MEMBERS[0].user_id)).toBeInTheDocument();
    expect(screen.getByText(MEMBERS[1].user_id)).toBeInTheDocument();
  });

  it("shows management + invitation controls for an owner", () => {
    setRole("owner");
    render(<MembersPage />);
    // Per-member role select + remove control are rendered.
    expect(screen.getByLabelText(`role for ${MEMBERS[0].user_id}`)).toBeInTheDocument();
    expect(screen.getByLabelText(`remove ${MEMBERS[0].user_id}`)).toBeInTheDocument();
    // The invite form (a mutation control) is present.
    expect(screen.getByLabelText("invite member")).toBeInTheDocument();
  });

  it("shows management + invitation controls for an admin", () => {
    setRole("admin");
    render(<MembersPage />);
    expect(screen.getByLabelText("invite member")).toBeInTheDocument();
    expect(screen.getByLabelText(`role for ${MEMBERS[0].user_id}`)).toBeInTheDocument();
  });

  it("is read-only for a plain member and explains why", () => {
    setRole("member");
    render(<MembersPage />);
    // No mutation controls; backend + RLS remain authoritative.
    expect(screen.queryByLabelText("invite member")).toBeNull();
    expect(screen.queryByLabelText(`role for ${MEMBERS[0].user_id}`)).toBeNull();
    expect(screen.queryByLabelText(`remove ${MEMBERS[0].user_id}`)).toBeNull();
    expect(screen.getByText(/an admin or owner must manage members/i)).toBeInTheDocument();
  });
});
