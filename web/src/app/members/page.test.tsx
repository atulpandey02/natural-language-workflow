import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

// Isolate the page's rendering + role-gating: stub the shell, mock all hooks.
vi.mock("@/components/AppShell", () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock("@/lib/api/hooks", () => ({
  useMembers: vi.fn(),
  useMe: vi.fn(),
  useCurrentWorkspace: vi.fn(),
  useChangeMemberRole: vi.fn(),
  useRemoveMember: vi.fn(),
  useInvitations: vi.fn(),
  useCreateInvitation: vi.fn(),
  useRevokeInvitation: vi.fn(),
}));

import MembersPage from "./page";
import {
  useChangeMemberRole,
  useCreateInvitation,
  useCurrentWorkspace,
  useInvitations,
  useMe,
  useMembers,
  useRemoveMember,
  useRevokeInvitation,
} from "@/lib/api/hooks";

const SELF = "11111111-2222-3333-4444-555555555555";
const OTHER_OWNER = "22222222-2222-3333-4444-555555555555";
const MEMBER = "66666666-7777-8888-9999-000000000000";
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const TOKEN = "tok_" + "x".repeat(40);

let removeMutation: ReturnType<typeof mutation>;
let revokeMutation: ReturnType<typeof mutation>;
let createMutation: ReturnType<typeof mutation>;

function mutation() {
  return { mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false, error: null };
}

function setup(role: string, selfRole = role) {
  const members = [
    { user_id: SELF, role: selfRole, joined_at: "2026-09-20T10:00:00Z" },
    { user_id: OTHER_OWNER, role: "owner", joined_at: "2026-09-21T10:00:00Z" },
    { user_id: MEMBER, role: "member", joined_at: "2026-09-22T10:00:00Z" },
  ];
  (useMembers as Mock).mockReturnValue({ isLoading: false, error: null, data: members });
  (useMe as Mock).mockReturnValue({ data: { id: SELF, email: "me@pilot.example" } });
  (useCurrentWorkspace as Mock).mockReturnValue({ data: { tenant_id: "t1", role } });
  (useChangeMemberRole as Mock).mockReturnValue(mutation());
  removeMutation = mutation();
  (useRemoveMember as Mock).mockReturnValue(removeMutation);
  (useInvitations as Mock).mockReturnValue({
    isLoading: false,
    error: null,
    data: [
      {
        id: "99999999-2222-3333-4444-555555555555",
        email: "approver@pilot.example",
        role: "admin",
        status: "pending",
        expires_at: "2026-10-01T10:00:00Z",
        created_at: "2026-09-24T10:00:00Z",
      },
    ],
  });
  createMutation = mutation();
  createMutation.mutateAsync.mockResolvedValue({
    id: "88888888-2222-3333-4444-555555555555",
    email: "approver@pilot.example",
    role: "admin",
    status: "pending",
    expires_at: "2026-10-01T10:00:00Z",
    created_at: "2026-09-24T10:00:00Z",
    token: TOKEN,
  });
  (useCreateInvitation as Mock).mockReturnValue(createMutation);
  revokeMutation = mutation();
  (useRevokeInvitation as Mock).mockReturnValue(revokeMutation);
}

afterEach(() => vi.clearAllMocks());

describe("Members page", () => {
  it("never renders an internal identifier and names the signed-in user", () => {
    setup("owner");
    const { container } = render(<MembersPage />);
    expect(container.textContent).not.toMatch(UUID_RE);
    expect(container.innerHTML).not.toMatch(UUID_RE);
    expect(screen.getByText("You · me@pilot.example")).toBeInTheDocument();
    expect(screen.getAllByText(/^Member since /)).toHaveLength(2);
    expect(screen.getAllByText("Owner").length).toBeGreaterThan(0);
  });

  it("gives an owner owner-level role choices, but no controls on their own row", () => {
    setup("owner");
    render(<MembersPage />);
    const rows = screen.getAllByTestId("member-row");
    expect(within(rows[0]).queryByRole("combobox")).toBeNull();
    expect(within(rows[0]).getByText("Your access")).toBeInTheDocument();
    const memberRole = within(rows[2]).getByRole("combobox");
    expect(
      within(memberRole)
        .getAllByRole("option")
        .map((o) => o.textContent),
    ).toEqual(["Owner", "Admin", "Member"]);
    expect(within(rows[1]).getByRole("combobox")).toBeInTheDocument(); // owner may manage owners
  });

  it("limits an admin to admin/member and hides controls on owner rows", () => {
    setup("admin");
    render(<MembersPage />);
    const rows = screen.getAllByTestId("member-row");
    expect(within(rows[1]).queryByRole("combobox")).toBeNull();
    expect(within(rows[1]).getByText("Only an owner can change an owner")).toBeInTheDocument();
    const memberRole = within(rows[2]).getByRole("combobox");
    expect(
      within(memberRole)
        .getAllByRole("option")
        .map((o) => o.textContent),
    ).toEqual(["Admin", "Member"]);
  });

  it("shows a plain member the roster only: no controls, no invitation request", () => {
    setup("member");
    render(<MembersPage />);
    expect(screen.getAllByTestId("member-row")).toHaveLength(3);
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.queryByText("Pending invitations")).toBeNull();
    expect(screen.queryByRole("form", { name: "Invite someone" })).toBeNull();
    expect(screen.getByTestId("member-readonly-note")).toBeInTheDocument();
    expect(useInvitations as Mock).toHaveBeenCalledWith(false);
  });

  it("requires confirmation before removing a member", () => {
    setup("owner");
    render(<MembersPage />);
    const row = screen.getAllByTestId("member-row")[2];
    fireEvent.click(within(row).getByRole("button", { name: "Remove…" }));
    expect(removeMutation.mutate).not.toHaveBeenCalled();
    fireEvent.click(within(row).getByRole("button", { name: "Remove" }));
    expect(removeMutation.mutate).toHaveBeenCalledWith(MEMBER, expect.anything());
  });

  it("lists pending invitations and revokes only after confirmation", () => {
    setup("admin");
    render(<MembersPage />);
    const row = screen.getByTestId("invitation-row");
    expect(within(row).getByText("approver@pilot.example")).toBeInTheDocument();
    expect(within(row).getByText("Admin")).toBeInTheDocument();
    fireEvent.click(within(row).getByRole("button", { name: /Revoke invitation for/ }));
    expect(revokeMutation.mutate).not.toHaveBeenCalled();
    fireEvent.click(within(row).getByRole("button", { name: "Revoke" }));
    expect(revokeMutation.mutate).toHaveBeenCalled();
  });

  it("validates the invite form inline and never offers the owner role", async () => {
    setup("owner");
    render(<MembersPage />);
    const roles = within(screen.getByLabelText("Role")).getAllByRole("option");
    expect(roles.map((o) => (o as HTMLOptionElement).value)).toEqual(["member", "admin"]);
    fireEvent.click(screen.getByRole("button", { name: "Create invitation" }));
    expect(await screen.findByText("Enter the email address they sign in with.")).toBeVisible();
    fireEvent.change(screen.getByLabelText("Email address"), { target: { value: "nope" } });
    fireEvent.click(screen.getByRole("button", { name: "Create invitation" }));
    expect(await screen.findByText("Enter a valid email address.")).toBeVisible();
    expect(createMutation.mutateAsync).not.toHaveBeenCalled();
  });

  it("creates an invitation and keeps the one-time link hidden until asked", async () => {
    setup("owner");
    const { container } = render(<MembersPage />);
    fireEvent.change(screen.getByLabelText("Email address"), {
      target: { value: "approver@pilot.example" },
    });
    fireEvent.change(screen.getByLabelText("Role"), { target: { value: "admin" } });
    fireEvent.click(screen.getByRole("button", { name: "Create invitation" }));
    await waitFor(() =>
      expect(createMutation.mutateAsync).toHaveBeenCalledWith({
        email: "approver@pilot.example",
        role: "admin",
      }),
    );
    const panel = await screen.findByTestId("invitation-created");
    expect(within(panel).getByText(/Invitation ready for approver@pilot.example/)).toBeVisible();
    expect(container.innerHTML).not.toContain(TOKEN); // hidden by default
    fireEvent.click(within(panel).getByRole("button", { name: "Show link" }));
    const link = screen.getByTestId("invitation-link") as HTMLInputElement;
    expect(link.value).toBe(`${window.location.origin}/invitations/accept?token=${TOKEN}`);
    fireEvent.click(within(panel).getByRole("button", { name: "Done" }));
    expect(container.innerHTML).not.toContain(TOKEN);
  });
});
