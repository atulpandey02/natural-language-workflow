import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const push = vi.fn();
const refresh = vi.fn();
const signInWithPassword = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ push, refresh }) }));
vi.mock("@/lib/supabase/client", () => ({
  getSupabaseBrowserClient: () => ({ auth: { signInWithPassword } }),
}));

import LoginPage from "./page";

beforeEach(() => window.history.replaceState(null, "", "/login"));
afterEach(() => vi.clearAllMocks());

async function fill(email: string, password: string) {
  if (email) await userEvent.type(screen.getByLabelText("Work email"), email);
  if (password) await userEvent.type(screen.getByLabelText("Password"), password);
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("LoginPage", () => {
  it("presents NLW, its capabilities and the invitation-only synthetic pilot", () => {
    render(<LoginPage />);
    // The form comes first (and first on mobile); product value sits beside it.
    const title = screen.getByRole("heading", { level: 1, name: "Sign in" });
    const headline = screen.getByRole("heading", {
      level: 2,
      name: "Turn business questions into governed workflows",
    });
    expect(title.compareDocumentPosition(headline) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    for (const c of ["Grounded analytics", "Durable execution", "Human approval"]) {
      expect(screen.getByText(c)).toBeInTheDocument();
    }
    expect(screen.getByTestId("pilot-note")).toHaveTextContent(/Invitation-only.*synthetic/);
    // No signup or password reset in the pilot.
    expect(screen.queryByRole("link", { name: /sign up|create account|forgot|reset/i })).toBeNull();
  });

  it("validates inline without calling the auth provider", async () => {
    render(<LoginPage />);
    await fill("", "");
    expect(screen.getByText("Enter your work email address.")).toBeInTheDocument();
    expect(screen.getByText("Enter your password.")).toBeInTheDocument();
    expect(screen.getByLabelText("Work email")).toHaveAttribute("aria-invalid", "true");
    expect(signInWithPassword).not.toHaveBeenCalled();
  });

  it("toggles password visibility accessibly", async () => {
    render(<LoginPage />);
    const input = screen.getByLabelText("Password");
    const toggle = screen.getByRole("button", { name: "Show password" });
    expect(input).toHaveAttribute("type", "password");
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    await userEvent.click(toggle);
    expect(input).toHaveAttribute("type", "text");
    expect(screen.getByRole("button", { name: "Hide password" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("shows a loading state, then friendly copy instead of the provider message", async () => {
    let resolve!: (v: unknown) => void;
    signInWithPassword.mockReturnValue(new Promise((r) => (resolve = r)));
    render(<LoginPage />);
    await fill("a@example.com", "wrong");
    expect(screen.getByRole("button", { name: "Signing in…" })).toBeDisabled();
    resolve({ error: { status: 400, message: "Invalid login credentials" } });
    const err = await screen.findByTestId("login-error");
    expect(err).toHaveTextContent("Email or password is incorrect");
    expect(err).not.toHaveTextContent("Invalid login credentials");
    expect(push).not.toHaveBeenCalled();
  });

  it("returns to an invitation after sign-in and scrubs the token from the address bar", async () => {
    window.history.replaceState(
      null,
      "",
      "/login?next=" + encodeURIComponent("/invitations/accept?token=abc123"),
    );
    signInWithPassword.mockResolvedValue({ error: null });
    render(<LoginPage />);
    expect(
      await screen.findByRole("heading", { name: "Sign in to accept your invitation" }),
    ).toBeInTheDocument();
    expect(window.location.search).toBe("");
    await fill("a@example.com", "pw");
    await waitFor(() => expect(push).toHaveBeenCalledWith("/invitations/accept?token=abc123"));
  });

  it("ignores an unsafe next path", async () => {
    window.history.replaceState(null, "", "/login?next=" + encodeURIComponent("//evil.example"));
    signInWithPassword.mockResolvedValue({ error: null });
    render(<LoginPage />);
    await fill("a@example.com", "pw");
    await waitFor(() => expect(push).toHaveBeenCalledWith("/"));
  });
});
