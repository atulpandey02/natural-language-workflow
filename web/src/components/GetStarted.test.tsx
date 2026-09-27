import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { GetStarted } from "./GetStarted";

describe("GetStarted onboarding", () => {
  it("shows the governed path, a guided analysis, sample data and pilot limits", () => {
    render(<GetStarted canManage={false} />);
    expect(screen.getByRole("list", { name: "Progress" })).toHaveTextContent(
      /Request.*Plan.*Approval.*Execution.*Result/,
    );
    expect(screen.getByRole("link", { name: /guided analysis/ })).toHaveAttribute(
      "href",
      "/workflows/new?dataset=sales-v1",
    );
    expect(screen.getByRole("link", { name: /Explore sample data/ })).toBeInTheDocument();
    expect(screen.getByTestId("pilot-limits")).toHaveTextContent(/synthetic/);
  });

  it("offers invite and connect actions only to owners and admins", () => {
    const { unmount } = render(<GetStarted canManage={false} />);
    expect(screen.queryByRole("link", { name: /Invite a teammate/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Connect data/ })).toBeNull();
    expect(screen.getByText(/Ask a workspace owner or admin/)).toBeVisible();
    unmount();
    render(<GetStarted canManage />);
    expect(screen.getByRole("link", { name: /Invite a teammate/ })).toHaveAttribute(
      "href",
      "/members",
    );
    expect(screen.getByRole("link", { name: /Connect data/ })).toHaveAttribute(
      "href",
      "/connectors",
    );
  });
});
