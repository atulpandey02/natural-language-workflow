import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { GetStarted } from "./GetStarted";

describe("GetStarted onboarding", () => {
  it("explains the journey, both datasets and pilot limits", () => {
    render(<GetStarted canManage={false} />);
    const steps = screen.getByRole("list", { name: "How NLW works" });
    expect(steps).toHaveTextContent(/Ask.*Review.*Execute.*Evidence/);
    expect(screen.getByRole("link", { name: /Sales/ })).toHaveAttribute(
      "href",
      "/workflows/new?dataset=sales-v1",
    );
    expect(screen.getByRole("link", { name: /Support/ })).toBeInTheDocument();
    expect(screen.getByTestId("pilot-limits")).toHaveTextContent(/synthetic/);
  });

  it("offers invite and connector actions only to owners and admins", () => {
    const { unmount } = render(<GetStarted canManage={false} />);
    expect(screen.queryByRole("link", { name: /Invite a teammate/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Slack destination/ })).toBeNull();
    unmount();
    render(<GetStarted canManage />);
    expect(screen.getByRole("link", { name: /Invite a teammate/ })).toHaveAttribute(
      "href",
      "/members",
    );
    expect(screen.getByRole("link", { name: /Slack destination/ })).toHaveAttribute(
      "href",
      "/connectors",
    );
  });
});
