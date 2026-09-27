import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ResponsiveDetails } from "./ResponsiveDetails";

describe("responsive disclosure drawer", () => {
  it("keeps desktop evidence collapsed until explicitly opened and supports Escape", () => {
    const original = window.matchMedia;
    window.matchMedia = vi
      .fn()
      .mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() });
    const { container } = render(
      <ResponsiveDetails className="workflow-details" breakpoint={1200} desktopOpen={false}>
        <summary>Evidence details</summary>
        <p>Completed evidence</p>
      </ResponsiveDetails>,
    );
    const panel = container.querySelector("details")!;
    expect(panel.open).toBe(false);
    fireEvent.click(screen.getByText("Evidence details"));
    expect(panel.open).toBe(true);
    fireEvent.keyDown(panel, { key: "Escape" });
    expect(panel.open).toBe(false);
    expect(screen.getByText("Evidence details")).toHaveFocus();
    window.matchMedia = original;
  });
  it("collapses on mobile and closes with Escape", () => {
    const original = window.matchMedia;
    window.matchMedia = vi
      .fn()
      .mockReturnValue({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() });
    const { container } = render(
      <ResponsiveDetails className="workflow-details" breakpoint={1200}>
        <summary>Evidence details</summary>
        <p>Completed evidence</p>
      </ResponsiveDetails>,
    );
    const panel = container.querySelector("details")!;
    expect(panel.open).toBe(false);
    fireEvent.click(screen.getByText("Evidence details"));
    expect(panel.open).toBe(true);
    fireEvent.keyDown(panel, { key: "Escape" });
    expect(panel.open).toBe(false);
    expect(screen.getByText("Evidence details")).toHaveFocus();
    window.matchMedia = original;
  });
});
