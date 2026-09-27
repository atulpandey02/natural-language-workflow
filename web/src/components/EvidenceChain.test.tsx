import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { EvidenceChain, runChain } from "./EvidenceChain";

describe("EvidenceChain", () => {
  it("marks earlier checkpoints done and the current one as the step", () => {
    render(<EvidenceChain current="Approval" tone="attention" />);
    const items = screen.getAllByRole("listitem");
    expect(items.map((li) => li.className)).toEqual(["done", "done", "current attention", "", ""]);
    expect(items[2]).toHaveAttribute("aria-current", "step");
    expect(items[0]).toHaveTextContent("Request (done)");
  });

  it("can show a completed journey", () => {
    render(<EvidenceChain current="Result" completed />);
    expect(screen.getAllByText(/\(done\)/)).toHaveLength(5);
    expect(
      screen.getByRole("list", { name: "Progress" }).querySelector("[aria-current]"),
    ).toBeNull();
  });

  it("never shows an UNKNOWN or failed run as a completed result", () => {
    for (const status of ["FAILED_WITH_UNKNOWN", "UNKNOWN", "FAILED", "PARTIAL"]) {
      const c = runChain(status);
      expect(c.completed).toBeFalsy();
      expect(c.current).toBe("Execution");
      expect(c.tone).toBeDefined();
    }
    expect(runChain("COMPLETED")).toEqual({ current: "Result", completed: true });
    expect(runChain("WAITING_APPROVAL")).toEqual({ current: "Approval", tone: "attention" });
  });
});
