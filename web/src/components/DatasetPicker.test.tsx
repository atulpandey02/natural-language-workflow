import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const DATASETS = [
  {
    id: "sales-v1",
    name: "Sales performance",
    rows: 1200,
    grain: "order",
    as_of: "2026-09-01",
    prompt: "Analyze the last six months of sales.",
  },
  {
    id: "support-v1",
    name: "Support operations",
    rows: 900,
    grain: "ticket",
    as_of: "2026-09-01",
    prompt: "How is support SLA compliance trending?",
  },
];
vi.mock("@/lib/api/analytics-hooks", () => ({
  useDatasets: () => ({ isLoading: false, error: null, data: DATASETS }),
}));

import { DatasetPicker } from "./DatasetPicker";

describe("DatasetPicker", () => {
  it("shows each synthetic dataset with its safe example question", async () => {
    const onSelect = vi.fn();
    render(<DatasetPicker onSelect={onSelect} />);
    const sales = screen.getByRole("button", { name: /Sales performance/ });
    expect(sales).toHaveAccessibleDescription(/Example: “Analyze the last six months of sales.”/);
    expect(sales).toHaveTextContent(/Synthetic historical snapshot/);
    await userEvent.click(screen.getByRole("button", { name: /Support operations/ }));
    expect(onSelect).toHaveBeenCalledWith("How is support SLA compliance trending?");
  });

  it("applies a preselected dataset once", () => {
    const onSelect = vi.fn();
    const { rerender } = render(<DatasetPicker onSelect={onSelect} preselect="support-v1" />);
    rerender(<DatasetPicker onSelect={onSelect} preselect="support-v1" />);
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith("How is support SLA compliance trending?");
  });

  it("ignores an unknown preselect", () => {
    const onSelect = vi.fn();
    render(<DatasetPicker onSelect={onSelect} preselect="healthcare-v1" />);
    expect(onSelect).not.toHaveBeenCalled();
  });
});
