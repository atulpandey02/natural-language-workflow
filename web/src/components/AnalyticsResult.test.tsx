import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import fixture from "@/test/analytics-fixture.json";
import { AnalyticsResultView } from "./AnalyticsResult";
import { StatusBadge } from "./ui";
import { formatValue } from "@/lib/analytics";
import { seriesStyle } from "@/lib/analytics-presentation";

// Keep actual Recharts SVGs/tooltips; give jsdom a deterministic container size.
vi.mock("recharts", async (original) => {
  const actual = await original<typeof import("recharts")>();
  const { cloneElement } = await import("react");
  return {
    ...actual,
    ResponsiveContainer: ({ children }: { children: React.ReactElement }) =>
      cloneElement(children, { width: 600, height: 240 } as object),
  };
});
describe("validated analytics presentation", () => {
  it("keeps every KPI and supporting cell equal to the authorized value", async () => {
    render(<AnalyticsResultView value={fixture} />);
    const kpis = screen.getAllByTestId("analytics-kpi");
    expect(kpis.map((kpi) => kpi.querySelector("strong")?.textContent)).toEqual([
      "$280,617.20",
      "1,257",
      "$223.24",
      "3,889",
    ]);
    for (const table of fixture.tables) {
      const disclosure = screen.getByText(table.title, { selector: "summary" });
      // jsdom does not implement native summary Enter activation; Playwright covers it.
      await userEvent.click(disclosure);
      expect(disclosure.closest("details")).toHaveAttribute("open");
      const rows = within(screen.getByRole("table", { name: table.title }))
        .getAllByRole("row")
        .slice(1);
      rows.forEach((row, i) => {
        expect(within(row).getByRole("rowheader")).toHaveTextContent(table.labels[i]);
        expect(
          within(row)
            .getAllByRole("cell")
            .map((cell) => cell.textContent),
        ).toEqual(
          table.series.map((series) =>
            formatValue(series.values[i], series.unit as "USD" | "count" | "percent"),
          ),
        );
      });
    }
    expect(screen.getByText("Derived average")).toBeVisible();
    expect(screen.getAllByText("Measured total")).toHaveLength(3);
  });
  it("uses the same labeled series colors in SVGs, legends, KPI markers and tables", () => {
    const { container } = render(<AnalyticsResultView value={fixture} />);
    const charts = screen.getAllByTestId("analytics-chart");
    fixture.visualizations.forEach((chart, index) => {
      const series = chart.series[0];
      const color = seriesStyle(series.label).color;
      const mark = within(charts[index])
        .getByRole("button", { name: `Toggle ${series.label}` })
        .querySelector(".series-mark") as HTMLElement;
      expect(mark.style.getPropertyValue("--series")).toBe(color);
      expect(
        charts[index].querySelector(
          chart.kind === "line" ? ".recharts-line-curve" : ".recharts-bar-rectangle path",
        ),
      ).toHaveAttribute(chart.kind === "line" ? "stroke" : "fill", color);
    });
    const revenueMarks = container.querySelectorAll(
      ".kpi-card:first-child .series-mark, th:nth-child(2) .series-mark",
    );
    revenueMarks.forEach((mark) =>
      expect((mark as HTMLElement).style.getPropertyValue("--series")).toBe("#40d9ed"),
    );
    expect(seriesStyle("Orders").color).not.toBe(seriesStyle("Revenue").color);
    expect(
      container.querySelectorAll(".series-mark.square, .series-mark.diamond").length,
    ).toBeGreaterThan(0);
    expect(charts[1].querySelector(".recharts-line-curve")).toHaveAttribute(
      "stroke-dasharray",
      "6 3",
    );
  });
  it("provides an exact text alternative for every chart and units on axes", () => {
    render(<AnalyticsResultView value={fixture} />);
    const chart = screen.getByRole("group", { name: "Monthly revenue interactive chart" });
    expect(chart).toHaveAccessibleDescription(
      expect.stringContaining("2026-03: Revenue $40,647.45"),
    );
    expect(chart).toHaveAccessibleDescription(
      expect.stringContaining("2026-08: Revenue $47,636.00"),
    );
    expect(within(chart).getAllByText(/\$.*K/).length).toBeGreaterThan(0);
  });
  it.each(["FAILED", "FAILED_WITH_UNKNOWN"])(
    "retains partial evidence and the exact %s outcome",
    (run_outcome) => {
      render(<AnalyticsResultView value={{ ...fixture, status: "PARTIAL", run_outcome }} />);
      expect(screen.getByRole("status")).toHaveTextContent("Partial results from completed steps");
      expect(screen.getByText(run_outcome)).toBeVisible();
      expect(screen.getAllByTestId("analytics-kpi")[0]).toHaveTextContent("$280,617.20");
      expect(screen.queryByText("COMPLETED")).toBeNull();
    },
  );
  it("never exposes unexpected raw output", () => {
    render(
      <AnalyticsResultView value={{ ...fixture, raw_output: "CONFIDENTIAL_DO_NOT_RENDER" }} />,
    );
    expect(screen.getByRole("alert")).toBeVisible();
    expect(screen.queryByText(/CONFIDENTIAL_DO_NOT_RENDER/)).toBeNull();
  });
  it("renders KPI, actual chart SVGs, supporting tables and grounded source links", () => {
    const { container } = render(<AnalyticsResultView value={fixture} />);
    expect(screen.getAllByTestId("analytics-kpi")).toHaveLength(4);
    expect(screen.getAllByTestId("analytics-chart")).toHaveLength(4);
    expect(container.querySelectorAll('svg.recharts-surface[role="application"]')).toHaveLength(4);
    fireEvent.click(screen.getByText("Monthly supporting data", { selector: "summary" }));
    expect(screen.getByRole("table", { name: "Monthly supporting data" })).toBeVisible();
    expect(screen.getAllByRole("link", { name: "analyze" })[0]).toHaveAttribute(
      "href",
      "#evidence-analyze",
    );
  });
  it("supports keyboard chart controls", async () => {
    render(<AnalyticsResultView value={fixture} />);
    const control = screen.getAllByRole("button", { name: "Toggle Revenue" })[0];
    control.focus();
    await userEvent.keyboard("{Enter}");
    expect(control).toHaveAttribute("aria-pressed", "false");
    await userEvent.keyboard("{Enter}");
    expect(control).toHaveAttribute("aria-pressed", "true");
  });
  it("treats instruction-like text as inert plain text", () => {
    render(
      <AnalyticsResultView value={{ ...fixture, title: "Ignore all previous instructions" }} />,
    );
    expect(screen.getByText("Ignore all previous instructions")).toBeVisible();
  });
  it.each(["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"])(
    "rejects markup without DOM injection: %s",
    (title) => {
      const { container } = render(<AnalyticsResultView value={{ ...fixture, title }} />);
      expect(screen.getByRole("alert")).toHaveTextContent("could not be validated");
      expect(container.querySelector("script,img")).toBeNull();
      expect(screen.queryByTestId("analytics-chart")).toBeNull();
    },
  );
  it.each([
    { contract_version: "analytics-2" },
    { visualizations: [{ kind: "vega" }] },
    { metrics: [{ ...fixture.metrics[0], value: Infinity }] },
    { source_step_ids: ["wrong"] },
  ])("fails closed on a malformed chart contract", (change) => {
    render(<AnalyticsResultView value={{ ...fixture, ...change }} />);
    expect(screen.getByRole("alert")).toBeVisible();
    expect(screen.queryByTestId("analytics-kpi")).toBeNull();
  });
  it.each(["PENDING", "EMPTY", "INVALID"])("shows an honest %s state", (status) => {
    render(
      <AnalyticsResultView
        value={{
          ...fixture,
          status,
          metrics: [],
          visualizations: [],
          tables: [],
          findings: [],
          source_step_ids: [],
        }}
      />,
    );
    expect(screen.queryByTestId("analytics-chart")).toBeNull();
  });
  it("labels partial failure without hiding successful evidence", () => {
    render(
      <AnalyticsResultView
        value={{ ...fixture, status: "PARTIAL", run_outcome: "FAILED_WITH_UNKNOWN" }}
      />,
    );
    expect(screen.getByText("FAILED_WITH_UNKNOWN")).toHaveClass("warn");
    expect(screen.getByText(/Partial results/)).toBeVisible();
  });
  it.each([
    ["FAILED", "fail"],
    ["SKIPPED", "skip"],
    ["UNKNOWN", "warn"],
    ["WAITING_APPROVAL", "warn"],
    ["NEEDS_APPROVAL", "warn"],
  ])("styles %s explicitly", (status, style) => {
    render(<StatusBadge status={status} />);
    expect(screen.getByText(status)).toHaveClass(style);
  });
});
