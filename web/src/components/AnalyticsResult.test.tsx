import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import fixture from "@/test/analytics-fixture.json";
import { AnalyticsResultView } from "./AnalyticsResult";
import { StatusBadge } from "./ui";
import { formatValue } from "@/lib/analytics";
import { seriesStyle } from "@/lib/analytics-presentation";

let resizeCallbacks: ResizeObserverCallback[];
beforeEach(() => {
  resizeCallbacks = [];
  vi.stubGlobal(
    "ResizeObserver",
    class {
      constructor(callback: ResizeObserverCallback) {
        resizeCallbacks.push(callback);
      }
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
});
afterEach(() => vi.unstubAllGlobals());

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
  it("announces horizontal overflow outside the focusable table region and removes the cue when it fits", () => {
    render(<AnalyticsResultView value={fixture} />);
    fireEvent.click(screen.getByText("Monthly supporting data", { selector: "summary" }));
    const region = screen.getByRole("region", { name: "Monthly supporting data" });
    expect(region).toHaveAttribute("tabindex", "0");
    expect(region).not.toHaveAttribute("aria-describedby");
    Object.defineProperties(region, {
      clientWidth: { value: 338, configurable: true },
      scrollWidth: { value: 460, configurable: true },
    });
    act(() => resizeCallbacks.forEach((callback) => callback([], {} as ResizeObserver)));
    expect(region).toHaveAccessibleDescription(
      "More columns: scroll horizontally or use ← / → when focused.",
    );
    const cue = screen.getByText(/More columns: scroll horizontally/);
    expect(cue).toBeVisible();
    expect(region).not.toContainElement(cue);
    region.focus();
    expect(region).toHaveFocus();
    expect(within(region).getByRole("rowheader", { name: "2026-03" })).toHaveTextContent("2026-03");
    Object.defineProperty(region, "clientWidth", { value: 600 });
    act(() => resizeCallbacks.forEach((callback) => callback([], {} as ResizeObserver)));
    expect(region).not.toHaveAttribute("aria-describedby");
    expect(screen.queryByText(/More columns: scroll horizontally/)).toBeNull();
  });
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
      expect((mark as HTMLElement).style.getPropertyValue("--series")).toBe("#1896a7"),
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
      const badge = document.querySelector(`[data-status="${run_outcome}"]`);
      expect(badge).toBeVisible();
      expect(badge).toHaveTextContent(run_outcome === "FAILED" ? "Failed" : "Outcome unknown");
      expect(screen.getAllByTestId("analytics-kpi")[0]).toHaveTextContent("$280,617.20");
      expect(document.querySelector('[data-status="COMPLETED"]')).toBeNull();
      expect(screen.queryByText("Completed")).toBeNull();
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
    expect(screen.getByText("Outcome unknown")).toHaveClass("warn");
    expect(screen.getByText(/Partial results/)).toBeVisible();
  });
  it.each([
    ["FAILED", "Failed", "fail"],
    ["SKIPPED", "Skipped", "skip"],
    ["UNKNOWN", "Outcome unknown", "warn"],
    ["WAITING_APPROVAL", "Awaiting approval", "warn"],
    ["NEEDS_APPROVAL", "Needs approval", "warn"],
  ])("styles %s explicitly", (status, label, style) => {
    render(<StatusBadge status={status} />);
    expect(screen.getByText(label)).toHaveClass(style);
    expect(screen.getByText(label)).toHaveAttribute("data-status", status);
  });
});

describe("insight sections", () => {
  it("groups the grounded findings verbatim, keeping their source links", () => {
    render(<AnalyticsResultView value={fixture} />);
    const changed = screen.getByRole("region", { name: "What changed" });
    const attention = screen.getByRole("region", { name: "Needs attention" });
    expect(changed).toHaveTextContent(fixture.findings[0].text);
    expect(attention).toHaveTextContent(fixture.findings[1].text);
    expect(within(attention).getAllByRole("link", { name: "analyze" }).length).toBeGreaterThan(0);
  });

  it("labels recommended actions as NLW next steps, not data conclusions", () => {
    render(<AnalyticsResultView value={fixture} />);
    const actions = screen.getByRole("region", { name: "Recommended actions" });
    expect(actions).toHaveTextContent("not conclusions from the data");
    expect(within(actions).getByRole("link", { name: "Ask a follow-up question" })).toHaveAttribute(
      "href",
      "/workflows/new",
    );
  });

  it("offers sharing only for a READY result", () => {
    render(
      <AnalyticsResultView value={{ ...fixture, status: "PARTIAL", run_outcome: "FAILED" }} />,
    );
    expect(screen.getByRole("region", { name: "Recommended actions" })).not.toHaveTextContent(
      /Share the summary/,
    );
  });
});

describe("large KPI values (B3)", () => {
  const withValues = (values: Array<[number | null, string]>) => ({
    ...fixture,
    metrics: fixture.metrics.map((m, i) => ({
      ...m,
      value: values[i][0],
      unit: values[i][1],
    })),
  });

  it("shows a marked compact value, with the exact value available accessibly", async () => {
    render(
      <AnalyticsResultView
        value={withValues([
          [12345678901.23, "USD"],
          [-1e12, "USD"],
          [0, "count"],
          [null, "percent"],
        ])}
      />,
    );
    const [big, negative, zero, missing] = screen.getAllByTestId("analytics-kpi");
    const bigValue = big.querySelector("strong")!;
    expect(bigValue).toHaveAttribute("data-compacted", "true");
    expect(bigValue).toHaveAttribute("title", "$12,345,678,901.23");
    expect(within(bigValue).getByText("$12.35B")).toHaveAttribute("aria-hidden", "true");
    expect(within(bigValue).getByText("$12,345,678,901.23")).toHaveClass("sr-only");
    expect(big).toHaveTextContent("rounded");
    // The exact value is reachable by keyboard, not only on hover.
    const exact = within(big).getByText("Exact value");
    expect(exact.tagName).toBe("SUMMARY");
    await userEvent.click(exact);
    expect(big.querySelector(".kpi-exact-value")).toHaveTextContent("$12,345,678,901.23");
    expect(within(negative).getByText("-$1.00T")).toBeVisible();
    expect(negative.querySelector("strong")).toHaveAttribute("title", "-$1,000,000,000,000.00");
    // Short values are unchanged and not marked.
    expect(zero.querySelector("strong")).toHaveTextContent(/^0$/);
    expect(zero.querySelector("[data-compacted]")).toBeNull();
    expect(missing.querySelector("strong")).toHaveTextContent("Unavailable");
  });

  it("keeps ordinary values exact", () => {
    render(<AnalyticsResultView value={fixture} />);
    const revenue = screen.getAllByTestId("analytics-kpi")[0];
    expect(revenue.querySelector("strong")).toHaveTextContent(/^\$280,617\.20$/);
    expect(revenue.querySelector("details")).toBeNull();
  });

  it("exposes the full-precision exact value once to assistive tech and in the disclosure", async () => {
    render(
      <AnalyticsResultView
        value={withValues([
          [12345678.123456, "hours"],
          [-0.123456789, "USD"],
          [280617.2, "USD"],
          [-0, "percent"],
        ])}
      />,
    );
    const [hours, fraction, ordinary, zero] = screen.getAllByTestId("analytics-kpi");
    const value = hours.querySelector("strong")!;
    expect(value).toHaveAttribute("data-rounded", "true");
    expect(within(value).getByText("12.35M h")).toHaveAttribute("aria-hidden", "true");
    expect(within(value).getByText("12,345,678.123456 h")).toHaveClass("sr-only");
    expect(value).toHaveAttribute("title", "12,345,678.123456 h");
    await userEvent.click(within(hours).getByText("Exact value"));
    const disclosed = hours.querySelector(".kpi-exact-value")!;
    expect(disclosed).toHaveTextContent("12,345,678.123456 h");
    expect(disclosed).toHaveAttribute("aria-hidden", "true"); // announced once, in the value
    // A short value with hidden precision is marked rounded too.
    expect(fraction.querySelector("strong")).toHaveAttribute("title", "-$0.123456789");
    expect(fraction).toHaveTextContent("rounded");
    expect(ordinary.querySelector("strong")).toHaveTextContent(/^\$280,617\.20$/);
    expect(ordinary.querySelector("[data-rounded]")).toBeNull();
    expect(zero.querySelector("strong")).toHaveTextContent(/^0%$/);
  });
});
