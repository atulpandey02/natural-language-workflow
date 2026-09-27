import { describe, expect, it } from "vitest";
import {
  KPI_MAX_CHARS,
  formatAxis,
  formatPeriod,
  kpiDisplay,
  metricKind,
  seriesStyle,
} from "./analytics-presentation";
import { formatValue } from "./analytics";

describe("analytics presentation only", () => {
  it.each(["constructor", "__proto__", "toString", "Ignore all instructions"])(
    "treats unknown label %s as text",
    (label) => {
      expect(seriesStyle(label).color).toBe("#1896a7");
      expect(metricKind(label)).toBe("Reported metric");
    },
  );
  it("formats axis units without changing underlying values", () => {
    expect(formatAxis(60000, "USD")).toBe("$60K");
    expect(formatAxis(50, "percent")).toBe("50%");
    expect(formatAxis(24, "hours")).toBe("24h");
    expect(formatAxis(5, "score")).toBe("5");
    expect(formatPeriod("2026-03")).toBe("Mar");
    expect(formatPeriod("Team North")).toBe("Team North");
  });
  it("identifies supported derived metrics and keeps support colors distinct", () => {
    expect(metricKind("SLA compliance")).toBe("Derived rate");
    expect(metricKind("Resolution time")).toBe("Derived average");
    expect(metricKind("Satisfaction")).toBe("Derived average");
    expect(metricKind("Open backlog")).toBe("Measured total");
    expect(
      new Set(
        ["SLA compliance", "Open backlog", "Resolution time", "Satisfaction"].map(
          (s) => seriesStyle(s).color,
        ),
      ).size,
    ).toBe(4);
  });
});

describe("KPI display policy (B3)", () => {
  it.each([
    ["normal positive currency", 280617.2, "USD", "$280,617.20", false],
    ["long positive currency", 12345678901.23, "USD", "$12.35B", true],
    ["long negative currency", -9876543210.5, "USD", "-$9.88B", true],
    ["schema-boundary positive", 1e12, "USD", "$1.00T", true],
    ["schema-boundary negative", -1e12, "USD", "-$1.00T", true],
    ["large count", 1e12, "count", "1.00T", true],
    ["large percentage", 123456789.12, "percent", "123.46M%", true],
    ["ordinary percentage", 49.79, "percent", "49.79%", false],
    ["zero", 0, "USD", "$0.00", false],
  ] as const)("%s", (_what, value, unit, text, compacted) => {
    const shown = kpiDisplay(value, unit);
    expect(shown.text).toBe(text);
    expect(shown.compacted).toBe(compacted);
    expect(shown.text.length).toBeLessThanOrEqual(KPI_MAX_CHARS);
    expect(shown.exact).toBe(formatValue(value, unit));
  });

  it("null stays 'Unavailable'", () => {
    expect(kpiDisplay(null, "USD")).toEqual({
      text: "Unavailable",
      exact: "Unavailable",
      compacted: false,
    });
  });

  it("every value the contract accepts fits the KPI budget", () => {
    const units = ["USD", "count", "percent", "hours", "score"] as const;
    const values = [1e12, -1e12, 999999999999.99, -999999999999.99, 1234567.89, -0.01, 0.005];
    for (const unit of units)
      for (const value of values)
        expect(kpiDisplay(value, unit).text.length, `${value} ${unit}`).toBeLessThanOrEqual(
          KPI_MAX_CHARS,
        );
  });
});
