import { describe, expect, it } from "vitest";
import {
  KPI_MAX_CHARS,
  exactValue,
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
      rounded: false,
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

describe("exact value keeps the parsed number's full precision", () => {
  // [value, USD, hours, percent]
  const CASES: Array<[number | null, string, string, string]> = [
    [12345678.123456, "$12,345,678.123456", "12,345,678.123456 h", "12,345,678.123456%"],
    [-12345678.123456, "-$12,345,678.123456", "-12,345,678.123456 h", "-12,345,678.123456%"],
    [0.123456789, "$0.123456789", "0.123456789 h", "0.123456789%"],
    [-0.123456789, "-$0.123456789", "-0.123456789 h", "-0.123456789%"],
    [999999999999.9999, "$999,999,999,999.9999", "999,999,999,999.9999 h", "999,999,999,999.9999%"],
    [
      -999999999999.9999,
      "-$999,999,999,999.9999",
      "-999,999,999,999.9999 h",
      "-999,999,999,999.9999%",
    ],
    [0, "$0.00", "0 h", "0%"],
    [-0, "$0.00", "0 h", "0%"],
    [1257, "$1,257.00", "1,257 h", "1,257%"],
    [-1e12, "-$1,000,000,000,000.00", "-1,000,000,000,000 h", "-1,000,000,000,000%"],
    [null, "Unavailable", "Unavailable", "Unavailable"],
  ];

  it.each(CASES)("%s", (value, usd, hours, percent) => {
    expect(exactValue(value, "USD")).toBe(usd);
    expect(exactValue(value, "hours")).toBe(hours);
    expect(exactValue(value, "percent")).toBe(percent);
  });

  it("round-trips: the exact digits parse back to the same number", () => {
    for (const [value] of CASES) {
      if (value === null) continue;
      const digits = exactValue(value, "count").replace(/,/g, "");
      expect(Number(digits)).toBe(value === 0 ? 0 : value);
    }
  });

  it("expands exponent forms deterministically, without noise", () => {
    expect(exactValue(1e-7, "count")).toBe("0.0000001");
    expect(exactValue(-1.5e-7, "hours")).toBe("-0.00000015 h");
    expect(Number(exactValue(5e-324, "count"))).toBe(5e-324);
  });

  it("marks the display rounded exactly when it hides precision", () => {
    const hours = kpiDisplay(12345678.123456, "hours");
    expect(hours).toMatchObject({
      text: "12.35M h",
      exact: "12,345,678.123456 h",
      compacted: true,
      rounded: true,
    });
    // Short but more precise than two decimals: shown rounded, and said so.
    expect(kpiDisplay(0.123456789, "hours")).toMatchObject({
      text: "0.12 h",
      exact: "0.123456789 h",
      compacted: false,
      rounded: true,
    });
    // Ordinary values are unchanged and not marked.
    expect(kpiDisplay(280617.2, "USD")).toMatchObject({
      text: "$280,617.20",
      exact: "$280,617.20",
      rounded: false,
    });
    expect(kpiDisplay(-0, "USD")).toMatchObject({ text: "$0.00", rounded: false });
  });
});
