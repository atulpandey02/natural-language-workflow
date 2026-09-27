import { describe, expect, it } from "vitest";
import { formatAxis, formatPeriod, metricKind, seriesStyle } from "./analytics-presentation";

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
