import type { Unit } from "./analytics";

// Presentation only. The backend owns metric definitions and all values.
const palette = {
  cyan: { color: "#40d9ed", marker: "circle", dash: undefined },
  blue: { color: "#83aaff", marker: "square", dash: "6 3" },
  magenta: { color: "#ed9be9", marker: "diamond", dash: "3 3" },
  coral: { color: "#ffa28f", marker: "square", dash: "8 3 2 3" },
  mint: { color: "#69e2bc", marker: "circle", dash: undefined },
  lime: { color: "#c1df7a", marker: "diamond", dash: "6 3" },
};
const metrics: Record<string, keyof typeof palette> = {
  Revenue: "cyan",
  "Revenue change": "coral",
  Orders: "blue",
  "Average order value": "magenta",
  Units: "lime",
  "SLA compliance": "mint",
  "Open backlog": "coral",
  "Resolution time": "magenta",
  Satisfaction: "lime",
  Tickets: "blue",
  Reopened: "coral",
};
export function seriesStyle(label: string) {
  return palette[Object.hasOwn(metrics, label) ? metrics[label] : "cyan"];
}
export function metricKind(label: string): string {
  if (["Average order value", "Resolution time", "Satisfaction"].includes(label))
    return "Derived average";
  if (["SLA compliance", "Revenue change"].includes(label)) return "Derived rate";
  if (["Revenue", "Orders", "Units", "Tickets", "Reopened", "Open backlog"].includes(label))
    return "Measured total";
  return "Reported metric";
}
export const unitLabel: Record<Unit, string> = {
  USD: "USD",
  count: "Count",
  percent: "Percent",
  hours: "Hours",
  score: "Score / 5",
};
export function formatAxis(value: number, unit: Unit): string {
  const number = new Intl.NumberFormat("en-US", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(value);
  if (unit === "USD") return `$${number}`;
  if (unit === "percent") return `${number}%`;
  if (unit === "hours") return `${number}h`;
  return number;
}
export function formatPeriod(label: string): string {
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(label)) return label;
  return new Intl.DateTimeFormat("en-US", { month: "short", timeZone: "UTC" }).format(
    new Date(`${label}-01T00:00:00Z`),
  );
}
