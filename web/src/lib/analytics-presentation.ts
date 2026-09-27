import { formatValue, type Unit } from "./analytics";

// Presentation only. The backend owns metric definitions and all values.
// Light-canvas series colors: each keeps >= 3:1 contrast against white, and
// markers/dashes distinguish series without relying on color. Violet is
// reserved for AI-assisted content and is not used for data.
const palette = {
  cyan: { color: "#1896a7", marker: "circle", dash: undefined },
  blue: { color: "#5165d6", marker: "square", dash: "6 3" },
  magenta: { color: "#c2418f", marker: "diamond", dash: "3 3" },
  coral: { color: "#e0574a", marker: "square", dash: "8 3 2 3" },
  mint: { color: "#1e8c6a", marker: "circle", dash: undefined },
  lime: { color: "#7a8b1e", marker: "diamond", dash: "6 3" },
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

/**
 * The exact parsed value, never rounded: the number's shortest round-trippable
 * decimal form (String(value)), with any exponent expanded, thousands grouping
 * on the integer part only, and every fractional digit kept. Currency shows at
 * least two decimals (padding zeros never changes the value). -0 reads as 0.
 * This preserves the parsed JavaScript number, not the original JSON spelling
 * ("1.2300" and "1.23" parse to the same number).
 */
export function exactValue(value: number | null, unit: Unit): string {
  if (value === null) return "Unavailable";
  const negative = value < 0; // false for -0, so -0 reads as 0
  const [integer, fraction] = expandExponent(String(Math.abs(value))).split(".");
  const grouped = integer.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const digits =
    unit === "USD"
      ? `${grouped}.${(fraction ?? "").padEnd(2, "0")}`
      : fraction
        ? `${grouped}.${fraction}`
        : grouped;
  return `${negative ? "-" : ""}${unit === "USD" ? "$" : ""}${digits}${UNIT_SUFFIX[unit]}`;
}

/** "1.5e-7" → "0.00000015", "1e+21" → "1000000000000000000000"; exact digit shifting. */
function expandExponent(text: string): string {
  const match = /^(\d+)(?:\.(\d+))?e([+-]\d+)$/.exec(text);
  if (!match) return text;
  const digits = match[1] + (match[2] ?? "");
  const point = match[1].length + Number(match[3]);
  if (point <= 0) return `0.${"0".repeat(-point)}${digits}`;
  if (point >= digits.length) return digits + "0".repeat(point - digits.length);
  return `${digits.slice(0, point)}.${digits.slice(point)}`;
}

/**
 * KPI display policy. The contract allows any finite value in ±1e12, so the
 * two-decimal display can be too long for a KPI card or can hide precision.
 * - Display: the two-decimal form when it fits KPI_MAX_CHARS ("$280,617.20"),
 *   otherwise compact notation to 2 decimals ("$12.35B", "-$1.00T").
 * - rounded: the display differs from the exact parsed value; the card then
 *   says so and offers the exact value (see exactValue).
 */
export const KPI_MAX_CHARS = 11;

const UNIT_SUFFIX: Record<Unit, string> = {
  USD: "",
  count: "",
  percent: "%",
  hours: " h",
  score: " / 5",
};

export function kpiDisplay(
  value: number | null,
  unit: Unit,
): { text: string; exact: string; compacted: boolean; rounded: boolean } {
  const v = value === 0 ? 0 : value; // -0 → 0
  const exact = exactValue(v, unit);
  const fixed = formatValue(v, unit);
  if (v === null || fixed.length <= KPI_MAX_CHARS)
    return { text: fixed, exact, compacted: false, rounded: fixed !== exact };
  const compact = new Intl.NumberFormat("en-US", {
    notation: "compact",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
    ...(unit === "USD" ? { style: "currency" as const, currency: "USD" } : {}),
  }).format(v);
  return { text: compact + UNIT_SUFFIX[unit], exact, compacted: true, rounded: true };
}
