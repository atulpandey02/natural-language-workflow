import { z } from "zod";

const safeText = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .refine(
      (v) => !/[<>\x00-\x1f]|https?:\/\/|www\.|javascript:|[0-9a-f]{8}-[0-9a-f-]{27,}/i.test(v),
      "Unsafe analytical text",
    );
const label = safeText(80);
const source = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
const sources = z.array(source).min(1).max(8);
const number = z.number().finite().min(-1e12).max(1e12).nullable();
const unit = z.enum(["USD", "count", "percent", "hours", "score"]);
const series = z.object({ label, unit, values: z.array(number).min(1).max(24) }).strict();
const metric = z.object({ label, value: number, unit, source_step_ids: sources }).strict();
const visualization = z
  .object({
    kind: z.enum(["line", "bar"]),
    title: label,
    labels: z.array(label).min(1).max(24),
    series: z.array(series).min(1).max(3),
    source_step_ids: sources,
  })
  .strict()
  .refine(
    (v) =>
      v.series.every((s) => s.values.length === v.labels.length) &&
      new Set(v.labels).size === v.labels.length &&
      new Set(v.series.map((s) => s.unit)).size === 1,
  );
const table = z
  .object({
    title: label,
    dimension: label,
    labels: z.array(label).min(1).max(24),
    series: z.array(series).min(1).max(4),
    source_step_ids: sources,
  })
  .strict()
  .refine((v) => v.series.every((s) => s.values.length === v.labels.length));
export const analyticsSchema = z
  .object({
    contract_version: z.literal("analytics-1"),
    title: label,
    status: z.enum(["READY", "PARTIAL", "PENDING", "EMPTY", "INVALID"]),
    run_outcome: z.enum([
      "COMPLETED",
      "FAILED",
      "FAILED_WITH_UNKNOWN",
      "WAITING_APPROVAL",
      "IN_PROGRESS",
      "PENDING",
    ]),
    metrics: z.array(metric).max(8),
    visualizations: z.array(visualization).max(6),
    tables: z.array(table).max(6),
    findings: z.array(z.object({ text: safeText(240), source_step_ids: sources }).strict()).max(8),
    freshness: z
      .array(
        z
          .object({
            dataset: z.enum(["sales-v1", "support-v1"]),
            as_of: z.literal("2026-09-01"),
            period_start: z.string().regex(/^2026-0[1-8]-01$/),
            period_end: z.literal("2026-08-31"),
            synthetic: z.literal(true),
          })
          .strict(),
      )
      .max(2),
    source_step_ids: z.array(source).max(8),
    summary_digest: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict()
  .superRefine((v, ctx) => {
    const items = [...v.metrics, ...v.visualizations, ...v.tables, ...v.findings];
    const known = new Set(v.source_step_ids);
    if (
      known.size !== v.source_step_ids.length ||
      items.some((i) => i.source_step_ids.some((s) => !known.has(s)))
    )
      ctx.addIssue({ code: "custom", message: "Invalid source references" });
    if (["EMPTY", "INVALID", "PENDING"].includes(v.status) && (items.length || known.size))
      ctx.addIssue({ code: "custom", message: "Unavailable result contains conclusions" });
    if (v.status === "READY" && (v.run_outcome !== "COMPLETED" || !known.size))
      ctx.addIssue({ code: "custom", message: "Analysis is not completed" });
  });
export type AnalyticsResult = z.infer<typeof analyticsSchema>;
export type Visualization = z.infer<typeof visualization>;
export type AnalyticsTable = z.infer<typeof table>;
export type Unit = z.infer<typeof unit>;
export interface Dataset {
  id: string;
  name: string;
  grain: string;
  rows: number;
  as_of: string;
  synthetic: true;
  tool: string;
  prompt: string;
}
export interface AnalyticsSource {
  source_run_id: string;
  contract_version: string;
  result_digest: string;
  message_digest: string;
  connector_id: string;
  connector_type: "slack";
  config_fingerprint: string;
  channel: string;
}
export function formatValue(value: number | null, unit: Unit): string {
  if (value === null) return "Unavailable";
  if (unit === "USD")
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD",
      maximumFractionDigits: 2,
    }).format(value);
  return (
    new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(value) +
    (unit === "percent" ? "%" : unit === "hours" ? " h" : unit === "score" ? " / 5" : "")
  );
}
