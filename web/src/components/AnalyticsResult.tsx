"use client";

import { useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  analyticsSchema,
  type AnalyticsTable,
  type Visualization,
  formatValue,
} from "@/lib/analytics";
import { Empty, StatusBadge } from "./ui";

function Sources({ ids }: { ids: string[] }) {
  return (
    <span className="evidence-links">
      Source{" "}
      {ids.map((id) => (
        <a
          key={id}
          href={`#evidence-${id}`}
          onClick={() => {
            const target = document.getElementById(`evidence-${id}`);
            const drawer = target?.closest("details");
            if (drawer) drawer.open = true;
            target?.focus();
          }}
        >
          {id}
        </a>
      ))}
    </span>
  );
}
function Chart({ chart }: { chart: Visualization }) {
  const [hidden, setHidden] = useState<string[]>([]);
  const colors = ["#87b4ff", "#66ddb1", "#e9c56b"];
  const points = chart.labels.map((label, index) => ({
    label,
    ...Object.fromEntries(chart.series.map((s, i) => [`v${i}`, s.values[index]])),
  }));
  const ChartType = chart.kind === "line" ? LineChart : BarChart;
  return (
    <section className="chart-card" aria-label={chart.title} data-testid="analytics-chart">
      <h3>{chart.title}</h3>
      <div className="chart-frame">
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <ChartType
            data={points}
            accessibilityLayer
            margin={{ top: 10, right: 12, left: 8, bottom: 10 }}
          >
            <CartesianGrid stroke="#303a4c" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="label" stroke="#aab6cb" tick={{ fontSize: 11 }} tickMargin={10} />
            <YAxis
              domain={
                chart.series[0].unit === "score"
                  ? [0, 5]
                  : chart.series[0].unit === "percent"
                    ? [0, 100]
                    : [0, "auto"]
              }
              allowDecimals={chart.series[0].unit !== "count"}
              stroke="#aab6cb"
              tick={{ fontSize: 11 }}
              width={58}
              tickFormatter={(v: number) =>
                new Intl.NumberFormat("en-US", { notation: "compact" }).format(v)
              }
            />
            <Tooltip
              contentStyle={{ background: "#172235", border: "1px solid #536581", borderRadius: 8 }}
              formatter={(v) =>
                typeof v === "number" ? formatValue(v, chart.series[0].unit) : "Unavailable"
              }
            />
            <Legend />
            {chart.series.map((s, i) =>
              chart.kind === "line" ? (
                <Line
                  key={s.label}
                  dataKey={`v${i}`}
                  name={s.label}
                  hide={hidden.includes(s.label)}
                  stroke={colors[i]}
                  strokeWidth={2.5}
                  dot={{ r: 3 }}
                  connectNulls={false}
                  isAnimationActive={false}
                />
              ) : (
                <Bar
                  key={s.label}
                  dataKey={`v${i}`}
                  name={s.label}
                  hide={hidden.includes(s.label)}
                  fill={colors[i]}
                  radius={[4, 4, 0, 0]}
                  isAnimationActive={false}
                />
              ),
            )}
          </ChartType>
        </ResponsiveContainer>
      </div>
      <div className="row chart-controls">
        {chart.series.map((s) => (
          <button
            className="secondary"
            key={s.label}
            aria-pressed={!hidden.includes(s.label)}
            onClick={() =>
              setHidden(
                hidden.includes(s.label)
                  ? hidden.filter((n) => n !== s.label)
                  : [...hidden, s.label],
              )
            }
          >
            Toggle {s.label}
          </button>
        ))}
      </div>
      <Sources ids={chart.source_step_ids} />
    </section>
  );
}
function SupportingTable({ table }: { table: AnalyticsTable }) {
  return (
    <details className="supporting-table">
      <summary>{table.title}</summary>
      <div className="table-scroll" tabIndex={0} role="region" aria-label={table.title}>
        <table>
          <caption>{table.title}</caption>
          <thead>
            <tr>
              <th scope="col">{table.dimension}</th>
              {table.series.map((s) => (
                <th key={s.label} scope="col">
                  {s.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {table.labels.map((label, i) => (
              <tr key={label}>
                <th scope="row">{label}</th>
                {table.series.map((s) => (
                  <td key={s.label}>{formatValue(s.values[i], s.unit)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Sources ids={table.source_step_ids} />
    </details>
  );
}
export function AnalyticsResultView({ value }: { value: unknown }) {
  const parsed = analyticsSchema.safeParse(value);
  if (!parsed.success || parsed.data.status === "INVALID")
    return (
      <div className="banner" role="alert">
        This analysis could not be validated. No charts have been shown.
      </div>
    );
  const result = parsed.data;
  if (result.status === "PENDING")
    return (
      <Empty>Analysis is queued or running. Results appear after a completed checkpoint.</Empty>
    );
  if (result.status === "EMPTY")
    return <Empty>No completed analytical evidence is available for this run.</Empty>;
  return (
    <section aria-label="Analytical results" data-testid="analytics-result">
      <div className="row result-heading">
        <div>
          <p className="eyebrow">GROUNDED ANALYSIS</p>
          <h2>{result.title}</h2>
        </div>
        <StatusBadge status={result.run_outcome} />
      </div>
      {result.status === "PARTIAL" ? (
        <p className="notice">
          Partial results from completed steps. The workflow has not completed successfully.
        </p>
      ) : null}
      {result.freshness.map((f) => (
        <p className="muted" key={f.dataset}>
          Synthetic · {f.dataset} · {f.period_start}–{f.period_end} · Snapshot {f.as_of}
        </p>
      ))}
      <div className="kpi-grid">
        {result.metrics.map((m, i) => (
          <article className="kpi-card" key={i} data-testid="analytics-kpi">
            <span>{m.label}</span>
            <strong>{formatValue(m.value, m.unit)}</strong>
            <Sources ids={m.source_step_ids} />
          </article>
        ))}
      </div>
      <div className="findings">
        <h3>What the data shows</h3>
        <ul>
          {result.findings.map((f, i) => (
            <li key={i}>
              {f.text} <Sources ids={f.source_step_ids} />
            </li>
          ))}
        </ul>
      </div>
      <div className="chart-grid">
        {result.visualizations.map((c, i) => (
          <Chart chart={c} key={i} />
        ))}
      </div>
      <h3>Supporting data</h3>
      {result.tables.map((t, i) => (
        <SupportingTable table={t} key={i} />
      ))}
      <p className="muted small">
        Historical synthetic data. Comparisons describe this sample; they do not establish causes.
      </p>
    </section>
  );
}
