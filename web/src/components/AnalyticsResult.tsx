"use client";

import { useEffect, useId, useRef, useState, type CSSProperties } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import Link from "next/link";
import {
  analyticsSchema,
  type AnalyticsResult,
  type AnalyticsTable,
  type Unit,
  type Visualization,
  formatValue,
} from "@/lib/analytics";
import {
  formatAxis,
  formatPeriod,
  kpiDisplay,
  metricKind,
  seriesStyle,
  unitLabel,
} from "@/lib/analytics-presentation";
import { Empty, StatusBadge } from "./ui";

type Finding = AnalyticsResult["findings"][number];

function SeriesMark({ label }: { label: string }) {
  const style = seriesStyle(label);
  return (
    <span
      aria-hidden="true"
      className={`series-mark ${style.marker}`}
      style={{ "--series": style.color } as CSSProperties}
    />
  );
}
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
function Chart({ chart, index }: { chart: Visualization; index: number }) {
  const [hidden, setHidden] = useState<string[]>([]);
  const descriptionId = useId();
  const horizontal = chart.kind === "bar";
  const unit = chart.series[0].unit;
  const points = chart.labels.map((label, index) => ({
    label,
    ...Object.fromEntries(chart.series.map((s, i) => [`v${i}`, s.values[index]])),
  }));
  const ChartType = horizontal ? BarChart : LineChart;
  const numberAxis = {
    type: "number" as const,
    domain: (unit === "score" ? [0, 5] : unit === "percent" ? [0, 100] : [0, "auto"]) as [
      number,
      number | string,
    ],
    allowDecimals: unit !== "count",
    tickFormatter: (v: number) => formatAxis(v, unit),
  };
  const categoryAxis = { type: "category" as const, dataKey: "label" };
  const axis = {
    stroke: "#8a94a7",
    tickLine: false,
    axisLine: false,
    tick: { fontSize: 12, fill: "#667085" },
    tickMargin: 10,
  };
  return (
    <section
      className={`chart-card chart-${index} chart-${chart.kind}`}
      aria-label={chart.title}
      data-testid="analytics-chart"
    >
      <div className="chart-heading">
        <h3>{chart.title}</h3>
        <span className="chart-unit">{unitLabel[unit]}</span>
      </div>
      <div
        className="chart-frame"
        role="group"
        aria-label={`${chart.title} interactive chart`}
        aria-describedby={descriptionId}
      >
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <ChartType
            data={points}
            layout={horizontal ? "vertical" : "horizontal"}
            accessibilityLayer
            margin={{ top: 12, right: 22, left: 0, bottom: 8 }}
          >
            <CartesianGrid
              stroke="#e3e8f0"
              strokeDasharray="2 5"
              horizontal={!horizontal}
              vertical={horizontal}
            />
            <XAxis
              {...axis}
              {...(horizontal ? numberAxis : categoryAxis)}
              tickFormatter={horizontal ? numberAxis.tickFormatter : formatPeriod}
              minTickGap={16}
            />
            <YAxis
              {...axis}
              {...(horizontal ? categoryAxis : numberAxis)}
              width={horizontal ? 96 : 58}
              interval={horizontal ? 0 : undefined}
            />
            <Tooltip
              cursor={
                horizontal ? { fill: "#5165d60d" } : { stroke: "#8a94a7", strokeDasharray: "3 3" }
              }
              allowEscapeViewBox={{ x: false, y: false }}
              content={({ active, label }) => {
                const pointIndex = chart.labels.indexOf(String(label));
                if (!active || pointIndex < 0) return null;
                return (
                  <div className="chart-tooltip" role="status">
                    <strong>{chart.labels[pointIndex]}</strong>
                    {chart.series
                      .filter((s) => !hidden.includes(s.label))
                      .map((s) => (
                        <div key={s.label}>
                          <span>
                            <SeriesMark label={s.label} />
                            {s.label}
                          </span>
                          <b>{formatValue(s.values[pointIndex], s.unit)}</b>
                        </div>
                      ))}
                  </div>
                );
              }}
            />
            {chart.series.map((s, i) =>
              chart.kind === "line" ? (
                <Line
                  key={s.label}
                  dataKey={`v${i}`}
                  name={s.label}
                  hide={hidden.includes(s.label)}
                  type="linear"
                  stroke={seriesStyle(s.label).color}
                  strokeDasharray={seriesStyle(s.label).dash}
                  strokeWidth={2.5}
                  dot={{ r: 3.5, strokeWidth: 2, fill: "#ffffff" }}
                  activeDot={{ r: 5 }}
                  connectNulls={false}
                  isAnimationActive={false}
                />
              ) : (
                <Bar
                  key={s.label}
                  dataKey={`v${i}`}
                  name={s.label}
                  hide={hidden.includes(s.label)}
                  fill={seriesStyle(s.label).color}
                  maxBarSize={18}
                  radius={[0, 3, 3, 0]}
                  isAnimationActive={false}
                />
              ),
            )}
          </ChartType>
        </ResponsiveContainer>
      </div>
      <p className="sr-only" id={descriptionId}>
        {chart.title}.{" "}
        {horizontal ? "Category comparison" : "Recorded observations joined with straight lines"}.{" "}
        {unitLabel[unit]}.
        {chart.labels
          .map(
            (label, i) =>
              ` ${label}: ${chart.series.map((s) => `${s.label} ${formatValue(s.values[i], s.unit)}`).join(", ")}.`,
          )
          .join("")}
      </p>
      <div className="chart-footer">
        <div className="chart-controls" role="group" aria-label={`${chart.title} series`}>
          {chart.series.map((s) => (
            <button
              className="secondary"
              key={s.label}
              aria-label={`Toggle ${s.label}`}
              aria-pressed={!hidden.includes(s.label)}
              onClick={() =>
                setHidden(
                  hidden.includes(s.label)
                    ? hidden.filter((n) => n !== s.label)
                    : [...hidden, s.label],
                )
              }
            >
              <SeriesMark label={s.label} />
              {s.label}
              <span aria-hidden="true" className="series-visibility">
                {hidden.includes(s.label) ? "Hidden" : "Shown"}
              </span>
            </button>
          ))}
        </div>
        <Sources ids={chart.source_step_ids} />
      </div>
    </section>
  );
}
function SupportingTable({ table }: { table: AnalyticsTable }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const cueId = useId();
  const [overflows, setOverflows] = useState(false);
  useEffect(() => {
    const region = scrollRef.current;
    if (!region) return;
    const observer = new ResizeObserver(() => {
      setOverflows(region.clientWidth > 0 && region.scrollWidth > region.clientWidth + 1);
    });
    observer.observe(region);
    // Disclosure opening, viewport changes and table content/font sizing can
    // each change whether the region needs horizontal scrolling.
    const content = region.querySelector("table");
    if (content) observer.observe(content);
    return () => observer.disconnect();
  }, []);
  return (
    <details className="supporting-table">
      <summary>
        {table.title}
        <span className="table-count">{table.labels.length} rows</span>
      </summary>
      {overflows ? (
        <p className="table-scroll-cue" id={cueId}>
          More columns: scroll horizontally or use ← / → when focused.
        </p>
      ) : null}
      <div
        ref={scrollRef}
        className="table-scroll"
        tabIndex={0}
        role="region"
        aria-label={table.title}
        aria-describedby={overflows ? cueId : undefined}
      >
        <table>
          <caption>{table.title}</caption>
          <thead>
            <tr>
              <th scope="col">{table.dimension}</th>
              {table.series.map((s) => (
                <th key={s.label} scope="col">
                  <SeriesMark label={s.label} />
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
// Presentation grouping only: the grounded finding text is shown unchanged and
// keeps its source links; nothing here adds a claim about the data.
const ATTENTION =
  /\b(declin|decreas|drop|fell|fall|below|backlog|breach|miss|worse|risk|overdue|reopen|slipp)/i;

function Insights({ findings, ready }: { findings: Finding[]; ready: boolean }) {
  const attention = findings.filter((f) => ATTENTION.test(f.text));
  const changed = findings.filter((f) => !ATTENTION.test(f.text));
  const list = (items: Finding[], offset: number) => (
    <ol>
      {items.map((f, i) => (
        <li key={i}>
          <span className="finding-index" aria-hidden="true">
            {String(offset + i + 1).padStart(2, "0")}
          </span>
          <div>
            {f.text}
            <Sources ids={f.source_step_ids} />
          </div>
        </li>
      ))}
    </ol>
  );
  return (
    <div className="insight-grid findings">
      <section className="insight" aria-labelledby="changed-title">
        <h3 id="changed-title">What changed</h3>
        {changed.length ? (
          list(changed, 0)
        ) : (
          <p className="muted small">No other findings in this sample.</p>
        )}
      </section>
      <section className="insight attention" aria-labelledby="attention-title">
        <h3 id="attention-title">Needs attention</h3>
        {attention.length ? (
          list(attention, changed.length)
        ) : (
          <p className="muted small">Nothing in these findings was flagged for attention.</p>
        )}
      </section>
      <section className="insight actions" aria-labelledby="actions-title">
        <h3 id="actions-title">Recommended actions</h3>
        <ul>
          <li>Open a finding&apos;s source step to check the evidence behind it.</li>
          {ready ? (
            <li>Share the summary with your team below; a second admin approves it first.</li>
          ) : null}
          <li>
            <Link href="/workflows/new">Ask a follow-up question</Link>
          </li>
        </ul>
        <p className="insight-note">Suggested next steps in NLW, not conclusions from the data.</p>
      </section>
    </div>
  );
}

/** A KPI value that never clips: exact when it fits, compact (and marked) when not. */
function KpiValue({ value, unit, label }: { value: number | null; unit: Unit; label: string }) {
  const shown = kpiDisplay(value, unit);
  if (!shown.compacted) {
    return (
      <>
        <strong>{shown.text}</strong>
        <span className="metric-kind">{metricKind(label)}</span>
      </>
    );
  }
  // Exact figure: read by screen readers in place, visible on demand (keyboard or
  // pointer), and able to break only at thousands separators.
  const parts = shown.exact.split(",");
  return (
    <>
      <strong title={shown.exact} data-compacted="true">
        <span aria-hidden="true">{shown.text}</span>
        <span className="sr-only">{shown.exact}</span>
      </strong>
      <span className="metric-kind">{metricKind(label)} · rounded</span>
      <details className="kpi-exact">
        <summary>Exact value</summary>
        <span className="kpi-exact-value">
          {parts.map((part, i) => (
            <span key={i}>
              {part}
              {i < parts.length - 1 ? (
                <>
                  ,<wbr />
                </>
              ) : null}
            </span>
          ))}
        </span>
      </details>
    </>
  );
}

export function AnalyticsResultView({
  value,
  outcomeOverride,
}: {
  value: unknown;
  /** A more cautious run outcome from the run page; replaces the result's own badge. */
  outcomeOverride?: string;
}) {
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
  const dataset = result.freshness.length === 1 ? result.freshness[0].dataset : undefined;
  const title =
    result.title === "Analysis results"
      ? dataset === "sales-v1"
        ? "Sales performance"
        : dataset === "support-v1"
          ? "Support performance"
          : result.title
      : result.title;
  return (
    <section
      className="analytics-result"
      aria-label="Analytical results"
      data-testid="analytics-result"
    >
      <div className="row result-heading">
        <div>
          <p className="eyebrow">Analysis report</p>
          <h2>{title}</h2>
        </div>
        <StatusBadge status={outcomeOverride ?? result.run_outcome} />
      </div>
      {result.status === "PARTIAL" ? (
        <p className="notice" role="status">
          Partial results from completed steps. The workflow has not completed successfully.
        </p>
      ) : null}
      <div className="result-provenance">
        {result.freshness.map((f) => (
          <p key={f.dataset}>
            <span className="dataset-tag">Synthetic · {f.dataset}</span>
            <span>
              {f.period_start} — {f.period_end}
            </span>
            <span>Snapshot {f.as_of}</span>
          </p>
        ))}
      </div>
      <div className="kpi-grid">
        {result.metrics.map((m, i) => (
          <article
            className="kpi-card"
            key={i}
            data-testid="analytics-kpi"
            style={{ "--series": seriesStyle(m.label).color } as CSSProperties}
          >
            <span className="kpi-label">
              <SeriesMark label={m.label} />
              {m.label}
            </span>
            <KpiValue value={m.value} unit={m.unit} label={m.label} />
            <Sources ids={m.source_step_ids} />
          </article>
        ))}
      </div>
      <Insights findings={result.findings} ready={result.status === "READY" && !outcomeOverride} />
      <div className="chart-section-heading">
        <h3>Performance trends & breakdowns</h3>
        <span>Hover or focus a chart and use arrow keys to inspect</span>
      </div>
      <div className="chart-grid">
        {result.visualizations.map((c, i) => (
          <Chart chart={c} index={i} key={i} />
        ))}
      </div>
      <section className="supporting-data" aria-labelledby="supporting-title">
        <div className="section-heading">
          <h3 id="supporting-title">Supporting data</h3>
          <span className="small muted">Expand to inspect exact values</span>
        </div>
        {result.tables.map((t, i) => (
          <SupportingTable table={t} key={i} />
        ))}
      </section>
      <p className="muted small analysis-footnote">
        Historical synthetic data. Comparisons describe this sample; they do not establish causes.
      </p>
    </section>
  );
}
