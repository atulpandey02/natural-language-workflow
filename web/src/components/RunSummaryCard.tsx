"use client";

import { StatusBadge } from "@/components/ui";
import type { RunSummaryOut } from "@/lib/api/types";

/**
 * Deterministic grounded run summary (M12B-A). Presentational only: every field
 * comes from the backend summary, which never surfaces raw tool output. All text
 * is rendered as JSX text content (React-escaped), so instruction-like or
 * markup-bearing detail can never inject HTML/script.
 */
export function RunSummaryCard({ summary }: { summary: RunSummaryOut }) {
  return (
    <div className="card" data-testid="run-summary">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <strong>Result summary</strong>
        <StatusBadge status={summary.outcome} />
      </div>
      <p data-testid="summary-headline">{summary.headline}</p>
      <p className="muted">
        {summary.succeeded} succeeded · {summary.failed} failed · {summary.unknown} unknown ·{" "}
        {summary.skipped} skipped
      </p>
      {summary.steps.length > 0 ? (
        <ul>
          {summary.steps.map((s) => (
            <li key={s.step_id}>
              <StatusBadge status={s.outcome} /> <strong>{s.step_id}</strong> — {s.detail}
            </li>
          ))}
        </ul>
      ) : null}
      <p className="muted">
        Deterministic summary of persisted state. Failed, skipped, and unknown steps are never
        reported as success.
      </p>
    </div>
  );
}
