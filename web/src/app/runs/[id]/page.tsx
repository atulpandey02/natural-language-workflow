"use client";

import { use } from "react";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading, StatusBadge } from "@/components/ui";
import { useRun, useRunActions, useRunSteps } from "@/lib/api/hooks";

export default function RunDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const run = useRun(id);
  const steps = useRunSteps(id);
  const actions = useRunActions(id);

  return (
    <AppShell>
      <h1>Run {id.slice(0, 8)}</h1>
      {run.isLoading ? <Loading /> : null}
      <ErrorBanner error={run.error} />

      {run.data ? (
        <div className="card">
          <div className="row" style={{ justifyContent: "space-between" }}>
            <StatusBadge status={run.data.status} />
            <span className="muted">
              trigger: {run.data.trigger}
              {run.data.scheduled_for ? ` · scheduled ${run.data.scheduled_for}` : ""}
            </span>
          </div>
          <p className="muted">
            created {new Date(run.data.created_at).toLocaleString()}
            {run.data.started_at
              ? ` · started ${new Date(run.data.started_at).toLocaleString()}`
              : ""}
            {run.data.finished_at
              ? ` · finished ${new Date(run.data.finished_at).toLocaleString()}`
              : ""}
          </p>
          {run.data.error ? <div className="banner">{run.data.error}</div> : null}
        </div>
      ) : null}

      <h2>Steps</h2>
      {steps.data && steps.data.length === 0 ? <Empty>No steps recorded yet.</Empty> : null}
      {steps.data && steps.data.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Step</th>
              <th>Tool</th>
              <th>Status</th>
              <th>Output preview</th>
            </tr>
          </thead>
          <tbody>
            {steps.data.map((s) => (
              <tr key={s.step_id}>
                <td>{s.step_id}</td>
                <td>{s.tool}</td>
                <td>
                  <StatusBadge status={s.status} />
                  {s.error ? <div className="muted">{s.error}</div> : null}
                </td>
                <td>
                  {s.output_preview ? (
                    <pre style={{ maxWidth: 360, whiteSpace: "pre-wrap" }}>
                      {JSON.stringify(s.output_preview)}
                    </pre>
                  ) : (
                    <span className="muted">—</span>
                  )}
                  {s.output_truncated ? <div className="muted">(truncated)</div> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      <h2>Action audit</h2>
      {actions.data && actions.data.length === 0 ? (
        <p className="muted">No external actions.</p>
      ) : null}
      {actions.data && actions.data.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Step</th>
              <th>Tool</th>
              <th>Destination</th>
              <th>Status</th>
              <th>Attempts</th>
            </tr>
          </thead>
          <tbody>
            {actions.data.map((a) => (
              <tr key={a.step_id}>
                <td>{a.step_id}</td>
                <td>{a.tool}</td>
                <td className="muted">{a.destination_summary ?? "—"}</td>
                <td>
                  <StatusBadge status={a.status} />
                  {a.error_class ? <div className="muted">{a.error_class}</div> : null}
                </td>
                <td>{a.attempts}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </AppShell>
  );
}
