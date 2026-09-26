"use client";
import { ResponsiveDetails } from "@/components/ResponsiveDetails";
import Link from "next/link";
import { use } from "react";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading, StatusBadge } from "@/components/ui";
import { RunSummaryCard } from "@/components/RunSummaryCard";
import { AnalyticsPanel } from "@/components/AnalyticsPanel";
import {
  useRun,
  useRunActions,
  useRunSteps,
  useRunSummary,
  useWorkflowProvenance,
} from "@/lib/api/hooks";
export default function RunDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const run = useRun(id),
    steps = useRunSteps(id),
    actions = useRunActions(id),
    summary = useRunSummary(id);
  const provenance = useWorkflowProvenance(run.data?.workflow_version_id);
  const source = provenance.data?.analytics_source;
  return (
    <AppShell>
      <p className="eyebrow">ANALYSIS & EXECUTION</p>
      <div className="row page-heading">
        <h1>Your analysis</h1>
        <Link href="/workflows/new">Ask a follow-up →</Link>
      </div>
      {run.isLoading ? <Loading /> : null}
      <ErrorBanner error={run.error} />
      {run.data ? (
        <div className="run-strip">
          <StatusBadge status={summary.data?.outcome ?? run.data.status} />
          <span className="muted">
            Run {id.slice(0, 8)} · {new Date(run.data.created_at).toLocaleString()}
          </span>
          <Link href={`/workflows/${run.data.workflow_id}`}>Open workflow</Link>
        </div>
      ) : null}
      {run.data?.error ? (
        <div className="banner" role="alert">
          {run.data.error}
        </div>
      ) : null}
      <div className="analysis-layout">
        <div className="analysis-main">
          <AnalyticsPanel runId={id} />
          {summary.data ? <RunSummaryCard summary={summary.data} /> : null}
          {!summary.data && summary.error ? (
            <div className="card" data-testid="run-summary-error">
              <strong>Result summary</strong>
              <ErrorBanner error={summary.error} />
            </div>
          ) : null}
        </div>
        <ResponsiveDetails className="workflow-details" breakpoint={1200}>
          <summary>Workflow & evidence details</summary>
          <div className="details-content">
            <p className="eyebrow">DURABLE EXECUTION</p>
            <h2>Workflow & evidence</h2>
            {source ? (
              <div className="card">
                <p className="eyebrow">TWO-PROPOSAL JOURNEY</p>
                <Link href={`/runs/${source.source_run_id}`}>Open source analysis run</Link>
                <p className="small muted">
                  This run sends the immutable summary from {source.contract_version}.
                </p>
                <p className="small muted">
                  Message digest <code>{source.message_digest}</code>
                </p>
                <p>Destination: {source.channel}</p>
              </div>
            ) : null}
            <ErrorBanner error={steps.error} />
            {steps.data?.length === 0 ? <Empty>No steps recorded yet.</Empty> : null}
            <ol className="timeline">
              {summary.data?.steps.map((s) => (
                <li id={`evidence-${s.step_id}`} key={s.step_id} tabIndex={-1}>
                  <StatusBadge status={s.outcome} />
                  <h3>{s.step_id}</h3>
                  <code>{s.tool}</code>
                  <p>{s.detail}</p>
                  {steps.data?.find((step) => step.step_id === s.step_id)?.finished_at ? (
                    <p className="small muted">
                      Checkpoint completed{" "}
                      {new Date(
                        steps.data.find((step) => step.step_id === s.step_id)!.finished_at!,
                      ).toLocaleString()}
                    </p>
                  ) : null}
                </li>
              ))}
            </ol>
            {summary.data?.outcome === "WAITING_APPROVAL" ? (
              <p className="notice">
                Waiting for a different admin or owner.{" "}
                <Link href="/approvals">Review approvals</Link>
              </p>
            ) : null}
            <h3>Action audit</h3>
            <ErrorBanner error={actions.error} />
            {actions.data?.length === 0 ? <p className="muted">No external actions.</p> : null}
            {actions.data?.map((a) => (
              <article className="card" key={a.step_id}>
                <strong>{a.step_id}</strong>
                <p>{a.tool}</p>
                <p>Destination: {a.destination_summary ?? "Unavailable"}</p>
                <StatusBadge status={a.status} />
                <p className="small muted">
                  {a.attempts} attempts · {a.error_class ?? "No error recorded"}
                </p>
              </article>
            ))}
            <p className="muted small">
              Each result cites a completed source step. Failed, skipped and unknown work cannot
              supply analytical findings.
            </p>
          </div>
        </ResponsiveDetails>
      </div>
    </AppShell>
  );
}
