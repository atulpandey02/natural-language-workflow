"use client";
import { ResponsiveDetails } from "@/components/ResponsiveDetails";
import Link from "next/link";
import { use } from "react";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading, OutcomeNotice, StatusBadge } from "@/components/ui";
import { RunSummaryCard } from "@/components/RunSummaryCard";
import { EvidenceChain, runChain } from "@/components/EvidenceChain";
import {
  OUTCOME_PENDING,
  deriveRunOutcome,
  isCautiousOutcome,
  isUnknownOutcome,
} from "@/lib/run-outcome";
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
  // Conservative precedence (lib/run-outcome.ts): UNKNOWN action evidence wins over
  // any summary; raw run status is never presented as the established outcome.
  const outcome = deriveRunOutcome({
    summary: { data: summary.data?.outcome, loading: summary.isLoading },
    actions: { data: actions.data?.map((a) => a.status), loading: actions.isLoading },
  });
  const cautious = isCautiousOutcome(outcome);
  const unknownSteps = new Set(
    (actions.data ?? []).filter((a) => a.status === "unknown").map((a) => a.step_id),
  );
  // A summary that reads less cautiously than the evidence is set aside, never styled as success.
  const summaryConflicts =
    Boolean(summary.data) && cautious && !isUnknownOutcome(summary.data?.outcome);
  const readFailed = Boolean(summary.error || actions.error);
  const source = provenance.data?.analytics_source;
  return (
    <AppShell>
      <div className="analytics-workspace">
        <div className="row page-heading">
          <h1>Analysis workspace</h1>
          <Link href="/workflows/new">Ask a follow-up →</Link>
        </div>
        {run.isLoading ? <Loading /> : null}
        <ErrorBanner error={run.error} />
        {run.data ? <EvidenceChain {...runChain(outcome)} /> : null}
        {run.data ? (
          <div className="run-strip">
            <StatusBadge status={outcome} />
            <span className="muted">
              Run {id.slice(0, 8)} · {new Date(run.data.created_at).toLocaleString()}
            </span>
            <Link href={`/workflows/${run.data.workflow_id}`}>Open workflow</Link>
          </div>
        ) : null}
        {/* The engine's raw error text is diagnostic, not user copy: explain the outcome instead. */}
        {run.data && outcome === OUTCOME_PENDING ? (
          <Loading label="Checking this run's recorded outcome…" />
        ) : null}
        {run.data ? <OutcomeNotice outcome={outcome} /> : null}
        {run.data && readFailed ? (
          <div className="row" data-testid="reload-evidence">
            <button
              type="button"
              className="secondary"
              onClick={() => {
                void summary.refetch();
                void actions.refetch();
              }}
            >
              Reload run evidence
            </button>
            <span className="muted small">
              This only reloads what NLW has recorded. It doesn&apos;t run the workflow again.
            </span>
          </div>
        ) : null}
        {/* A run that can't be loaded (missing, or another workspace's) gets one
            explanation, not a cascade of identical errors from every panel. */}
        {run.error ? (
          <p>
            <Link href="/runs">Back to runs</Link>
          </p>
        ) : null}
        {run.error ? null : (
          <div className="analysis-layout">
            <div className="analysis-main">
              <AnalyticsPanel runId={id} cautiousOutcome={cautious ? outcome : undefined} />
              {summary.data && !summaryConflicts ? <RunSummaryCard summary={summary.data} /> : null}
              {summaryConflicts && outcome !== OUTCOME_PENDING ? (
                <div className="card" data-testid="run-summary-conflict">
                  <strong>Result summary</strong>
                  <p className="muted">
                    Set aside: the action audit records an outcome NLW couldn&apos;t confirm, so
                    this run is shown with the more cautious outcome above.
                  </p>
                </div>
              ) : null}
              {!summary.data && summary.error ? (
                <div className="card" data-testid="run-summary-error">
                  <strong>Result summary</strong>
                  <ErrorBanner error={summary.error} />
                </div>
              ) : null}
            </div>
            <ResponsiveDetails className="workflow-details" breakpoint={1200} desktopOpen={false}>
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
                  {summary.data?.steps.map((s) => {
                    // An action recorded as unknown overrides the step's summary outcome.
                    const stepUnknown = s.outcome === "UNKNOWN" || unknownSteps.has(s.step_id);
                    return (
                      <li id={`evidence-${s.step_id}`} key={s.step_id} tabIndex={-1}>
                        <StatusBadge status={stepUnknown ? "UNKNOWN" : s.outcome} />
                        <h3>{s.step_id}</h3>
                        <code>{s.tool}</code>
                        <p>{s.detail}</p>
                        {steps.data?.find((step) => step.step_id === s.step_id)?.finished_at ? (
                          <p className="small muted">
                            {stepUnknown ? "Checkpoint recorded" : "Checkpoint completed"}{" "}
                            {new Date(
                              steps.data.find((step) => step.step_id === s.step_id)!.finished_at!,
                            ).toLocaleString()}
                          </p>
                        ) : null}
                      </li>
                    );
                  })}
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
        )}
      </div>
    </AppShell>
  );
}
