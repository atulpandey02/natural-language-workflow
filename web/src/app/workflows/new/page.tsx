"use client";
import { ResponsiveDetails } from "@/components/ResponsiveDetails";

import { useRef, useState } from "react";
import { AppShell } from "@/components/AppShell";
import { PlanReview } from "@/components/PlanReview";
import { DatasetPicker } from "@/components/DatasetPicker";
import { ErrorBanner } from "@/components/ui";
import { useCreatePlan } from "@/lib/api/hooks";
import type { PlanProposalOut } from "@/lib/api/types";

export default function NewWorkflowPage() {
  const createPlan = useCreatePlan();
  const [prompt, setPrompt] = useState("");
  const [proposal, setProposal] = useState<PlanProposalOut | null>(null);
  const [submitted, setSubmitted] = useState("");
  const composer = useRef<HTMLTextAreaElement>(null);
  // `?dataset=sales-v1` (from the home page's next actions) preselects a sample.
  // Read once on the client; it only feeds the picker's effect, never markup.
  const [preselect] = useState<string | null>(() =>
    typeof window === "undefined"
      ? null
      : new URLSearchParams(window.location.search).get("dataset"),
  );
  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    // One plan request at a time: a double click or Enter while planning is ignored.
    if (createPlan.isPending || !prompt.trim()) return;
    setProposal(null);
    setSubmitted(prompt);
    try {
      setProposal(await createPlan.mutateAsync(prompt));
    } catch {
      /* mutation exposes error */
    }
  }
  return (
    <AppShell>
      <p className="eyebrow">YOUR DATA, A CLEARER PICTURE</p>
      <h1>What would you like to understand?</h1>
      <p className="lead muted">
        Ask a business question. Review the steps, run the analysis, and explore the evidence.
      </p>
      <div className="analysis-layout">
        <div className="analysis-main">
          <DatasetPicker
            preselect={preselect}
            onSelect={(text) => {
              setPrompt(text);
              setProposal(null);
              composer.current?.focus();
            }}
          />
          {submitted ? (
            <div className="request-bubble">
              <span className="eyebrow">YOUR REQUEST</span>
              <p>{submitted}</p>
            </div>
          ) : null}
          {proposal ? <PlanReview proposal={proposal} /> : null}
          <form onSubmit={onSubmit} className="composer" noValidate>
            <label htmlFor="prompt">What should this workflow do?</label>
            <textarea
              ref={composer}
              id="prompt"
              rows={4}
              maxLength={4000}
              value={prompt}
              onChange={(e) => {
                setPrompt(e.target.value);
                setProposal(null);
              }}
              placeholder="Analyze the last six months of sales…"
              required
            />
            <ErrorBanner error={createPlan.error} />
            {createPlan.isPending ? (
              <p className="muted small" role="status" data-testid="planning-progress">
                Preparing a plan and running the safety checks. This usually takes a few seconds.
              </p>
            ) : null}
            <div className="row">
              <span className="muted small">
                You&apos;ll review the plan first · Nothing is sent without approval
              </span>
              <button type="submit" disabled={createPlan.isPending || !prompt.trim()}>
                {createPlan.isPending ? "Preparing…" : "Prepare plan"}
              </button>
            </div>
          </form>
        </div>
        <ResponsiveDetails className="workflow-details" breakpoint={1200}>
          <summary>Workflow details</summary>
          <div className="details-content">
            <p className="eyebrow">HOW IT WORKS</p>
            <h2>From question to evidence</h2>
            <ol className="timeline">
              <li>Choose a sample dataset and ask your question.</li>
              <li>Prepare a plan and review its steps and safety checks.</li>
              <li>Save it as a workflow, then choose Run now.</li>
              <li>Explore the results and the step behind each finding.</li>
            </ol>
            <p className="muted">
              Slack sharing creates a separate proposal after analysis. A different admin or owner
              must approve it.
            </p>
            <p className="small muted">
              Samples are fixed historical data, with no real personal or customer information.
            </p>
          </div>
        </ResponsiveDetails>
      </div>
    </AppShell>
  );
}
