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
  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
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
            <div className="row">
              <span className="muted small">Review before running · No automatic delivery</span>
              <button type="submit" disabled={createPlan.isPending || !prompt.trim()}>
                {createPlan.isPending ? "Planning…" : "Plan"}
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
              <li>Choose a dataset and describe your question.</li>
              <li>Review the proposed tools and feasibility.</li>
              <li>Materialize the workflow, then start the run.</li>
              <li>Explore grounded results and source steps.</li>
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
