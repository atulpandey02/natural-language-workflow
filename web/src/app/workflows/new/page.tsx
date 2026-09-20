"use client";

import { useState } from "react";
import { AppShell } from "@/components/AppShell";
import { PlanReview } from "@/components/PlanReview";
import { ErrorBanner } from "@/components/ui";
import { useCreatePlan } from "@/lib/api/hooks";
import type { PlanProposalOut } from "@/lib/api/types";

export default function NewWorkflowPage() {
  const createPlan = useCreatePlan();
  const [prompt, setPrompt] = useState("");
  const [proposal, setProposal] = useState<PlanProposalOut | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const result = await createPlan.mutateAsync(prompt);
    setProposal(result);
  }

  return (
    <AppShell>
      <h1>Describe a workflow</h1>
      <form onSubmit={onSubmit} className="card" noValidate>
        <label htmlFor="prompt">What should this workflow do?</label>
        <textarea
          id="prompt"
          rows={4}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          placeholder="Query yesterday's failed payments and post a summary to Slack…"
          required
        />
        <ErrorBanner error={createPlan.error} />
        <div style={{ marginTop: 12 }}>
          <button type="submit" disabled={createPlan.isPending || !prompt.trim()}>
            {createPlan.isPending ? "Planning…" : "Plan"}
          </button>
        </div>
      </form>

      {proposal ? <PlanReview proposal={proposal} /> : null}
    </AppShell>
  );
}
