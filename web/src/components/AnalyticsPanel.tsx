"use client";

import { useState } from "react";
import { useRunAnalytics, useSlackProposal } from "@/lib/api/analytics-hooks";
import { useConnectors } from "@/lib/api/hooks";
import type { PlanProposalOut } from "@/lib/api/types";
import { analyticsSchema } from "@/lib/analytics";
import { AnalyticsResultView } from "./AnalyticsResult";
import { ErrorBanner, Loading } from "./ui";
import { PlanReview } from "./PlanReview";

export function AnalyticsPanel({ runId }: { runId: string }) {
  const result = useRunAnalytics(runId);
  const parsed = analyticsSchema.safeParse(result.data);
  const canShare = parsed.success && parsed.data.status === "READY" && !result.error;
  const connectors = useConnectors();
  const create = useSlackProposal(runId);
  const [selection, setSelection] = useState("");
  const [proposal, setProposal] = useState<PlanProposalOut | null>(null);
  const choices = (connectors.data ?? [])
    .filter((c) => c.type === "slack" && c.status !== "disabled")
    .flatMap((c) => {
      const channels = [
        c.config.default_channel,
        ...(Array.isArray(c.config.allowed_channels) ? c.config.allowed_channels : []),
      ].filter((v): v is string => typeof v === "string" && /^[CGD][A-Z0-9]+$/.test(v));
      return [...new Set(channels)].map((channel) => ({
        key: `${c.id}:${channel}`,
        id: c.id,
        channel,
        label: `${c.name} · ${channel}`,
      }));
    });
  async function propose() {
    if (!canShare) return;
    const selected = choices.find((c) => c.key === selection);
    if (!selected) return;
    try {
      setProposal(
        await create.mutateAsync({ connector_id: selected.id, channel: selected.channel }),
      );
    } catch {
      /* mutation exposes the error */
    }
  }
  return (
    <>
      {result.isLoading ? <Loading label="Loading analytical evidence…" /> : null}
      <ErrorBanner error={result.error} />
      {result.data ? <AnalyticsResultView value={result.data} /> : null}
      {canShare ? (
        <section className="card handoff">
          <div className="handoff-intro">
            <p className="eyebrow">NEXT / SHARE INSIGHTS</p>
            <h2>Take the findings to your team</h2>
            <p className="muted">
              Create a separate Slack proposal from this completed analysis. A different admin or
              owner must approve the exact message before delivery.
            </p>
          </div>
          <div className="handoff-controls">
            <ErrorBanner error={connectors.error} />
            {choices.length ? (
              <>
                <label htmlFor="slack-destination">Slack destination</label>
                <select
                  id="slack-destination"
                  value={selection}
                  onChange={(e) => {
                    setSelection(e.target.value);
                    setProposal(null);
                  }}
                >
                  <option value="">Select connector and channel</option>
                  {choices.map((c) => (
                    <option key={c.key} value={c.key}>
                      {c.label}
                    </option>
                  ))}
                </select>
                <button onClick={propose} disabled={!selection || create.isPending}>
                  {create.isPending ? "Preparing proposal…" : "Send summary to Slack"}
                </button>
              </>
            ) : (
              <p>No active Slack destination. Ask an admin to configure a connector.</p>
            )}
            <ErrorBanner error={create.error} />
          </div>
        </section>
      ) : null}
      {canShare && proposal ? <PlanReview proposal={proposal} /> : null}
    </>
  );
}
