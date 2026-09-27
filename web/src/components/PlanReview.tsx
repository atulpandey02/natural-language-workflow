"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import type { PlanProposalOut } from "@/lib/api/types";
import { useMaterialize } from "@/lib/api/hooks";
import { ErrorBanner, StatusBadge } from "@/components/ui";
import { findingText, planStatusCopy, toolLabel } from "@/lib/plan-language";

const MATERIALIZABLE = new Set(["PASS", "NEEDS_APPROVAL"]);

interface Finding {
  code?: string;
  severity?: string;
}

export function PlanReview({ proposal }: { proposal: PlanProposalOut }) {
  const router = useRouter();
  const materialize = useMaterialize();
  const canMaterialize = MATERIALIZABLE.has(proposal.status);

  const findings = Array.isArray((proposal.feasibility as { findings?: Finding[] })?.findings)
    ? ((proposal.feasibility as { findings?: Finding[] }).findings as Finding[])
    : [];
  const clarifications = proposal.clarification_questions ?? [];

  async function onMaterialize() {
    if (materialize.isPending) return;
    try {
      const result = await materialize.mutateAsync(proposal.id);
      router.push(`/workflows/${result.workflow_id}`);
    } catch {
      /* mutation exposes the error */
    }
  }

  return (
    <div className={`card${proposal.analytics_source ? " handoff-review" : ""}`}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2 style={{ margin: 0, fontSize: 18 }}>{proposal.workflow_name}</h2>
        <StatusBadge status={proposal.status} />
      </div>
      <p className="muted" data-testid="plan-status-copy">
        {planStatusCopy(proposal.status)}
      </p>

      {proposal.analytics_source ? (
        <section className="handoff-evidence" aria-label="Slack proposal evidence">
          <p className="eyebrow">IMMUTABLE SLACK PROPOSAL</p>
          <h3>Exact message for approval</h3>
          <p className="message-destination">
            Destination: <strong>{proposal.analytics_source.channel}</strong>
          </p>
          <pre aria-label="Immutable Slack message">
            {String(
              (
                proposal.proposed_plan?.steps as Array<{ args?: { text?: string } }> | undefined
              )?.[0]?.args?.text ?? "Message unavailable",
            )}
          </pre>
          <Link href={`/runs/${proposal.analytics_source.source_run_id}`}>
            Open source analysis run
          </Link>
          <p className="muted small">
            {proposal.analytics_source.contract_version} · message digest{" "}
            <code>{proposal.analytics_source.message_digest}</code>
          </p>
          <p>A separate run will request approval from a different admin or owner.</p>
        </section>
      ) : null}
      {proposal.proposed_plan ? (
        <>
          <h3 style={{ fontSize: 14 }}>What will happen</h3>
          <PlanSteps plan={proposal.proposed_plan} />
        </>
      ) : (
        <p className="muted">The planner didn&apos;t propose any steps for this request.</p>
      )}

      {findings.length > 0 ? (
        <>
          <h3 style={{ fontSize: 14 }}>Safety checks</h3>
          <ul data-testid="plan-findings">
            {[...new Set(findings.map((f) => findingText(f.code)))].map((text) => (
              <li key={text}>{text}</li>
            ))}
          </ul>
        </>
      ) : null}

      {clarifications.length > 0 ? (
        <>
          <h3 style={{ fontSize: 14 }}>Questions from the planner</h3>
          <ul>
            {clarifications.map((q, i) => (
              <li key={i}>{q}</li>
            ))}
          </ul>
        </>
      ) : null}

      <ErrorBanner error={materialize.error} />

      {canMaterialize ? (
        <div className="row">
          <button
            onClick={onMaterialize}
            disabled={materialize.isPending}
            aria-describedby="save-workflow-help"
          >
            {materialize.isPending ? "Saving…" : "Save workflow"}
          </button>
          <span className="muted small" id="save-workflow-help">
            Saves a fixed, versioned copy of these steps. Nothing runs until you choose Run now.
          </span>
        </div>
      ) : (
        <p className="muted" data-testid="materialize-blocked">
          This plan can&apos;t be saved yet. Revise your request, then prepare the plan again.
        </p>
      )}
    </div>
  );
}

function PlanSteps({ plan }: { plan: Record<string, unknown> }) {
  const steps = Array.isArray((plan as { steps?: unknown[] }).steps)
    ? ((plan as { steps?: Array<Record<string, unknown>> }).steps as Array<Record<string, unknown>>)
    : [];
  if (steps.length === 0) return <p className="muted">No steps.</p>;
  return (
    <div className="table-scroll" tabIndex={0} role="region" aria-label="Proposed steps">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Step</th>
            <th>Uses</th>
            <th>Runs after</th>
          </tr>
        </thead>
        <tbody>
          {steps.map((s, i) => (
            <tr key={i}>
              <td>{i + 1}</td>
              <td>{toolLabel(s.tool)}</td>
              <td className="muted">{s.connector ? String(s.connector) : "Built in"}</td>
              <td className="muted">
                {Array.isArray(s.depends_on) && s.depends_on.length
                  ? (s.depends_on as string[])
                      .map((d) => `step ${steps.findIndex((x) => x.id === d) + 1 || "?"}`)
                      .join(", ")
                  : "Start"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
