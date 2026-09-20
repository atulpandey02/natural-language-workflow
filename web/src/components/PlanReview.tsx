"use client";

import { useRouter } from "next/navigation";
import type { PlanProposalOut } from "@/lib/api/types";
import { useMaterialize } from "@/lib/api/hooks";
import { ErrorBanner, StatusBadge } from "@/components/ui";

const MATERIALIZABLE = new Set(["PASS", "NEEDS_APPROVAL"]);

interface Finding {
  code?: string;
  severity?: string;
  message?: string;
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
    const result = await materialize.mutateAsync(proposal.id);
    router.push(`/workflows/${result.workflow_id}`);
  }

  return (
    <div className="card">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2 style={{ margin: 0, fontSize: 18 }}>{proposal.workflow_name}</h2>
        <StatusBadge status={proposal.status} />
      </div>

      {proposal.proposed_plan ? (
        <>
          <h3 style={{ fontSize: 14 }}>Proposed steps</h3>
          <PlanSteps plan={proposal.proposed_plan} />
        </>
      ) : (
        <p className="muted">No executable plan was produced.</p>
      )}

      {findings.length > 0 ? (
        <>
          <h3 style={{ fontSize: 14 }}>Findings</h3>
          <ul>
            {findings.map((f, i) => (
              <li key={i}>
                <span className="muted">{f.severity ?? "info"}:</span> {f.code}
                {f.message ? ` — ${f.message}` : ""}
              </li>
            ))}
          </ul>
        </>
      ) : null}

      {clarifications.length > 0 ? (
        <>
          <h3 style={{ fontSize: 14 }}>Clarifications needed</h3>
          <ul>
            {clarifications.map((q, i) => (
              <li key={i}>{q}</li>
            ))}
          </ul>
        </>
      ) : null}

      <ErrorBanner error={materialize.error} />

      {canMaterialize ? (
        <button onClick={onMaterialize} disabled={materialize.isPending}>
          {materialize.isPending ? "Materializing…" : "Materialize workflow"}
        </button>
      ) : (
        <p className="muted" data-testid="materialize-blocked">
          This plan is <strong>{proposal.status}</strong> and cannot be materialized. Revise the
          request or answer the clarifications, then plan again.
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
    <table>
      <thead>
        <tr>
          <th>Step</th>
          <th>Tool</th>
          <th>Connector</th>
          <th>Depends on</th>
        </tr>
      </thead>
      <tbody>
        {steps.map((s, i) => (
          <tr key={i}>
            <td>{String(s.id ?? i)}</td>
            <td>{String(s.tool ?? "")}</td>
            <td className="muted">{s.connector ? String(s.connector) : "—"}</td>
            <td className="muted">
              {Array.isArray(s.depends_on) && s.depends_on.length
                ? (s.depends_on as string[]).join(", ")
                : "—"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
