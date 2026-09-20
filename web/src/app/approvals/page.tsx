"use client";

import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading, RoleGate, canApprove } from "@/components/ui";
import { useApprovals, useCurrentWorkspace, useDecideApproval } from "@/lib/api/hooks";

export default function ApprovalsPage() {
  const approvals = useApprovals();
  const current = useCurrentWorkspace();
  const decide = useDecideApproval();
  const role = current.data?.role;

  return (
    <AppShell>
      <h1>Pending approvals</h1>
      {approvals.isLoading ? <Loading /> : null}
      <ErrorBanner error={approvals.error} />
      <ErrorBanner error={decide.error} />
      {!canApprove(role) ? (
        <p className="muted">You can view approvals; an admin or owner must decide them.</p>
      ) : null}

      {approvals.data && approvals.data.length === 0 ? <Empty>No pending approvals.</Empty> : null}

      {(approvals.data ?? []).map((a) => (
        <div key={a.id} className="card">
          <div className="row" style={{ justifyContent: "space-between" }}>
            <strong>{a.tool}</strong>
            <span className="muted">connector: {a.connector_name}</span>
          </div>
          <p className="muted">
            run {a.run_id.slice(0, 8)} · step {a.step_id}
            {a.requested_at ? ` · requested ${new Date(a.requested_at).toLocaleString()}` : ""}
          </p>
          <pre style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(a.preview, null, 2)}</pre>
          <RoleGate role={role} allow={["owner", "admin"]}>
            <div className="row">
              <button
                onClick={() => decide.mutate({ id: a.id, decision: "approve" })}
                disabled={decide.isPending}
              >
                Approve
              </button>
              <button
                className="secondary"
                onClick={() => decide.mutate({ id: a.id, decision: "reject" })}
                disabled={decide.isPending}
              >
                Reject
              </button>
            </div>
          </RoleGate>
        </div>
      ))}
    </AppShell>
  );
}
