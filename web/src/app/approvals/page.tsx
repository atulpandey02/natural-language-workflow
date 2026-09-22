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
          <p className="muted">
            requested by: <strong>{a.requested_by_user_id ?? "unknown"}</strong>
          </p>
          <p className="muted">
            destination: <strong>{a.destination ?? "unresolved"}</strong>
          </p>
          {a.payload_review_blocked ? (
            <p className="badge warn" role="alert">
              This action’s payload is too large to review safely and cannot be approved. Reject it,
              or reduce the payload and re-run.
            </p>
          ) : (
            <pre style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(a.preview, null, 2)}</pre>
          )}
          <RoleGate role={role} allow={["owner", "admin"]}>
            {/* Separation of duties: the backend forbids deciding an approval you
                requested. viewer_can_decide reflects that (and any other server
                rule); the UI merely disables the controls to match. The backend
                stays authoritative. */}
            {a.viewer_can_decide ? (
              <div className="row">
                <button
                  onClick={() => decide.mutate({ id: a.id, decision: "approve" })}
                  disabled={decide.isPending || a.payload_review_blocked}
                  title={
                    a.payload_review_blocked
                      ? "Payload exceeds the safe review size; it cannot be approved unseen."
                      : undefined
                  }
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
            ) : (
              <p className="muted" role="note">
                You requested this action, so someone else must approve it.
              </p>
            )}
          </RoleGate>
        </div>
      ))}
    </AppShell>
  );
}
