"use client";

import Link from "next/link";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading, RoleGate, canApprove } from "@/components/ui";
import { useApprovals, useCurrentWorkspace, useDecideApproval, useMe } from "@/lib/api/hooks";
import { toolLabel } from "@/lib/plan-language";

/** The reviewed content: a Slack message verbatim, otherwise the exact payload. */
function ActionPreview({ preview }: { preview: unknown }) {
  const args = (preview as { args?: Record<string, unknown> | null } | null)?.args;
  if (args && typeof args.text === "string") {
    return (
      <>
        <p className="muted small">Exact message that will be sent:</p>
        <pre style={{ whiteSpace: "pre-wrap" }} aria-label="Exact message to be sent">
          {args.text}
        </pre>
      </>
    );
  }
  return (
    <>
      <p className="muted small">Exact content that will be sent:</p>
      <pre style={{ whiteSpace: "pre-wrap" }} aria-label="Exact content to be sent">
        {JSON.stringify(args ?? {}, null, 2)}
      </pre>
    </>
  );
}

export default function ApprovalsPage() {
  const approvals = useApprovals();
  const current = useCurrentWorkspace();
  const decide = useDecideApproval();
  const me = useMe();
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
            <h2 style={{ margin: 0, fontSize: 16 }}>{toolLabel(a.tool)}</h2>
            <span className="muted">Connector: {a.connector_name}</span>
          </div>
          <p className="muted">
            Requested by{" "}
            <strong>
              {a.requested_by_user_id && a.requested_by_user_id === me.data?.id
                ? "you"
                : "another workspace member"}
            </strong>
            {a.requested_at ? ` · ${new Date(a.requested_at).toLocaleString()}` : ""} ·{" "}
            <Link href={`/runs/${a.run_id}`}>Open the run</Link>
          </p>
          <p className="muted">
            Destination: <strong>{a.destination ?? "Can't be confirmed"}</strong>
          </p>
          {a.payload_review_blocked ? (
            <p className="badge warn" role="alert">
              This action’s payload is too large to review safely and cannot be approved. Reject it,
              or reduce the payload and re-run.
            </p>
          ) : (
            <ActionPreview preview={a.preview} />
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
