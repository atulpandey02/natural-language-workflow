"use client";

import Link from "next/link";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading, RoleGate, StatusBadge, canApprove } from "@/components/ui";
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
      <div className="page-intro">
        <p className="eyebrow">Human approval</p>
        <h1>Pending approvals</h1>
        <p className="lead muted">
          Actions that send anything outside NLW wait here until a second admin or owner reviews the
          exact content.
        </p>
      </div>
      {approvals.isLoading ? <Loading /> : null}
      <ErrorBanner error={approvals.error} />
      <ErrorBanner error={decide.error} />
      {!canApprove(role) ? (
        <p className="muted">You can view approvals; an admin or owner must decide them.</p>
      ) : null}

      {approvals.data && approvals.data.length === 0 ? <Empty>No pending approvals.</Empty> : null}

      {(approvals.data ?? []).map((a) => {
        const mine = Boolean(a.requested_by_user_id) && a.requested_by_user_id === me.data?.id;
        const policyId = `policy-${a.id}`;
        return (
          <article key={a.id} className="card approval-card" aria-labelledby={`title-${a.id}`}>
            <header>
              <div>
                <p className="eyebrow">Awaiting approval</p>
                <h2 id={`title-${a.id}`}>{toolLabel(a.tool)}</h2>
                <p className="muted small" style={{ margin: "4px 0 0" }}>
                  Requested by <strong>{mine ? "you" : "another workspace member"}</strong>
                  {a.requested_at ? ` · ${new Date(a.requested_at).toLocaleString()}` : ""}
                </p>
              </div>
              <StatusBadge status="WAITING_APPROVAL" />
            </header>
            <div className="approval-body">
              <dl className="approval-facts">
                <div>
                  <dt>Destination</dt>
                  <dd>
                    <strong>{a.destination ?? "Can't be confirmed"}</strong>
                  </dd>
                </div>
                <div>
                  <dt>Connector</dt>
                  <dd>{a.connector_name}</dd>
                </div>
                <div>
                  <dt>Why approval is needed</dt>
                  <dd id={policyId}>
                    This sends content outside NLW. Workspace policy requires a second admin or
                    owner — never the requester.
                  </dd>
                </div>
                <div>
                  <dt>Supporting evidence</dt>
                  <dd>
                    <Link href={`/runs/${a.run_id}`}>Open the run</Link> to see its steps and source
                    analysis.
                  </dd>
                </div>
              </dl>
              <div>
                {a.payload_review_blocked ? (
                  <div className="error-panel warn" role="alert">
                    <strong>This can&apos;t be reviewed safely</strong>
                    <p>
                      The content is too large to show in full, so it can&apos;t be approved unseen.
                      Reject it, or reduce the content and run it again.
                    </p>
                  </div>
                ) : (
                  <ActionPreview preview={a.preview} />
                )}
              </div>
            </div>
            <footer>
              <RoleGate role={role} allow={["owner", "admin"]}>
                {/* Separation of duties: the backend forbids deciding an approval you
                    requested. viewer_can_decide reflects that (and any other server
                    rule); the UI merely disables the controls to match. The backend
                    stays authoritative. */}
                {a.viewer_can_decide ? (
                  <>
                    <button
                      className="approve"
                      aria-describedby={policyId}
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
                      className="danger"
                      onClick={() => decide.mutate({ id: a.id, decision: "reject" })}
                      disabled={decide.isPending}
                    >
                      Reject
                    </button>
                    <span className="muted small">
                      Approving sends exactly the content shown. Rejecting sends nothing.
                    </span>
                  </>
                ) : (
                  <p className="self-note" role="note">
                    You requested this action, so someone else must approve it.
                  </p>
                )}
              </RoleGate>
              {!canApprove(role) ? (
                <p className="muted small" style={{ margin: 0 }}>
                  Only an admin or owner can decide this.
                </p>
              ) : null}
            </footer>
          </article>
        );
      })}
    </AppShell>
  );
}
