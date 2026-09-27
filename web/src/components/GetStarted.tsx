import Link from "next/link";
import { EvidenceChain } from "./EvidenceChain";

/** First-use guidance: shown until the workspace has its first workflow. */
export function GetStarted({ canManage }: { canManage: boolean }) {
  return (
    <section className="card" aria-labelledby="get-started-title" data-testid="get-started">
      <div className="section-heading">
        <h2 id="get-started-title">Set up your workspace</h2>
        <EvidenceChain current="Request" />
      </div>
      <p className="muted small">
        Every analysis follows the same governed path: your request becomes a plan you review,
        anything that leaves NLW waits for approval, and every result links to its evidence.
      </p>
      <div className="next-actions">
        <Link href="/workflows/new?dataset=sales-v1">
          <span className="choice-icon" aria-hidden="true">
            ▷
          </span>
          <strong>Run a guided analysis →</strong>
          <span>Walk through Sales end to end: plan, run and evidence.</span>
        </Link>
        <Link href="/workflows/new">
          <span className="choice-icon" aria-hidden="true">
            ⊟
          </span>
          <strong>Explore sample data →</strong>
          <span>See the synthetic Sales and Support datasets and example questions.</span>
        </Link>
        {canManage ? (
          <>
            <Link href="/members">
              <span className="choice-icon people" aria-hidden="true">
                ⚇
              </span>
              <strong>Invite a teammate →</strong>
              <span>Add an approver so shared results get a second pair of eyes.</span>
            </Link>
            <Link href="/connectors">
              <span className="choice-icon connect" aria-hidden="true">
                ⊞
              </span>
              <strong>Connect data or add a Slack destination →</strong>
              <span>Register where NLW may read from or share approved results.</span>
            </Link>
          </>
        ) : (
          <div className="disabled-choice">
            <strong>Invite teammates and connect data</strong>
            <span>Ask a workspace owner or admin — they manage members and connectors.</span>
          </div>
        )}
      </div>
      <p className="pilot-note small" data-testid="pilot-limits" style={{ marginTop: 14 }}>
        Pilot limits: the Sales and Support datasets are fixed, synthetic historical snapshots with
        no real customer or personal information. Uploading your own data isn&apos;t available in
        this pilot.
      </p>
    </section>
  );
}
