import Link from "next/link";

/** First-use guidance: shown until the workspace has its first workflow. */
export function GetStarted({ canManage }: { canManage: boolean }) {
  return (
    <section className="card" aria-labelledby="get-started-title" data-testid="get-started">
      <h2 id="get-started-title">Get started</h2>
      <ol className="steps" aria-label="How NLW works">
        <li>
          <strong>Ask</strong>
          <span>Pick a sample dataset and ask a business question.</span>
        </li>
        <li>
          <strong>Review</strong>
          <span>Check the proposed steps before anything runs.</span>
        </li>
        <li>
          <strong>Execute</strong>
          <span>Run it; sharing to Slack waits for a second approver.</span>
        </li>
        <li>
          <strong>Evidence</strong>
          <span>Follow every finding back to the step that produced it.</span>
        </li>
      </ol>
      <div className="next-actions">
        <Link href="/workflows/new?dataset=sales-v1">
          <strong>Analyze synthetic Sales data →</strong>
          <span>e.g. “What drove revenue changes over the last six months?”</span>
        </Link>
        <Link href="/workflows/new?dataset=support-v1">
          <strong>Analyze synthetic Support data →</strong>
          <span>e.g. “Where are response times slipping, and which queues are at risk?”</span>
        </Link>
        {canManage ? (
          <>
            <Link href="/members">
              <strong>Invite a teammate →</strong>
              <span>Add an approver so shared results get a second pair of eyes.</span>
            </Link>
            <Link href="/connectors">
              <strong>Add a Slack destination →</strong>
              <span>Register where approved results may be shared.</span>
            </Link>
          </>
        ) : null}
      </div>
      <p className="pilot-note small" data-testid="pilot-limits">
        Pilot limits: the Sales and Support datasets are fixed, synthetic historical snapshots with
        no real customer or personal information. Uploading your own data isn&apos;t available in
        this pilot.
      </p>
    </section>
  );
}
