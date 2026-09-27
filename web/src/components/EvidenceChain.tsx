/** The NLW journey as a small checkpoint trail: request → plan → approval → execution → result. */
export const CHAIN = ["Request", "Plan", "Approval", "Execution", "Result"] as const;
export type ChainStage = (typeof CHAIN)[number];

export function EvidenceChain({
  current,
  tone,
  completed = false,
}: {
  current: ChainStage;
  /** How the current checkpoint stands: needs a person, or failed. */
  tone?: "attention" | "failed";
  /** Every checkpoint, including the current one, is done. */
  completed?: boolean;
}) {
  const at = CHAIN.indexOf(current);
  return (
    <ol className="evidence-chain" aria-label="Progress">
      {CHAIN.map((stage, i) => {
        const done = i < at || (completed && i === at);
        const state = done
          ? i === at
            ? "done here"
            : "done"
          : i === at
            ? `current ${tone ?? ""}`.trim()
            : "";
        return (
          <li
            key={stage}
            className={state}
            aria-current={i === at && !completed ? "step" : undefined}
          >
            <span className="dot" aria-hidden="true" />
            <span className="chain-label">{stage}</span>
            {done ? <span className="sr-only"> (done)</span> : null}
          </li>
        );
      })}
    </ol>
  );
}

/** Where a run stands on the chain. UNKNOWN or failed outcomes never read as done. */
export function runChain(status: string | undefined): {
  current: ChainStage;
  tone?: "attention" | "failed";
  completed?: boolean;
} {
  switch (status) {
    case "COMPLETED":
    case "SUCCESS":
      return { current: "Result", completed: true };
    case "WAITING_APPROVAL":
      return { current: "Approval", tone: "attention" };
    case "FAILED":
      return { current: "Execution", tone: "failed" };
    case "FAILED_WITH_UNKNOWN":
    case "ACTION_OUTCOME_UNKNOWN":
    case "UNKNOWN":
    case "PARTIAL":
      return { current: "Execution", tone: "attention" };
    default:
      return { current: "Execution" };
  }
}
