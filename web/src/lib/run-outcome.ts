// Which outcome a run page may state. The deterministic run summary is the
// authority. Without it, raw run/step status is NOT enough to call a failure
// safely retryable: an external action may have happened. Persisted action
// evidence can only make the answer more cautious, never less.

/** The run's outcome could not be established from authoritative evidence. */
export const OUTCOME_UNAVAILABLE = "OUTCOME_UNAVAILABLE";

const UNKNOWN_OUTCOMES = new Set(["FAILED_WITH_UNKNOWN", "ACTION_OUTCOME_UNKNOWN", "UNKNOWN"]);

export function deriveRunOutcome(input: {
  runStatus: string | undefined;
  /** Outcome from the run summary, when it has been read successfully. */
  summaryOutcome: string | undefined;
  /** True while the first summary read is still in flight. */
  summaryLoading: boolean;
  /** Persisted external-action statuses, when they have been read. */
  actionStatuses: string[] | undefined;
}): string | undefined {
  const { runStatus, summaryOutcome, summaryLoading, actionStatuses } = input;
  const actionUnknown = actionStatuses?.some((s) => s === "unknown") ?? false;

  if (summaryOutcome) {
    // Action evidence may only escalate a failure to UNKNOWN, never soften it.
    if (actionUnknown && summaryOutcome === "FAILED") return "FAILED_WITH_UNKNOWN";
    return summaryOutcome;
  }
  if (actionUnknown) return "ACTION_OUTCOME_UNKNOWN";
  if (runStatus === "FAILED") {
    // Loading: say nothing yet. Unavailable: never fall back to "retry is safe".
    return summaryLoading ? undefined : OUTCOME_UNAVAILABLE;
  }
  return runStatus;
}

export function isUnknownOutcome(outcome: string | undefined): boolean {
  return outcome !== undefined && UNKNOWN_OUTCOMES.has(outcome);
}
