// Which outcome a run page may state. Precedence, most conservative first:
//
//   1. Persisted action evidence saying `unknown` → UNKNOWN, whatever the
//      summary or run status says (COMPLETED, PARTIAL, IN_PROGRESS, FAILED…).
//   2. A summary outcome that is itself UNKNOWN.
//   3. Evidence still loading → OUTCOME_PENDING (no claim at all).
//   4. The deterministic run summary, once it and the action evidence are read.
//   5. Otherwise → OUTCOME_UNAVAILABLE (neutral: some steps may have run).
//
// Raw run status is never presented as the established outcome: it can't tell
// whether an external action happened.

/** The run's outcome could not be established from authoritative evidence. */
export const OUTCOME_UNAVAILABLE = "OUTCOME_UNAVAILABLE";
/** Evidence is still being read; nothing is claimed yet. */
export const OUTCOME_PENDING = "OUTCOME_PENDING";

const UNKNOWN_OUTCOMES = new Set(["FAILED_WITH_UNKNOWN", "ACTION_OUTCOME_UNKNOWN", "UNKNOWN"]);

export function isUnknownOutcome(outcome: string | undefined): boolean {
  return outcome !== undefined && UNKNOWN_OUTCOMES.has(outcome);
}

/** Outcomes for which the page must not show success, sharing or rerun guidance. */
export function isCautiousOutcome(outcome: string | undefined): boolean {
  return (
    isUnknownOutcome(outcome) || outcome === OUTCOME_UNAVAILABLE || outcome === OUTCOME_PENDING
  );
}

export interface EvidenceRead<T> {
  data: T | undefined;
  /** First read still in flight (no data yet). */
  loading: boolean;
}

export function deriveRunOutcome(input: {
  summary: EvidenceRead<string>;
  actions: EvidenceRead<string[]>;
}): string {
  const { summary, actions } = input;
  const actionUnknown = actions.data?.some((s) => s === "unknown") ?? false;

  if (actionUnknown)
    return isUnknownOutcome(summary.data) ? summary.data! : "ACTION_OUTCOME_UNKNOWN";
  if (isUnknownOutcome(summary.data)) return summary.data!;
  if (summary.loading || actions.loading) return OUTCOME_PENDING;
  if (summary.data) return summary.data;
  return OUTCOME_UNAVAILABLE;
}
